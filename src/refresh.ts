import type { Scrubber } from '@ai-ecoverse/slicc-scrub';
import { text } from './bytes.ts';
import { Refused } from './errors.ts';
import { decrypt } from './keys.ts';
import { aad, type Rotation, records, removed, rotate, type VaultRecord } from './records.ts';
import type { Vault } from './vault.ts';

export const DUE = 5 * 60 * 1000;
export const EGRESS_TIMEOUT = 30 * 1000;
export const JERK = 'jerk-seal';

type Fields = Record<string, unknown>;

export interface OAuth {
  tokenUrl: string;
  clientId: string;
  scope?: string;
  resource?: string;
}

export interface EgressRequest {
  method: string;
  url: string;
  headers: [string, string][];
  body: string;
}

export interface EgressResponse {
  status: number;
  headers: [string, string][];
  body: Uint8Array | string;
}

export type Send = (ns: string, request: EgressRequest) => Promise<EgressResponse>;
export type Announce = (ns: string, name: string, source: string, expiresAt: number) => void;

export function checkOAuth(value: unknown): OAuth {
  const given = (value ?? {}) as Fields;
  const url = typeof given.tokenUrl === 'string' ? URL.parse(given.tokenUrl) : null;
  const valid =
    url?.protocol === 'https:' &&
    typeof given.clientId === 'string' &&
    given.clientId.length > 0 &&
    (given.scope === undefined || typeof given.scope === 'string') &&
    (given.resource === undefined || typeof given.resource === 'string');
  if (!valid)
    throw new Refused('EINVAL', 'oauth must be { tokenUrl (https), clientId, scope?, resource? }');
  return {
    tokenUrl: url.href,
    clientId: given.clientId as string,
    ...(given.scope === undefined ? {} : { scope: given.scope as string }),
    ...(given.resource === undefined ? {} : { resource: given.resource as string }),
  };
}

export function due(record: VaultRecord, now: number): boolean {
  return (
    record.kind === 'secret' &&
    !removed(record) &&
    record.refresh !== undefined &&
    record.expiresAt !== undefined &&
    record.expiresAt - now <= DUE
  );
}

export function tokenRequest(oauth: OAuth, refreshToken: string): EgressRequest {
  const form = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: oauth.clientId,
  });
  if (oauth.scope) form.set('scope', oauth.scope);
  if (oauth.resource) form.set('resource', oauth.resource);
  return {
    method: 'POST',
    url: oauth.tokenUrl,
    headers: [
      ['content-type', 'application/x-www-form-urlencoded'],
      ['accept', 'application/json'],
    ],
    body: form.toString(),
  };
}

export function tokens(response: EgressResponse, scrubber: Scrubber | null) {
  const raw = typeof response.body === 'string' ? response.body : text(response.body);
  let parsed: Fields;
  try {
    parsed = JSON.parse(raw);
  } catch {
    parsed = {};
  }
  const access = parsed.access_token;
  if (response.status < 200 || response.status > 299 || typeof access !== 'string') {
    const reason = typeof parsed.error === 'string' ? parsed.error : `status ${response.status}`;
    throw new Refused(
      'EACCES',
      `refresh failed: ${scrubber ? scrubber.text(reason).text : reason}`
    );
  }
  const expires =
    typeof parsed.expires_in === 'number' && parsed.expires_in >= 0 ? parsed.expires_in : null;
  const refresh = typeof parsed.refresh_token === 'string' ? parsed.refresh_token : null;
  return { access, expires, refresh };
}

export class Refresher {
  readonly vault: Vault;
  send: Send | null = null;
  announce: Announce | null = null;
  readonly announced = new Map<string, number>();
  readonly running = new Map<string, Promise<Fields>>();

  constructor(vault: Vault) {
    this.vault = vault;
  }

  async sweep(ns: string): Promise<void> {
    const now = this.vault.now();
    for (const record of (await records(this.vault.db, ns)).filter((r) => due(r, now))) {
      await this.refresh(ns, record.name).catch(() => null);
    }
  }

  refresh(ns: string, name: string): Promise<Fields> {
    const key = `${ns}\u0000${name}`;
    const known = this.running.get(key);
    if (known !== undefined) return known;
    const running = this.run(ns, name).finally(() => {
      this.running.delete(key);
    });
    this.running.set(key, running);
    return running;
  }

  async run(ns: string, name: string): Promise<Fields> {
    const held = await records(this.vault.db, ns);
    const record = held.find((r) => r.kind === 'secret' && r.name === name && !removed(r));
    if (!record?.refresh || record.expiresAt === undefined) {
      throw new Refused('ENOENT', `${name} has no refresh source`);
    }
    if (record.refresh === JERK) return this.jerk(ns, record);
    const grant = held.find((r) => r.kind === 'grant' && r.name === record.refresh && !removed(r));
    if (!grant?.oauth) throw new Refused('ENOENT', `${name}'s grant ${record.refresh} is missing`);
    return this.oauth(ns, record, grant);
  }

  jerk(ns: string, record: VaultRecord): Fields {
    const key = `${ns}\u0000${record.name}`;
    if (this.announced.get(key) !== record.expiresAt) {
      this.announced.set(key, record.expiresAt as number);
      this.announce?.(ns, record.name, record.source, record.expiresAt as number);
    }
    return { state: 'requested' };
  }

  async oauth(ns: string, record: VaultRecord, grant: VaultRecord): Promise<Fields> {
    if (!this.send) throw new Refused('ENOTCONN', 'no page is connected to send the refresh');
    const dek = this.vault.keyring.use();
    const token = await decrypt(dek.key, grant.sealed, aad(grant.ns, grant.kind, grant.name));
    const response = await this.send(ns, tokenRequest(grant.oauth as OAuth, token));
    const got = tokens(response, await this.vault.scrubbers.get(ns));
    const now = this.vault.now();
    const expiresAt = got.expires === null ? null : now + got.expires * 1000;
    const replaced = got.refresh && got.refresh !== token ? got.refresh : undefined;
    const rotations: Rotation[] = [
      { record, value: got.access, expiresAt },
      { record: grant, ...(replaced ? { value: replaced } : {}) },
    ];
    await rotate(
      this.vault.db,
      dek,
      ns,
      rotations,
      { type: 'refresh', name: record.name, grant: grant.name, uid: null, tag: null },
      now
    );
    await this.vault.changed(ns, ['secrets', 'audit']);
    return { state: 'refreshed', ...(expiresAt === null ? {} : { expiresAt }) };
  }
}

export function egressOver(port: MessagePort, ms = EGRESS_TIMEOUT): Promise<EgressResponse> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      port.close();
      reject(new Refused('ETIMEDOUT', 'the page did not answer the refresh in time'));
    }, ms);
    port.onmessage = (event: MessageEvent) => {
      clearTimeout(timer);
      port.close();
      const data = (event.data ?? {}) as Fields;
      const headers = Array.isArray(data.headers) ? (data.headers as [string, string][]) : [];
      const body =
        typeof data.body === 'string' || data.body instanceof Uint8Array ? data.body : '';
      if (typeof data.status !== 'number') {
        reject(
          new Refused(
            'ENOTCONN',
            typeof data.error === 'string' ? `egress failed: ${data.error}` : 'egress failed'
          )
        );
        return;
      }
      resolve({ status: data.status, headers, body });
    };
    port.start();
  });
}
