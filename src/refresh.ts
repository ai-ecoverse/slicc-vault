import type { Scrubber } from '@ai-ecoverse/slicc-scrub';
import { text } from './bytes.ts';
import { request, transact } from './db.ts';
import { Refused } from './errors.ts';
import { decrypt } from './keys.ts';
import { aad, type Rotation, records, removed, rotate, type VaultRecord } from './records.ts';
import type { Vault } from './vault.ts';

export const DUE = 5 * 60 * 1000;
export const REANNOUNCE = 10 * 60 * 1000;
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
  const raw = typeof given.tokenUrl === 'string' ? given.tokenUrl : '';
  const url = URL.parse(raw);
  const valid =
    url?.protocol === 'https:' &&
    !userinfo(raw) &&
    !url.username &&
    !url.password &&
    typeof given.clientId === 'string' &&
    given.clientId.length > 0 &&
    (given.scope === undefined || typeof given.scope === 'string') &&
    (given.resource === undefined || typeof given.resource === 'string');
  if (!valid)
    throw new Refused(
      'EINVAL',
      'oauth must be { tokenUrl (https, without userinfo), clientId, scope?, resource? }'
    );
  return {
    tokenUrl: url.href,
    clientId: given.clientId as string,
    ...(given.scope === undefined ? {} : { scope: given.scope as string }),
    ...(given.resource === undefined ? {} : { resource: given.resource as string }),
  };
}

export type TokenKind = 'secret' | 'model' | 'mcp';
const TOKENS = new Set<string>(['secret', 'model', 'mcp']);

export function due(record: VaultRecord, now: number): boolean {
  return (
    TOKENS.has(record.kind) &&
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

const AUTHORITY = /^[a-z][a-z0-9+.-]*:\/*([^/?#]*)/i;

export function userinfo(raw: string): boolean {
  const cleaned = raw
    .replace(/^[\0-\x20]+|[\0-\x20]+$/g, '')
    .replace(/[\t\n\r]/g, '')
    .replace(/\\/g, '/');
  return (AUTHORITY.exec(cleaned)?.[1] ?? '').includes('@');
}
const SINGLE = ['access_token', 'refresh_token', 'token_type', 'expires_in'];

export function topKeys(raw: string): string[] {
  const keys: string[] = [];
  let depth = 0;
  for (let i = 0; i < raw.length; i++) {
    const char = raw[i];
    if (char === '"') {
      let end = i + 1;
      while (end < raw.length && raw[end] !== '"') end += raw[end] === '\\' ? 2 : 1;
      if (depth === 1 && /^\s*:/.test(raw.slice(end + 1)))
        keys.push(JSON.parse(raw.slice(i, end + 1)));
      i = end;
    } else if (char === '{' || char === '[') depth++;
    else if (char === '}' || char === ']') depth--;
  }
  return keys;
}

export function tokens(response: EgressResponse, scrubber: Scrubber | null) {
  const raw = typeof response.body === 'string' ? response.body : text(response.body);
  let parsed: Fields;
  try {
    const json = JSON.parse(raw);
    parsed = json !== null && typeof json === 'object' ? json : {};
  } catch {
    parsed = {};
  }
  const keys = Object.keys(parsed).length ? topKeys(raw) : [];
  const twice = SINGLE.find((key) => keys.indexOf(key) !== keys.lastIndexOf(key));
  if (twice) throw new Refused('EACCES', `refresh failed: the IdP returned ${twice} twice`);
  const access = parsed.access_token;
  const failed = response.status < 200 || response.status > 299 || parsed.error !== undefined;
  if (failed || typeof access !== 'string') {
    const reason = typeof parsed.error === 'string' ? parsed.error : `status ${response.status}`;
    throw new Refused(
      'EACCES',
      `refresh failed: ${scrubber ? scrubber.text(reason).text : reason}`
    );
  }
  const type = parsed.token_type;
  if (type !== undefined && (typeof type !== 'string' || type.toLowerCase() !== 'bearer')) {
    throw new Refused('EACCES', 'refresh failed: the IdP returned a token_type other than Bearer');
  }
  const lifetime = parsed.expires_in;
  if (
    lifetime !== undefined &&
    (typeof lifetime !== 'number' || !(lifetime >= 0) || !Number.isFinite(lifetime * 1000))
  ) {
    throw new Refused('EACCES', 'refresh failed: the IdP returned an invalid expires_in');
  }
  const expires = lifetime === undefined ? null : lifetime;
  const replacement = parsed.refresh_token;
  if (replacement !== undefined && typeof replacement !== 'string') {
    throw new Refused('EACCES', 'refresh failed: the IdP returned an invalid refresh_token');
  }
  const refresh = replacement ?? null;
  return { access, expires, refresh };
}

export class Refresher {
  readonly vault: Vault;
  send: Send | null = null;
  announce: Announce | null = null;
  readonly running = new Map<string, Promise<Fields>>();

  constructor(vault: Vault) {
    this.vault = vault;
  }

  async sweep(ns: string): Promise<void> {
    const now = this.vault.now();
    for (const record of (await records(this.vault.db, ns)).filter((r) => due(r, now))) {
      await this.refresh(ns, record.name, record.kind as TokenKind).catch(() => null);
    }
  }

  refresh(ns: string, name: string, kind: TokenKind = 'secret'): Promise<Fields> {
    const key = `${ns}\u0000${kind}\u0000${name}`;
    const known = this.running.get(key);
    if (known !== undefined) return known;
    const running = this.run(ns, name, kind).finally(() => {
      this.running.delete(key);
    });
    this.running.set(key, running);
    return running;
  }

  async run(ns: string, name: string, kind: TokenKind): Promise<Fields> {
    const seen = await this.token(ns, name, kind);
    return navigator.locks.request(`refresh:${ns}\u0000${seen.refresh}`, () =>
      this.locked(ns, name, seen)
    );
  }

  async token(ns: string, name: string, kind: TokenKind): Promise<VaultRecord> {
    const held = await records(this.vault.db, ns);
    const record = held.find((r) => r.kind === kind && r.name === name && !removed(r));
    if (!record?.refresh || record.expiresAt === undefined) {
      throw new Refused('ENOENT', `${name} has no refresh source`);
    }
    return record;
  }

  async locked(ns: string, name: string, seen: VaultRecord): Promise<Fields> {
    const held = await records(this.vault.db, ns);
    const record = held.find((r) => r.kind === seen.kind && r.name === name && !removed(r));
    if (!record) throw new Refused('ENOENT', `${name} has no refresh source`);
    if (record.updatedAt !== seen.updatedAt) {
      return {
        state: 'refreshed',
        ...(record.expiresAt === undefined ? {} : { expiresAt: record.expiresAt }),
      };
    }
    if (record.refresh === JERK) return this.jerk(ns, record);
    const grant = held.find((r) => r.kind === 'grant' && r.name === record.refresh && !removed(r));
    if (!grant?.oauth || grant.source !== record.source)
      throw new Refused('ENOENT', `${name}'s grant ${record.refresh} is missing`);
    return this.oauth(ns, record, grant);
  }

  async jerk(ns: string, record: VaultRecord): Promise<Fields> {
    const key = `announced:${ns}\u0000${record.name}`;
    const now = this.vault.now();
    const fresh = await transact(this.vault.db, ['meta'], 'readwrite', async (tx) => {
      const meta = tx.objectStore('meta');
      const last = (await request(meta.get(key))) as { expiresAt: number; at: number } | undefined;
      if (last && last.expiresAt === record.expiresAt && now - last.at < REANNOUNCE) return false;
      await request(meta.put({ expiresAt: record.expiresAt, at: now }, key));
      return true;
    });
    if (fresh) this.announce?.(ns, record.name, record.source, record.expiresAt as number);
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
    const replaced = got.refresh !== null && got.refresh !== token ? got.refresh : undefined;
    const rotations: Rotation[] = [
      { record, value: got.access, expiresAt },
      { record: grant, ...(replaced === undefined ? {} : { value: replaced }) },
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
