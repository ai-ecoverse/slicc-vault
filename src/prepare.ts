import type { Hit, Scrubber } from '@ai-ecoverse/slicc-scrub';
import { text } from './bytes.ts';
import { Refused } from './errors.ts';
import { decrypt } from './keys.ts';
import {
  aad,
  checkValue,
  NAME,
  records,
  removed,
  type SealInput,
  sealAll,
  type VaultRecord,
} from './records.ts';
import { checkOAuth, type TokenKind, tokens } from './refresh.ts';
import { kernelPort, modelFor, serverFor } from './refusal.ts';
import { loadRegistered } from './rules.ts';
import type { Vault } from './vault.ts';

type Fields = Record<string, unknown>;

export interface Outgoing {
  method: string;
  url: string;
  headers: [string, string][];
  body?: string | Uint8Array;
}

export const MAX_BODY = 32 * 1024 * 1024;
const FOUND = /fnox_proxy_[0-9a-f]{24}/g;
const METHOD = /^[A-Z]{1,16}$/;
const TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const LOCKED = 'vault is locked: unlock it in the vault window to continue';

export function outgoing(value: unknown): Outgoing {
  const given = (value ?? {}) as Fields;
  const headers = given.headers;
  const body = given.body;
  const valid =
    typeof given.method === 'string' &&
    METHOD.test(given.method) &&
    typeof given.url === 'string' &&
    URL.canParse(given.url) &&
    Array.isArray(headers) &&
    headers.every(
      (pair) =>
        Array.isArray(pair) &&
        pair.length === 2 &&
        typeof pair[0] === 'string' &&
        TOKEN.test(pair[0]) &&
        typeof pair[1] === 'string' &&
        !/[\r\n\0]/.test(pair[1])
    ) &&
    (body === undefined || typeof body === 'string' || body instanceof Uint8Array);
  if (!valid) {
    throw new Refused(
      'EINVAL',
      'request must be { method, url, headers: [name, value][], body?: string | bytes }'
    );
  }
  const size =
    typeof body === 'string'
      ? body.length * 3 <= MAX_BODY
        ? 0
        : new TextEncoder().encode(body).byteLength
      : (body?.byteLength ?? 0);
  if (size > MAX_BODY) throw new Refused('EINVAL', 'request bodies are at most 32 MiB');
  return {
    method: given.method as string,
    url: given.url as string,
    headers: headers as [string, string][],
    ...(body === undefined ? {} : { body: body as string | Uint8Array }),
  };
}

export interface Target {
  who: string;
  owns: (record: VaultRecord) => boolean;
  reaches: boolean;
  loopback: boolean;
}

export async function scrubbed(scrubber: Scrubber, request: Outgoing) {
  if (request.body === undefined) return { body: undefined, hits: [] as Hit[] };
  if (typeof request.body === 'string') {
    const out = scrubber.text(request.body);
    return { body: out.text, hits: out.hits };
  }
  const out = scrubber.bytes(request.body);
  return { body: out.bytes, hits: out.hits };
}

export class Preparer {
  readonly vault: Vault;
  readonly ns: string;

  constructor(vault: Vault, ns: string) {
    this.vault = vault;
    this.ns = ns;
  }

  async scrubber(): Promise<Scrubber> {
    const scrubber = await this.vault.scrubbers.get(this.ns);
    if (!scrubber) throw new Refused('EACCES', LOCKED);
    return scrubber;
  }

  async usable(record: VaultRecord): Promise<VaultRecord> {
    if (record.expiresAt === undefined || record.expiresAt > this.vault.now()) return record;
    if (!record.refresh) throw new Refused('EACCES', `${record.name} expired`);
    await this.vault.refresher.refresh(this.ns, record.name, record.kind as TokenKind).catch(() => {
      throw new Refused('EACCES', `${record.name} expired; refreshing`);
    });
    const fresh = (await records(this.vault.db, this.ns)).find(
      (r) => r.kind === record.kind && r.name === record.name && !removed(r)
    );
    if (!fresh || (fresh.expiresAt !== undefined && fresh.expiresAt <= this.vault.now())) {
      throw new Refused('EACCES', `${record.name} expired; refreshing`);
    }
    return fresh;
  }

  async fill(text: string, held: Map<string, VaultRecord>, target: Target, url: boolean) {
    let out = text;
    for (const placeholder of new Set(text.match(FOUND) ?? [])) {
      const found = held.get(placeholder);
      if (!found) continue;
      if (removed(found)) throw new Refused('EACCES', `${found.name} was removed`);
      if (!target.owns(found)) {
        throw new Refused(
          'EACCES',
          `${found.name} isn't a credential of ${target.who}; secrets are never sent to model or MCP endpoints`
        );
      }
      if (!target.reaches) {
        throw new Refused('EACCES', `${found.name} is sent only to ${target.who}'s own endpoints`);
      }
      const record = await this.usable(found);
      held.set(placeholder, record);
      const key = this.vault.keyring.key;
      if (!key) throw new Refused('EACCES', LOCKED);
      const value = await decrypt(key, record.sealed, aad(record.ns, record.kind, record.name));
      out = out.split(placeholder).join(url ? encodeURIComponent(value) : value);
    }
    return out;
  }

  async prepare(request: Outgoing, target: Target): Promise<Fields> {
    const parsed = new URL(request.url);
    const loopback = target.loopback && kernelPort(parsed) !== null;
    if (parsed.protocol !== 'https:' && !loopback) {
      throw new Refused('EACCES', 'model and MCP requests go out over https only');
    }
    await this.scrubber();
    const held = new Map((await records(this.vault.db, this.ns)).map((r) => [r.placeholder, r]));
    const url = await this.fill(request.url, held, target, true);
    const headers: [string, string][] = [];
    for (const [name, value] of request.headers) {
      headers.push([name, await this.fill(value, held, target, false)]);
    }
    const scrubber = await this.scrubber();
    const head = [request.method, request.url, ...request.headers.flat()];
    if (head.some((text) => scrubber.text(text).hits.length > 0)) {
      throw new Refused('EACCES', 'the request head carries a value; send its placeholder instead');
    }
    const { body, hits } = await scrubbed(scrubber, request);
    return {
      request: {
        method: request.method,
        url,
        headers,
        ...(body === undefined ? {} : { body }),
      },
      hits,
      version: scrubber.version,
    };
  }

  async inferred(request: Outgoing): Promise<string | null> {
    const text = [request.url, ...request.headers.map(([, value]) => value)].join(' ');
    const present = new Set(text.match(FOUND) ?? []);
    const models = (await records(this.vault.db, this.ns)).filter(
      (r) => r.kind === 'model' && present.has(r.placeholder)
    );
    return models.length === 1 ? (models[0].provider as string) : null;
  }

  async model(fields: Fields): Promise<Fields> {
    const given = fields.provider;
    if (given !== undefined && (typeof given !== 'string' || !given)) {
      throw new Refused('EINVAL', 'provider must be a pi-ai provider id');
    }
    const request = outgoing(fields.request);
    const provider = (given as string | undefined) ?? (await this.inferred(request));
    const registered = await loadRegistered(this.vault.db, this.ns);
    return this.prepare(request, {
      who: provider ?? 'this request',
      owns: (record) =>
        provider !== null && record.kind === 'model' && record.provider === provider,
      reaches: provider !== null && modelFor(registered, provider, new URL(request.url)),
      loopback: false,
    });
  }

  async mcp(fields: Fields): Promise<Fields> {
    const server = fields.server;
    if (typeof server !== 'string' || !server) {
      throw new Refused('EINVAL', 'server must be a registered MCP server name');
    }
    const request = outgoing(fields.request);
    const registered = await loadRegistered(this.vault.db, this.ns);
    const url = new URL(request.url);
    const entry = serverFor(registered, server, url);
    const names = new Set(
      registered.mcp.filter((e) => e.server === server).flatMap((e) => e.names)
    );
    return this.prepare(request, {
      who: server,
      owns: (record) =>
        record.kind === 'mcp' && (record.server === server || names.has(record.name)),
      reaches: entry !== null,
      loopback: true,
    });
  }

  async list(): Promise<Fields> {
    const scrubber = await this.scrubber();
    const clean = (settings: Record<string, string>) =>
      Object.fromEntries(
        Object.entries(settings)
          .filter(([key]) => scrubber.text(key).hits.length === 0)
          .map(([key, value]) => [key, scrubber.text(value).text])
      );
    return records(this.vault.db, this.ns).then((held) => {
      const now = this.vault.now();
      const plain = (r: VaultRecord) =>
        [r.name, r.provider ?? '', r.server ?? ''].every((t) => scrubber.text(t).hits.length === 0);
      const shown = held.filter(
        (r) => (r.kind === 'model' || r.kind === 'mcp') && !removed(r) && plain(r)
      );
      return {
        records: shown.map((r) => {
          const expired = r.expiresAt !== undefined && r.expiresAt <= now;
          return {
            kind: r.kind,
            name: r.name,
            placeholder: r.placeholder,
            state: expired ? (r.refresh ? 'refreshing' : 'expired') : 'ready',
            ...(r.provider === undefined ? {} : { provider: r.provider }),
            ...(r.server === undefined ? {} : { server: r.server }),
            ...(r.expiresAt === undefined ? {} : { expiresAt: r.expiresAt }),
            ...(r.settings === undefined ? {} : { settings: clean(r.settings) }),
          };
        }),
      };
    });
  }

  async grant(fields: Fields): Promise<Fields> {
    const server = fields.server;
    const response = fields.response;
    if (typeof server !== 'string' || !server) {
      throw new Refused('EINVAL', 'server must be a registered MCP server name');
    }
    if (typeof response !== 'string' && !(response instanceof Uint8Array)) {
      throw new Refused('EINVAL', 'response must be the token response body');
    }
    const naming = [server, typeof fields.name === 'string' ? fields.name : ''];
    const before = await this.scrubber();
    if (naming.some((text) => before.text(text).hits.length > 0)) {
      throw new Refused('EINVAL', 'the server or record name holds a value');
    }
    const oauth = checkOAuth(fields.oauth);
    const registered = await loadRegistered(this.vault.db, this.ns);
    if (!registered.mcp.some((e) => e.server === server && e.tokenUrl === oauth.tokenUrl)) {
      throw new Refused('EACCES', `${oauth.tokenUrl} isn't the registered tokenUrl of ${server}`);
    }
    if (fields.name !== undefined && typeof fields.name !== 'string') {
      throw new Refused('EINVAL', 'name must be a record name');
    }
    const base = fields.name ?? defaultName(server);
    const grantName = `${base}_GRANT`;
    if (!NAME.test(base) || grantName.length > 128) {
      throw new Refused('EINVAL', 'name must be a record name');
    }
    const got = tokens(
      { status: 200, headers: [], body: response },
      await this.vault.scrubbers.get(this.ns)
    );
    checkValue(got.access);
    if (got.refresh !== null) checkValue(got.refresh);
    const now = this.vault.now();
    const source = 'oauth:mcp' as const;
    const dek = this.vault.keyring.use();
    const common = { ns: this.ns, source, uid: null, tag: null, now };
    const access: SealInput = {
      ...common,
      kind: 'mcp',
      name: base,
      value: got.access,
      server,
      exclusive: true,
      ...(got.expires === null ? {} : { expiresAt: now + got.expires * 1000 }),
      ...(got.refresh !== null ? { refresh: grantName } : {}),
    };
    const grant: SealInput[] =
      got.refresh !== null
        ? [{ ...common, kind: 'grant', name: grantName, value: got.refresh, oauth }]
        : [];
    const written = (await sealAll(this.vault.db, dek, [access, ...grant])).map((s) => s.record);
    const [sealedAccess, sealedGrant] = written;
    await this.vault.changed(this.ns, ['secrets', 'audit']);
    const raw = typeof response === 'string' ? response : text(response);
    const parsed = JSON.parse(raw) as Fields;
    const scrubber = (await this.vault.scrubbers.get(this.ns)) as Scrubber;
    const kept: Fields = {};
    if (typeof parsed.token_type === 'string') kept.token_type = parsed.token_type;
    if (typeof parsed.expires_in === 'number') kept.expires_in = parsed.expires_in;
    if (typeof parsed.scope === 'string') kept.scope = scrubber.text(parsed.scope).text;
    const rewritten = JSON.stringify({
      ...kept,
      access_token: sealedAccess.placeholder,
      ...(sealedGrant ? { refresh_token: sealedGrant.placeholder } : {}),
    });
    const shown = written.map((r) => ({
      kind: r.kind,
      name: r.name,
      placeholder: r.placeholder,
    }));
    return {
      response: typeof response === 'string' ? rewritten : new TextEncoder().encode(rewritten),
      records: shown,
      ...(sealedAccess.expiresAt === undefined ? {} : { expiresAt: sealedAccess.expiresAt }),
    };
  }

  async refresh(fields: Fields): Promise<Fields> {
    const { server, provider } = fields;
    const byServer = typeof server === 'string' && server;
    const byProvider = typeof provider === 'string' && provider;
    if (!byServer === !byProvider)
      throw new Refused('EINVAL', 'refresh takes a server or a provider');
    const named = fields.name;
    const matching = (await records(this.vault.db, this.ns)).filter(
      (r) =>
        !removed(r) &&
        r.refresh !== undefined &&
        (named === undefined || r.name === named) &&
        (byServer
          ? r.kind === 'mcp' && r.server === server
          : r.kind === 'model' && r.provider === provider)
    );
    const found = matching[0];
    if (!found)
      throw new Refused('ENOENT', `${byServer ? server : provider} has no refreshable credential`);
    if (matching.length > 1) {
      throw new Refused(
        'EINVAL',
        `${byServer ? server : provider} has several; name the one to refresh`
      );
    }
    return this.vault.refresher.refresh(this.ns, found.name, found.kind as TokenKind);
  }
}

function defaultName(server: string): string {
  const upper = server.toUpperCase().replace(/[^A-Z0-9_]/g, '_');
  return `${/^[A-Z_]/.test(upper) ? '' : 'MCP_'}${upper}_ACCESS_TOKEN`.slice(0, 120);
}
