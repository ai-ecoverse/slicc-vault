import { compile, type Hit, type Scrubber } from '@ai-ecoverse/slicc-scrub';
import { text } from './bytes.ts';
import { all as every, transact } from './db.ts';
import { Refused } from './errors.ts';
import { decrypt } from './keys.ts';
import { signIn } from './providers.ts';
import {
  aad,
  binding,
  checkValue,
  NAME,
  records,
  removed,
  type SealInput,
  scrubIn,
  sealAll,
  type VaultRecord,
} from './records.ts';
import { checkOAuth, type TokenKind, tokens } from './refresh.ts';
import {
  holds,
  kernelPort,
  type McpServer,
  modelFor,
  modelRefused,
  pageSealed,
  pageServer,
  type Registered,
  serverFor,
  servers,
  tofu,
  under,
} from './refusal.ts';
import { endpointsIn, loadRegistered, migrate, pin } from './rules.ts';
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
  reaches: (record: VaultRecord) => boolean;
  loopback: boolean;
  settle?: (filled: VaultRecord[]) => Promise<void>;
}

function still(target: Target, filled: VaultRecord[]): void {
  if (filled.some((record) => !target.owns(record) || !target.reaches(record))) {
    throw new Refused(
      'EAGAIN',
      "the vault's endpoints changed meanwhile; prepare the request again"
    );
  }
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

  async fill(
    text: string,
    held: Map<string, VaultRecord>,
    target: Target,
    url: boolean,
    seen: { refreshes: number; filled: VaultRecord[] }
  ) {
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
      if (!target.reaches(found)) {
        throw new Refused('EACCES', `${found.name} is sent only to ${target.who}'s own endpoints`);
      }
      const record = await this.usable(found);
      if (record !== found) {
        seen.refreshes += 1;
        if (!target.owns(record)) {
          throw new Refused('EACCES', `${record.name} changed while it was refreshed; try again`);
        }
      }
      held.set(placeholder, record);
      seen.filled.push(record);
      const key = this.vault.keyring.key;
      if (!key) throw new Refused('EACCES', LOCKED);
      const value = await decrypt(key, record.sealed, aad(record.ns, record.kind, record.name));
      if (await this.vault.scrubbers.holdsAnother(this.ns, record, value)) {
        throw new Refused('EACCES', `${record.name}'s value contains another stored value`);
      }
      out = out.split(placeholder).join(url ? encodeURIComponent(value) : value);
    }
    return out;
  }

  async prepare(
    request: Outgoing,
    make: (registered?: Registered) => Promise<Target>
  ): Promise<Fields> {
    const target = await make();
    const parsed = new URL(request.url);
    const loopback = target.loopback && kernelPort(parsed) !== null;
    if (parsed.protocol !== 'https:' && !loopback) {
      throw new Refused('EACCES', 'model and MCP requests go out over https only');
    }
    const first = await this.scrubber();
    const held = new Map((await records(this.vault.db, this.ns)).map((r) => [r.placeholder, r]));
    const seen = { refreshes: 0, filled: [] as VaultRecord[] };
    const url = await this.fill(request.url, held, target, true, seen);
    const headers: [string, string][] = [];
    for (const [name, value] of request.headers) {
      headers.push([name, await this.fill(value, held, target, false, seen)]);
    }
    const again = await make();
    still(again, seen.filled);
    await again.settle?.(seen.filled);
    const scrubber = await this.scrubber();
    if (scrubber.version !== first.version + seen.refreshes) {
      throw new Refused(
        'EAGAIN',
        "the vault's values changed meanwhile; prepare the request again"
      );
    }
    const all = scrubber.version === first.version ? [scrubber] : [first, scrubber];
    const head = [request.method, request.url, ...request.headers.flat()];
    if (head.some((text) => all.some((s) => s.text(text).hits.length > 0))) {
      throw new Refused('EACCES', 'the request head carries a value; send its placeholder instead');
    }
    let { body, hits } = await scrubbed(first, request);
    if (all.length > 1) {
      const again = await scrubbed(scrubber, {
        ...request,
        ...(body === undefined ? {} : { body }),
      });
      body = again.body;
      hits = [...hits, ...again.hits];
    }
    if ((await this.scrubber()).version !== scrubber.version) {
      throw new Refused(
        'EAGAIN',
        "the vault's values changed meanwhile; prepare the request again"
      );
    }
    const [registered, live, version] = await transact(
      this.vault.db,
      ['meta', 'records'],
      'readonly',
      (tx) =>
        Promise.all([
          endpointsIn(tx, this.ns),
          every<VaultRecord>(tx, 'records', this.ns),
          scrubIn(tx, this.ns),
        ])
    );
    if (version !== scrubber.version) {
      throw new Refused(
        'EAGAIN',
        "the vault's values changed meanwhile; prepare the request again"
      );
    }
    const last = await make(registered);
    still(last, seen.filled);
    const now = new Map(live.map((r) => [r.placeholder, r]));
    const moved = seen.filled.some((r) => {
      const found = now.get(r.placeholder);
      return (
        !found || removed(found) || found.updatedAt !== r.updatedAt || found.unpins !== r.unpins
      );
    });
    if (moved) {
      throw new Refused(
        'EAGAIN',
        "the vault's values changed meanwhile; prepare the request again"
      );
    }
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
    return this.prepare(request, async (given) => {
      const registered = given ?? (await loadRegistered(this.vault.db, this.ns));
      return {
        who: provider ?? 'this request',
        owns: (record) =>
          provider !== null && record.kind === 'model' && record.provider === provider,
        reaches: (record) =>
          provider !== null &&
          modelFor(registered, provider, new URL(request.url), record.name, record.settings),
        loopback: false,
      };
    });
  }

  async mcp(fields: Fields): Promise<Fields> {
    const server = fields.server;
    if (typeof server !== 'string' || !server) {
      throw new Refused('EINVAL', 'server must be a registered MCP server name');
    }
    const request = outgoing(fields.request);
    const url = new URL(request.url);
    await this.migrated(await this.scrubber());
    return this.prepare(request, (given) => this.mcpTarget(server, url, given));
  }

  async migrated(scrubber: Scrubber): Promise<void> {
    const clean = (text: string) => scrubber.text(text).text;
    if (await migrate(this.vault.db, this.ns, this.vault.now(), clean)) {
      await this.vault.loadPolicy(this.ns);
      await this.vault.changed(this.ns, ['secrets', 'audit', 'exits']);
    }
  }

  async mcpTarget(server: string, url: URL, given?: Registered): Promise<Target> {
    const registered = given ?? (await loadRegistered(this.vault.db, this.ns));
    const entry = serverFor(registered, server, url);
    const loopback = entry !== null && new URL(entry.url).protocol === 'http:';
    const bound = (record: VaultRecord) => {
      if (entry === null) return true;
      if (!holds(registered, entry, record)) return false;
      const overridden = record.pinned === true && pageServer(registered, record.server);
      if (record.url !== undefined && !overridden) return under(record.url, url);
      return !pageSealed(record) || under(entry.url, url);
    };
    const names = new Set(
      servers(registered)
        .filter((e) => e.server === server)
        .flatMap((e) => e.names)
    );
    return {
      who: server,
      owns: (record) =>
        record.kind === 'mcp' &&
        (record.server === server || names.has(record.name)) &&
        bound(record),
      reaches: () => entry !== null && !modelRefused(registered, url),
      loopback,
      settle: async (filled) => {
        const fresh = entry ? filled.filter((r) => tofu(registered, entry, r)) : [];
        if (!fresh.length) return;
        const scrubber = await this.scrubber();
        const clean = (text: string) => scrubber.text(text).text;
        const names = fresh.map((r) => r.name);
        const done = await pin(
          this.vault.db,
          this.ns,
          names,
          entry as McpServer,
          this.vault.now(),
          clean
        );
        if (done.pinned) await this.vault.changed(this.ns, ['secrets', 'audit']);
        if (done.elsewhere.length) {
          throw new Refused(
            'EACCES',
            `${done.elsewhere[0]} was pinned to another URL meanwhile; it is sent only there`
          );
        }
      },
    };
  }

  async list(): Promise<Fields> {
    for (let tries = 0; tries < 3; tries++) {
      const scrubber = await this.scrubber();
      const held = await records(this.vault.db, this.ns);
      if ((await this.scrubber()).version === scrubber.version) return this.shown(scrubber, held);
    }
    throw new Refused('EAGAIN', "the vault's values keep changing; try again");
  }

  shown(scrubber: Scrubber, held: VaultRecord[]): Fields {
    const clean = (settings: Record<string, string>) =>
      Object.fromEntries(
        Object.entries(settings)
          .filter(([key]) => scrubber.text(key).hits.length === 0)
          .map(([key, value]) => [key, scrubber.text(value).text])
      );
    const now = this.vault.now();
    const echoed = (t: string) => scrubber.text(t).hits.length > 0;
    const plain = (r: VaultRecord) =>
      [r.name, r.provider ?? '', r.server ?? ''].every((t) => scrubber.text(t).hits.length === 0);
    const shown = held.filter(
      (r) => (r.kind === 'model' || r.kind === 'mcp') && !removed(r) && plain(r)
    );
    const dead = new Set(held.filter((r) => r.kind === 'grant' && r.dead).map((r) => r.name));
    return {
      records: shown.map((r) => {
        const expired = r.expiresAt !== undefined && r.expiresAt <= now;
        const renews = r.refresh !== undefined && !dead.has(r.refresh);
        return {
          kind: r.kind,
          name: r.name,
          placeholder: r.placeholder,
          state: expired ? (renews ? 'refreshing' : 'expired') : 'ready',
          ...(r.provider === undefined ? {} : { provider: r.provider }),
          ...(r.server === undefined ? {} : { server: r.server }),
          ...(r.expiresAt === undefined || echoed(String(r.expiresAt))
            ? {}
            : { expiresAt: r.expiresAt }),
          ...(r.settings === undefined ? {} : { settings: clean(r.settings) }),
        };
      }),
    };
  }

  async signIn(fields: Fields): Promise<Fields> {
    const provider = fields.provider as string;
    const response = fields.response;
    const oauth = typeof provider === 'string' ? signIn(provider) : null;
    if (!oauth) throw new Refused('ENOTSUP', `the vault has no sign-in for ${String(provider)}`);
    if (fields.server !== undefined || fields.oauth !== undefined) {
      throw new Refused(
        'EINVAL',
        'a provider sign-in takes no server or oauth: the vault knows them'
      );
    }
    if (typeof response !== 'string' && !(response instanceof Uint8Array)) {
      throw new Refused('EINVAL', 'response must be the token response body');
    }
    const name = fields.name;
    if (typeof name !== 'string' || !NAME.test(name) || `${name}_GRANT`.length > 128) {
      throw new Refused('EINVAL', "name must be the account's record name");
    }
    const scrubber = await this.scrubber();
    if (scrubber.text(name).hits.length > 0) throw new Refused('EINVAL', 'the name holds a value');
    const bound = binding('model', { provider, settings: fields.settings });
    const now = this.vault.now();
    const got = await tokens({ status: 200, headers: [], body: response }, scrubber, now, true);
    checkValue(got.access);
    if (got.refresh !== null) checkValue(got.refresh);
    const grantName = `${name}_GRANT`;
    const common = { ns: this.ns, source: `oauth:${provider}` as const, uid: null, tag: null, now };
    const access: SealInput = {
      ...common,
      kind: 'model',
      name,
      value: got.access,
      ...bound,
      stash: true,
      ...(got.expires === null ? {} : { expiresAt: now + got.expires * 1000 }),
      ...(got.refresh !== null ? { refresh: grantName } : {}),
    };
    const grant: SealInput[] =
      got.refresh !== null
        ? [{ ...common, kind: 'grant', name: grantName, value: got.refresh, oauth }]
        : [];
    const dek = this.vault.keyring.use();
    const written = (await sealAll(this.vault.db, dek, [access, ...grant])).map((s) => s.record);
    await this.vault.changed(this.ns, ['secrets', 'audit']);
    const expiry = written[0].expiresAt;
    return {
      records: written.map((r) => ({ kind: r.kind, name: r.name, placeholder: r.placeholder })),
      ...(expiry === undefined ? {} : { expiresAt: expiry }),
    };
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
    await this.migrated(before);
    const registered = await loadRegistered(this.vault.db, this.ns);
    if (!servers(registered).some((e) => e.server === server && e.tokenUrl === oauth.tokenUrl)) {
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
    const got = await tokens(
      { status: 200, headers: [], body: response },
      await this.vault.scrubbers.get(this.ns),
      this.vault.now()
    );
    checkValue(got.access);
    if (got.refresh !== null) checkValue(got.refresh);
    const returned = compile(
      [got.access, ...(got.refresh === null ? [] : [got.refresh])].map((value, i) => ({
        name: `T${i}`,
        placeholder: `fnox_proxy_${'0'.repeat(23)}${i}`,
        value,
      })),
      { version: 0 }
    );
    const tokensIn = (text: string) =>
      returned.text(text).hits.some((hit) => hit.form !== 'fragment');
    if (tokensIn(server) || tokensIn(base) || tokensIn(grantName)) {
      throw new Refused('EINVAL', 'the server or record name holds a value');
    }
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
        ? [{ ...common, kind: 'grant', name: grantName, value: got.refresh, oauth, server }]
        : [];
    const written = (await sealAll(this.vault.db, dek, [access, ...grant])).map((s) => s.record);
    const [sealedAccess, sealedGrant] = written;
    await this.vault.changed(this.ns, ['secrets', 'audit']);
    const raw = typeof response === 'string' ? response : text(response);
    const parsed = JSON.parse(raw) as Fields;
    const scrubber = (await this.vault.scrubbers.get(this.ns)) as Scrubber;
    const rewritten = JSON.stringify({
      ...plainFields(parsed, scrubber, [
        [got.access, sealedAccess.placeholder],
        ...(sealedGrant
          ? [[got.refresh as string, sealedGrant.placeholder] as [string, string]]
          : []),
      ]),
      access_token: sealedAccess.placeholder,
      ...(sealedGrant ? { refresh_token: sealedGrant.placeholder } : {}),
    });
    const own = new Set(written.map((r) => r.name));
    const foreign = (t: string) => scrubber.text(t).hits.some((h) => !own.has(h.name));
    const named = (t: string) => (foreign(t) ? scrubber.text(t).text : t);
    const shown = written.map((r) => ({
      kind: r.kind,
      name: named(r.name),
      placeholder: r.placeholder,
    }));
    const expiry = sealedAccess.expiresAt;
    return {
      response: typeof response === 'string' ? rewritten : new TextEncoder().encode(rewritten),
      records: shown,
      ...(expiry === undefined || foreign(String(expiry)) ? {} : { expiresAt: expiry }),
    };
  }

  async refresh(fields: Fields): Promise<Fields> {
    const { server, provider } = fields;
    const byServer = typeof server === 'string' && server;
    const byProvider = typeof provider === 'string' && provider;
    if (!byServer === !byProvider)
      throw new Refused('EINVAL', 'refresh takes a server or a provider');
    const named = fields.name;
    const before = await this.scrubber();
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
    const reply = await this.vault.refresher.refresh(this.ns, found.name, found.kind as TokenKind);
    const expiry = reply.expiresAt;
    if (typeof expiry !== 'number') return reply;
    const after = await this.scrubber();
    const alone = after.version <= before.version + 1;
    const echoes = [before, after].some((x) => x.text(String(expiry)).hits.length > 0);
    if (alone && !echoes) return reply;
    const { expiresAt: _echo, ...rest } = reply;
    return rest;
  }
}

function plainFields(parsed: Fields, scrubber: Scrubber, swaps: [string, string][]): Fields {
  const swap = (text: string) =>
    swaps.reduce((out, [token, placeholder]) => out.split(token).join(placeholder), text);
  const kept: Fields = {};
  if (typeof parsed.token_type === 'string') kept.token_type = parsed.token_type;
  const lifetime = parsed.expires_in;
  const echoes = (text: string) => scrubber.text(text).hits.length > 0 || swap(text) !== text;
  if (typeof lifetime === 'number' && !echoes(String(lifetime))) kept.expires_in = lifetime;
  if (typeof parsed.scope === 'string') kept.scope = scrubber.text(swap(parsed.scope)).text;
  return kept;
}

function defaultName(server: string): string {
  const upper = server.toUpperCase().replace(/[^A-Z0-9_]/g, '_');
  return `${/^[A-Z_]/.test(upper) ? '' : 'MCP_'}${upper}_ACCESS_TOKEN`.slice(0, 120);
}
