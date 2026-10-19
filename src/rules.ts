import { verify } from './attest.ts';
import type { PolicyChange, PolicyFile, PolicyFileState, PolicyResult, Rule } from './contract.ts';
import { all, request, transact } from './db.ts';
import { Refused } from './errors.ts';
import {
  type Accepted,
  build,
  CONFIG_FILE,
  type ConfigPolicy,
  diffConfig,
  diffExtra,
  type ExtraPolicy,
  NONE,
  type Policy,
  parseConfig,
  parseExtra,
} from './policy.ts';
import { audit, NAME, PROVIDER, removed, type VaultRecord } from './records.ts';
import {
  servers as allServers,
  type Custom,
  contains,
  coveredByBuiltIn,
  endpoint,
  type McpServer,
  NO_ENDPOINTS,
  NO_PAGE,
  type Owned,
  onHost,
  patterns,
  type Registered,
  under,
} from './refusal.ts';

export interface Stored {
  accepted: Accepted;
  seen: Record<string, string[]>;
  last?: PolicyFileState[];
}

const EMPTY_STORE: Stored = { accepted: NONE, seen: {} };

export function loadStored(db: IDBDatabase, ns: string): Promise<Stored> {
  return transact(db, ['meta'], 'readonly', async (tx) => {
    const stored = (await request(tx.objectStore('meta').get(`policy:${ns}`))) as
      | Stored
      | undefined;
    return stored ?? EMPTY_STORE;
  });
}

export function loadRegistered(db: IDBDatabase, ns: string): Promise<Registered> {
  return transact(db, ['meta'], 'readonly', async (tx) => {
    const stored = (await request(tx.objectStore('meta').get(`endpoints:${ns}`))) as
      | Registered
      | undefined;
    return stored ?? NO_ENDPOINTS;
  });
}

export function refuser(registered: Registered) {
  const all = patterns(registered);
  return (rule: Rule) =>
    all.some((pattern) =>
      rule.protocol === 'smtp' || rule.protocol === 'pg'
        ? onHost(pattern, rule.domain)
        : contains(pattern, rule.domain, rule.paths)
    );
}

export async function policyIn(tx: IDBTransaction, ns: string) {
  const meta = tx.objectStore('meta');
  const [stored, endpoints] = (await Promise.all([
    request(meta.get(`policy:${ns}`)),
    request(meta.get(`endpoints:${ns}`)),
  ])) as [Stored | undefined, Registered | undefined];
  const registered = endpoints ?? NO_ENDPOINTS;
  return { policy: build((stored ?? EMPTY_STORE).accepted, refuser(registered)), registered };
}

export async function loadPolicy(db: IDBDatabase, ns: string): Promise<Policy> {
  return (await transact(db, ['meta'], 'readonly', (tx) => policyIn(tx, ns))).policy;
}

function serversOf(value: unknown): McpServer[] {
  if (!Array.isArray(value)) throw new Refused('EINVAL', 'mcp must be a list');
  return value.map((entry) => {
    const item = typeof entry === 'string' ? { server: entry, url: entry, names: [] } : entry;
    const names = Array.isArray(item?.names) ? item.names : [];
    const tokenUrl = item?.tokenUrl;
    const valid =
      typeof item?.server === 'string' &&
      typeof item.url === 'string' &&
      endpoint(item.url, true) !== null &&
      (tokenUrl === undefined ||
        (typeof tokenUrl === 'string' && endpoint(tokenUrl, false) !== null)) &&
      names.every((name: unknown) => typeof name === 'string' && NAME.test(name));
    if (!valid) throw new Refused('EINVAL', `not an MCP server: ${JSON.stringify(entry)}`);
    const token = tokenUrl === undefined ? {} : { tokenUrl: new URL(tokenUrl).href };
    return { server: item.server, url: item.url, names, ...token };
  });
}

function mergeServers(stored: McpServer[], given: McpServer[], all: McpServer[]): McpServer[] {
  const byUrl = new Map(stored.map((server) => [`${server.server} ${server.url}`, server]));
  const firstToken = new Map<string, string>();
  for (const entry of [...all, ...given]) {
    if (entry.tokenUrl && !firstToken.has(entry.server))
      firstToken.set(entry.server, entry.tokenUrl);
  }
  for (const entry of given) {
    const token = firstToken.get(entry.server);
    const server = token ? { ...entry, tokenUrl: token } : entry;
    const key = `${server.server} ${server.url}`;
    const known = byUrl.get(key);
    byUrl.set(
      key,
      known
        ? { ...server, ...known, names: [...new Set([...known.names, ...server.names])] }
        : server
    );
  }
  return [...byUrl.values()];
}

function count(model: string[], mcp: McpServer[], custom: Owned[] = []): number {
  return model.length + custom.length + mcp.reduce((sum, s) => sum + s.names.length + 1, 0);
}

function modelsOf(model: unknown): string[] {
  const given = model === undefined ? [] : model;
  const ownedOf = (entry: unknown) =>
    entry && typeof entry === 'object' ? (entry as Partial<Owned>) : null;
  const okEntry = (entry: unknown) => {
    const item = ownedOf(entry);
    const url = typeof entry === 'string' ? entry : item?.url;
    const provider = item ? item.provider : 'any';
    return (
      typeof url === 'string' &&
      endpoint(url, false) !== null &&
      typeof provider === 'string' &&
      PROVIDER.test(provider)
    );
  };
  if (!Array.isArray(given) || !given.every(okEntry)) {
    throw new Refused('EINVAL', 'model must be a list of https base URLs or { provider, url }');
  }
  return given.map((entry) => (typeof entry === 'string' ? entry : (entry as Owned).url));
}

interface Bound {
  name: string;
  url: string;
}

function bound(item: unknown): item is Bound {
  return (
    !!item &&
    typeof item === 'object' &&
    typeof (item as Bound).name === 'string' &&
    typeof (item as Bound).url === 'string'
  );
}

interface PageModels {
  plain: string[];
  bound: Bound[];
}

function pageModelsOf(model: unknown): PageModels {
  const given = model === undefined ? [] : model;
  const ok = (item: unknown) =>
    (typeof item === 'string' && endpoint(item, false) !== null) ||
    (bound(item) &&
      NAME.test(item.name) &&
      endpoint(item.url, false) !== null &&
      !/[*{}]/.test(item.url));
  if (!Array.isArray(given) || !given.every(ok)) {
    throw new Refused(
      'EINVAL',
      'model must be a list of https base URLs or { name, url } for a model record'
    );
  }
  return {
    plain: given.filter((item) => typeof item === 'string') as string[],
    bound: (given.filter((item) => typeof item !== 'string') as Bound[]).map(({ name, url }) => ({
      name,
      url,
    })),
  };
}

interface Removal {
  urls: Set<string>;
  bound: Set<string>;
  servers: Set<string>;
}

const REMOVE = 'remove must be { model?: (url | { name, url })[], mcp?: { server, url }[] }';

function removalOf(remove: unknown): Removal {
  if (remove !== undefined && (!remove || typeof remove !== 'object' || Array.isArray(remove))) {
    throw new Refused('EINVAL', REMOVE);
  }
  const given = (remove ?? {}) as { model?: unknown; mcp?: unknown };
  const model = given.model ?? [];
  const mcp = given.mcp ?? [];
  const entry = (item: unknown) => typeof item === 'string' || bound(item);
  const server = (item: unknown) =>
    !!item &&
    typeof item === 'object' &&
    typeof (item as McpServer).server === 'string' &&
    typeof (item as McpServer).url === 'string';
  if (!Array.isArray(model) || !model.every(entry) || !Array.isArray(mcp) || !mcp.every(server)) {
    throw new Refused('EINVAL', REMOVE);
  }
  return {
    urls: new Set(model.filter((item) => typeof item === 'string')),
    bound: new Set((model.filter(bound) as Bound[]).map((b) => `${b.name} ${b.url}`)),
    servers: new Set((mcp as McpServer[]).map((s) => `${s.server} ${s.url}`)),
  };
}

async function customFor(tx: IDBTransaction, ns: string, given: Bound[]): Promise<Custom[]> {
  const store = tx.objectStore('records');
  const out: Custom[] = [];
  for (const { name, url } of given) {
    const record = (await request(store.get([ns, 'model', name]))) as VaultRecord | undefined;
    if (!record || removed(record) || typeof record.provider !== 'string') {
      throw new Refused('EINVAL', `${name} isn't a model record of this vault`);
    }
    out.push({ provider: record.provider, name, url });
  }
  return out;
}

export function dropCustom(db: IDBDatabase, ns: string, name: string): Promise<boolean> {
  return transact(db, ['meta'], 'readwrite', async (tx) => {
    const before = await stored(tx, ns);
    const page = before.page ?? NO_PAGE;
    const custom = page.custom.filter((entry) => entry.name !== name);
    if (custom.length === page.custom.length) return false;
    await request(
      tx.objectStore('meta').put({ ...before, page: { ...page, custom } }, `endpoints:${ns}`)
    );
    return true;
  });
}

function stored(tx: IDBTransaction, ns: string): Promise<Registered> {
  return request(tx.objectStore('meta').get(`endpoints:${ns}`)).then(
    (found) => (found as Registered | undefined) ?? NO_ENDPOINTS
  );
}

export function register(
  db: IDBDatabase,
  ns: string,
  model: unknown,
  mcp: unknown
): Promise<{ registered: Registered; added: number }> {
  const models = modelsOf(model);
  const given = mcp === undefined ? [] : serversOf(mcp);
  return transact(db, ['meta'], 'readwrite', async (tx) => {
    const before = await stored(tx, ns);
    const owned = new Set((before.page ?? NO_PAGE).mcp.map((server) => server.server));
    const mcps = given.filter((server) => !owned.has(server.server));
    const registered = {
      ...before,
      ...(before === NO_ENDPOINTS ? { migrated: true } : {}),
      model: [...new Set([...before.model, ...models])],
      mcp: mergeServers(before.mcp, mcps, allServers(before)),
    };
    const added = count(registered.model, registered.mcp) - count(before.model, before.mcp);
    await request(tx.objectStore('meta').put(registered, `endpoints:${ns}`));
    return { registered, added };
  });
}

function unpinOf(unpin: unknown): string[] {
  const given = unpin === undefined ? [] : unpin;
  if (
    !Array.isArray(given) ||
    !given.every((name) => typeof name === 'string' && NAME.test(name))
  ) {
    throw new Refused('EINVAL', 'unpin must be a list of mcp record names');
  }
  return given;
}

async function unpinIn(tx: IDBTransaction, ns: string, names: string[], now: number, clean: Clean) {
  const store = tx.objectStore('records');
  let count = 0;
  for (const name of names) {
    const record = (await request(store.get([ns, 'mcp', name]))) as VaultRecord | undefined;
    if (!record?.pinned) continue;
    const next: VaultRecord = { ...record, unpins: (record.unpins ?? 0) + 1 };
    delete next.url;
    delete next.pinned;
    await request(store.put(next));
    const host = clean(new URL(record.url as string).hostname);
    await audit(tx, ns, {
      type: 'endpoints',
      unpinned: { name: clean(name), server: clean(record.server as string), host },
      uid: null,
      tag: null,
      at: now,
    });
    count += 1;
  }
  return count;
}

export function registerPage(
  db: IDBDatabase,
  ns: string,
  model: unknown,
  mcp: unknown,
  remove?: unknown,
  unpin?: unknown,
  now = 0,
  clean: Clean = (text) => text
): Promise<{ registered: Registered; changed: number; unpins: number }> {
  const models = pageModelsOf(model);
  const mcps = mcp === undefined ? [] : serversOf(mcp);
  const removal = removalOf(remove);
  const unpinned = unpinOf(unpin);
  return transact(db, ['meta', 'records', 'audit'], 'readwrite', async (tx) => {
    const before = await stored(tx, ns);
    const page = before.page ?? NO_PAGE;
    const mcpNext = mergeServers(page.mcp, mcps, page.mcp);
    const custom = await customFor(tx, ns, models.bound);
    const byKey = new Map([...page.custom, ...custom].map((c) => [`${c.name} ${c.url}`, c]));
    const next = {
      model: [...new Set([...page.model, ...models.plain])].filter((url) => !removal.urls.has(url)),
      mcp: mcpNext.filter((s) => !removal.servers.has(`${s.server} ${s.url}`)),
      custom: [...byKey.values()].filter((c) => !removal.bound.has(`${c.name} ${c.url}`)),
    };
    const overlap = next.custom.find((c) =>
      next.mcp.some(
        (server) => under(server.url, new URL(c.url)) || under(c.url, new URL(server.url))
      )
    );
    if (overlap) {
      throw new Refused('EINVAL', `${overlap.url} is an MCP server, never a model endpoint`);
    }
    const changed = JSON.stringify(next) !== JSON.stringify(page);
    const fresh = before === NO_ENDPOINTS ? { migrated: true } : {};
    const gone = page.mcp
      .map((server) => server.server)
      .filter((name) => !next.mcp.some((server) => server.server === name));
    const held = [...new Set([...(before.held ?? []), ...gone])];
    const registered = { ...before, ...fresh, page: next, ...(held.length ? { held } : {}) };
    if (changed) await request(tx.objectStore('meta').put(registered, `endpoints:${ns}`));
    const unpins = await unpinIn(tx, ns, unpinned, now, clean);
    return { registered, changed: changed ? 1 : 0, unpins };
  });
}

export type Clean = (text: string) => string;

export function pin(
  db: IDBDatabase,
  ns: string,
  names: string[],
  server: McpServer,
  now: number,
  clean: Clean
): Promise<{ pinned: number; elsewhere: string[] }> {
  const url = new URL(server.url).href;
  return transact(db, ['records', 'audit'], 'readwrite', async (tx) => {
    const store = tx.objectStore('records');
    let pinned = 0;
    const elsewhere: string[] = [];
    for (const name of names) {
      const record = (await request(store.get([ns, 'mcp', name]))) as VaultRecord | undefined;
      if (!record || removed(record)) continue;
      if (record.url !== undefined) {
        if (record.url !== url) elsewhere.push(name);
        continue;
      }
      await request(store.put({ ...record, url, pinned: true }));
      const host = clean(new URL(url).hostname);
      await audit(tx, ns, {
        type: 'endpoints',
        pinned: { name: clean(name), server: clean(server.server), host },
        uid: null,
        tag: null,
        at: now,
      });
      pinned += 1;
    }
    return { pinned, elsewhere };
  });
}

function hostOfUrl(url: string): string {
  return URL.parse(url)?.hostname ?? '';
}

export function migrate(db: IDBDatabase, ns: string, now: number, clean: Clean): Promise<boolean> {
  return transact(db, ['meta', 'records', 'audit'], 'readwrite', async (tx) => {
    const meta = tx.objectStore('meta');
    const before = (await request(meta.get(`endpoints:${ns}`))) as Registered | undefined;
    if (!before || before.migrated) return false;
    const purged = (before.owned ?? [])
      .filter((entry) => !coveredByBuiltIn(entry.provider, entry.url))
      .map((entry) => ({ provider: clean(entry.provider), host: clean(hostOfUrl(entry.url)) }));
    const page = before.page ?? NO_PAGE;
    const owned = new Set(page.mcp.map((server) => server.server));
    const held = (await all<VaultRecord>(tx, 'records', ns)).filter(
      (r) =>
        r.kind === 'mcp' &&
        r.url === undefined &&
        r.source !== 'oauth:mcp' &&
        typeof r.server === 'string' &&
        !owned.has(r.server)
    );
    const tombstones = new Set(before.held ?? []);
    const wanted = new Set(held.map((r) => r.server as string).filter((n) => !tombstones.has(n)));
    const urls = (name: string) => before.mcp.filter((server) => server.server === name).length;
    const adopted = before.mcp.filter(
      (server) => wanted.has(server.server) && urls(server.server) === 1
    );
    const ambiguous = [...wanted].filter((name) => urls(name) > 1);
    const next: Registered = {
      ...before,
      mcp: before.mcp.filter((server) => !adopted.includes(server)),
      page: { ...page, mcp: [...page.mcp, ...adopted] },
      migrated: true,
      ...(ambiguous.length || tombstones.size
        ? { held: [...new Set([...tombstones, ...ambiguous])] }
        : {}),
    };
    delete next.owned;
    await request(meta.put(next, `endpoints:${ns}`));
    const shown = adopted.map((s) => ({ server: clean(s.server), host: clean(hostOfUrl(s.url)) }));
    if (!purged.length && !shown.length) return false;
    await audit(tx, ns, {
      type: 'endpoints',
      ...(purged.length ? { purged } : {}),
      ...(shown.length ? { adopted: shown } : {}),
      uid: null,
      tag: null,
      at: now,
    });
    return true;
  });
}

export const SEEN = 64;

type Evaluation =
  | { path: string; sha256: string | null; trusted: false; warnings: string[] }
  | {
      path: string;
      sha256: string;
      trusted: true;
      warnings: string[];
      config?: ConfigPolicy;
      extra?: ExtraPolicy;
    };

async function evaluate(upload: unknown): Promise<Evaluation> {
  const verdict = await verify(upload);
  if (!verdict.trusted) {
    const { path, sha256, warning } = verdict;
    return { path, sha256, trusted: false, warnings: [warning] };
  }
  const warnings: string[] = [];
  const { path, sha256 } = verdict;
  try {
    if (path === CONFIG_FILE) {
      return { path, sha256, trusted: true, warnings, config: parseConfig(verdict.text, warnings) };
    }
    return { path, sha256, trusted: true, warnings, extra: parseExtra(verdict.text, warnings) };
  } catch (error) {
    const warning = `rules not trusted: ${path}: ${(error as Error).message}`;
    return { path, sha256, trusted: false, warnings: [warning] };
  }
}

function current(accepted: Accepted, path: string): string | null {
  return (path === CONFIG_FILE ? accepted.config?.sha256 : accepted.extra?.sha256) ?? null;
}

function merge(
  accepted: Accepted,
  evaluation: Evaluation
): { next: Accepted; changes: PolicyChange[] } {
  if (!evaluation.trusted || current(accepted, evaluation.path) === evaluation.sha256) {
    return { next: accepted, changes: [] };
  }
  if (evaluation.config) {
    const changes = diffConfig(accepted.config?.parsed ?? null, evaluation.config);
    return {
      next: { ...accepted, config: { sha256: evaluation.sha256, parsed: evaluation.config } },
      changes,
    };
  }
  const extra = evaluation.extra as ExtraPolicy;
  const changes = diffExtra(accepted.extra?.parsed ?? null, extra);
  return { next: { ...accepted, extra: { sha256: evaluation.sha256, parsed: extra } }, changes };
}

function states(evaluations: Evaluation[]): PolicyFileState[] {
  return evaluations.map(({ path, sha256, trusted, warnings }) => ({
    path,
    sha256,
    accepted: trusted,
    warnings,
  }));
}

function remember(seen: Record<string, string[]>, path: string, sha256: string): boolean {
  const known = Array.isArray(seen[path]) ? seen[path] : [];
  if (known.includes(sha256)) return false;
  seen[path] = [...known, sha256].slice(-SEEN);
  return true;
}

export async function apply(
  db: IDBDatabase,
  ns: string,
  files: unknown,
  now: number
): Promise<{ result: PolicyResult; changed: boolean }> {
  const uploads = Array.isArray(files) ? files.slice(0, 2) : [];
  const evaluations: Evaluation[] = [];
  for (const upload of uploads) evaluations.push(await evaluate(upload));
  const { accepted, changed } = await transact(db, ['meta', 'audit'], 'readwrite', async (tx) => {
    const meta = tx.objectStore('meta');
    const stored = ((await request(meta.get(`policy:${ns}`))) as Stored | undefined) ?? EMPTY_STORE;
    const seen = { ...stored.seen };
    let next = stored.accepted;
    let moved = false;
    for (const evaluation of evaluations) {
      const merged = merge(next, evaluation);
      moved ||= merged.next !== next;
      next = merged.next;
      const mark = `${evaluation.trusted ? 'trusted' : 'refused'}:${evaluation.sha256}`;
      if (evaluation.sha256 === null || !remember(seen, evaluation.path, mark)) continue;
      moved = true;
      await audit(tx, ns, {
        type: 'policy',
        uid: null,
        tag: null,
        file: evaluation.path as PolicyFile,
        sha256: evaluation.sha256,
        accepted: evaluation.trusted,
        changes: merged.changes,
        ...(evaluation.warnings.length ? { warning: evaluation.warnings.join('; ') } : {}),
        at: now,
      });
    }
    await request(meta.put({ accepted: next, seen, last: states(evaluations) }, `policy:${ns}`));
    return { accepted: next, changed: moved };
  });
  const rules = (accepted.config?.parsed.rules ?? []).map(({ secret, rule }) => ({
    secret,
    ...rule,
  }));
  const result: PolicyResult = {
    accepted: evaluations.length > 0 && evaluations.every((e) => e.trusted),
    files: states(evaluations),
    rules,
    warnings: evaluations.flatMap((e) => e.warnings),
  };
  return { result, changed };
}
