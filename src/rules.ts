import { verify } from './attest.ts';
import type { PolicyChange, PolicyFile, PolicyFileState, PolicyResult, Rule } from './contract.ts';
import { request, transact } from './db.ts';
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
import { audit, NAME, PROVIDER } from './records.ts';
import {
  servers as allServers,
  contains,
  endpoint,
  type McpServer,
  NO_ENDPOINTS,
  NO_PAGE,
  type Owned,
  onHost,
  patterns,
  type Registered,
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

export function register(
  db: IDBDatabase,
  ns: string,
  model: unknown,
  mcp: unknown,
  role: 'agent' | 'page' = 'agent'
): Promise<{ registered: Registered; added: number }> {
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
  const models = given.map((entry) => (typeof entry === 'string' ? entry : (entry as Owned).url));
  const plain = given.filter((entry) => typeof entry === 'string') as string[];
  const custom = given
    .filter((entry) => typeof entry !== 'string')
    .map((entry) => ({ provider: (entry as Owned).provider, url: (entry as Owned).url }));
  const mcps = mcp === undefined ? [] : serversOf(mcp);
  return transact(db, ['meta'], 'readwrite', async (tx) => {
    const meta = tx.objectStore('meta');
    const stored =
      ((await request(meta.get(`endpoints:${ns}`))) as Registered | undefined) ?? NO_ENDPOINTS;
    const page = stored.page ?? NO_PAGE;
    const all = allServers(stored);
    let registered: Registered;
    let added: number;
    if (role === 'page') {
      const ownedBy = new Map(
        [...page.custom, ...custom].map((o) => [`${o.provider} ${o.url}`, o])
      );
      const next = {
        model: [...new Set([...page.model, ...plain])],
        mcp: mergeServers(page.mcp, mcps, all),
        custom: [...ownedBy.values()],
      };
      registered = { ...stored, page: next };
      added = count(next.model, next.mcp, next.custom) - count(page.model, page.mcp, page.custom);
    } else {
      registered = {
        ...stored,
        model: [...new Set([...stored.model, ...models])],
        mcp: mergeServers(stored.mcp, mcps, all),
      };
      added = count(registered.model, registered.mcp) - count(stored.model, stored.mcp);
    }
    await request(meta.put(registered, `endpoints:${ns}`));
    return { registered, added };
  });
}

export function unregister(db: IDBDatabase, ns: string, remove: unknown): Promise<number> {
  const given = (remove ?? {}) as { model?: unknown; mcp?: unknown };
  const model = given.model ?? [];
  const mcp = given.mcp ?? [];
  const entry = (item: unknown) =>
    typeof item === 'string' ||
    (!!item &&
      typeof item === 'object' &&
      typeof (item as Owned).provider === 'string' &&
      typeof (item as Owned).url === 'string');
  const server = (item: unknown) =>
    !!item &&
    typeof item === 'object' &&
    typeof (item as McpServer).server === 'string' &&
    typeof (item as McpServer).url === 'string';
  if (!Array.isArray(model) || !model.every(entry) || !Array.isArray(mcp) || !mcp.every(server)) {
    throw new Refused(
      'EINVAL',
      'remove must be { model?: (url | { provider, url })[], mcp?: { server, url }[] }'
    );
  }
  const urls = new Set(model.filter((item) => typeof item === 'string'));
  const owned = new Set(
    (model.filter((item) => typeof item !== 'string') as Owned[]).map(
      (o) => `${o.provider} ${o.url}`
    )
  );
  const servers = new Set((mcp as McpServer[]).map((s) => `${s.server} ${s.url}`));
  return transact(db, ['meta'], 'readwrite', async (tx) => {
    const meta = tx.objectStore('meta');
    const stored =
      ((await request(meta.get(`endpoints:${ns}`))) as Registered | undefined) ?? NO_ENDPOINTS;
    const page = stored.page ?? NO_PAGE;
    const next = {
      model: page.model.filter((url) => !urls.has(url)),
      mcp: page.mcp.filter((s) => !servers.has(`${s.server} ${s.url}`)),
      custom: page.custom.filter((o) => !owned.has(`${o.provider} ${o.url}`)),
    };
    const removed =
      count(page.model, page.mcp, page.custom) - count(next.model, next.mcp, next.custom);
    if (removed) await request(meta.put({ ...stored, page: next }, `endpoints:${ns}`));
    return removed;
  });
}

export function purgeOwned(db: IDBDatabase, ns: string, now: number): Promise<number> {
  return transact(db, ['meta', 'audit'], 'readwrite', async (tx) => {
    const meta = tx.objectStore('meta');
    const stored = (await request(meta.get(`endpoints:${ns}`))) as Registered | undefined;
    if (stored?.owned === undefined) return 0;
    const owned = stored.owned;
    const rest: Registered = { ...stored };
    delete rest.owned;
    await request(meta.put(rest, `endpoints:${ns}`));
    if (owned.length) {
      await audit(tx, ns, { type: 'endpoints', purged: owned, uid: null, tag: null, at: now });
    }
    return owned.length;
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
