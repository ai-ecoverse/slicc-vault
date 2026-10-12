import { verify } from './attest.ts';
import type { PolicyChange, PolicyFile, PolicyFileState, PolicyResult } from './contract.ts';
import { request, transact } from './db.ts';
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
import { audit } from './records.ts';

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

export async function loadPolicy(db: IDBDatabase, ns: string): Promise<Policy> {
  return build((await loadStored(db, ns)).accepted);
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
): Promise<{ result: PolicyResult; policy: Policy; changed: boolean }> {
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
  return { result, policy: build(accepted), changed };
}
