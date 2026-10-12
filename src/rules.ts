import { verify } from './attest.ts';
import type { PolicyChange, PolicyFile, PolicyFileState, PolicyResult } from './contract.ts';
import { request, transact } from './db.ts';
import {
  type Accepted,
  build,
  CONFIG_FILE,
  diffConfig,
  diffExtra,
  NONE,
  type Policy,
  parseConfig,
  parseExtra,
} from './policy.ts';
import { audit } from './records.ts';

export interface Stored {
  accepted: Accepted;
  seen: Record<string, string>;
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

interface Outcome {
  path: string;
  sha256: string | null;
  accepted: boolean;
  warnings: string[];
  changes: PolicyChange[];
  next: Accepted;
}

async function judge(upload: unknown, accepted: Accepted): Promise<Outcome> {
  const verdict = await verify(upload);
  if (!verdict.trusted) {
    const { path, sha256, warning } = verdict;
    return { path, sha256, accepted: false, warnings: [warning], changes: [], next: accepted };
  }
  const warnings: string[] = [];
  try {
    if (verdict.path === CONFIG_FILE) {
      const parsed = parseConfig(verdict.text, warnings);
      const changes = diffConfig(accepted.config?.parsed ?? null, parsed);
      const next = { ...accepted, config: { sha256: verdict.sha256, parsed } };
      return {
        path: verdict.path,
        sha256: verdict.sha256,
        accepted: true,
        warnings,
        changes,
        next,
      };
    }
    const parsed = parseExtra(verdict.text, warnings);
    const changes = diffExtra(accepted.extra?.parsed ?? null, parsed);
    const next = { ...accepted, extra: { sha256: verdict.sha256, parsed } };
    return { path: verdict.path, sha256: verdict.sha256, accepted: true, warnings, changes, next };
  } catch (error) {
    const warning = `rules not trusted: ${verdict.path}: ${(error as Error).message}`;
    return {
      path: verdict.path,
      sha256: verdict.sha256,
      accepted: false,
      warnings: [warning],
      changes: [],
      next: accepted,
    };
  }
}

function states(outcomes: Outcome[]): PolicyFileState[] {
  return outcomes.map(({ path, sha256, accepted, warnings }) => ({
    path,
    sha256,
    accepted,
    warnings,
  }));
}

function current(accepted: Accepted, path: string): string | null {
  return (path === CONFIG_FILE ? accepted.config?.sha256 : accepted.extra?.sha256) ?? null;
}

export async function apply(
  db: IDBDatabase,
  ns: string,
  files: unknown,
  now: number
): Promise<{ result: PolicyResult; policy: Policy; changed: boolean }> {
  const uploads = Array.isArray(files) ? files.slice(0, 2) : [];
  const stored = await loadStored(db, ns);
  let accepted = stored.accepted;
  const seen = { ...stored.seen };
  const outcomes: Outcome[] = [];
  for (const upload of uploads) {
    const outcome = await judge(upload, accepted);
    outcomes.push(outcome);
    if (outcome.accepted && current(accepted, outcome.path) !== outcome.sha256)
      accepted = outcome.next;
  }
  const fresh = outcomes.filter((o) => o.sha256 !== null && seen[o.path] !== o.sha256);
  await transact(db, ['meta', 'audit'], 'readwrite', async (tx) => {
    for (const outcome of fresh) {
      seen[outcome.path] = outcome.sha256 as string;
      await audit(tx, ns, {
        type: 'policy',
        file: outcome.path as PolicyFile,
        sha256: outcome.sha256,
        accepted: outcome.accepted,
        changes: outcome.changes,
        ...(outcome.warnings.length ? { warning: outcome.warnings.join('; ') } : {}),
        at: now,
      });
    }
    const last = states(outcomes);
    await request(tx.objectStore('meta').put({ accepted, seen, last }, `policy:${ns}`));
  });
  const policy = build(accepted);
  const rules = (accepted.config?.parsed.rules ?? []).map(({ secret, rule }) => ({
    secret,
    ...rule,
  }));
  const result: PolicyResult = {
    accepted: outcomes.length > 0 && outcomes.every((o) => o.accepted),
    files: states(outcomes),
    rules,
    warnings: outcomes.flatMap((o) => o.warnings),
  };
  return { result, policy, changed: fresh.length > 0 };
}
