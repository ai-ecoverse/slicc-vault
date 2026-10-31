import { hex } from './bytes.ts';
import type { Attestation, MissingPolicyFile, PolicyFile } from './contract.ts';
import { FILES } from './policy.ts';

export type Verdict =
  | { trusted: true; path: PolicyFile; sha256: string; text: string }
  | { trusted: true; path: PolicyFile; absent: true }
  | { trusted: false; path: string; sha256: string | null; warning: string };

const WRITABLE = 0o022;
const TYPE = 0o170000;
const FILE = 0o100000;
const DIRECTORY = 0o040000;
const FIELDS = [
  'path',
  'bytes',
  'uid',
  'gid',
  'mode',
  'ino',
  'mtimeMs',
  'sha256',
  'users',
  'onRootFs',
  'parents',
];
const ABSENT_FIELDS = ['path', 'absent', 'users', 'onRootFs', 'parents'];
const PARENT_FIELDS = ['path', 'uid', 'gid', 'mode'];
const USERS = new Set(['off', 'report', 'enforce']);

type Fields = Record<string, unknown>;

function integer(value: unknown): boolean {
  return typeof value === 'number' && Number.isInteger(value);
}

function exactly(value: unknown, fields: string[]): value is Fields {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return keys.length === fields.length && fields.every((field) => keys.includes(field));
}

function wellFormedParent(parent: unknown): boolean {
  if (!exactly(parent, PARENT_FIELDS)) return false;
  return (
    typeof parent.path === 'string' &&
    integer(parent.uid) &&
    integer(parent.gid) &&
    integer(parent.mode)
  );
}

export function wellFormed(value: unknown): value is Attestation {
  if (!exactly(value, FIELDS)) return false;
  return (
    typeof value.path === 'string' &&
    value.bytes instanceof Uint8Array &&
    integer(value.uid) &&
    integer(value.gid) &&
    integer(value.mode) &&
    typeof value.ino === 'number' &&
    typeof value.mtimeMs === 'number' &&
    typeof value.sha256 === 'string' &&
    /^[0-9a-f]{64}$/.test(value.sha256) &&
    typeof value.users === 'string' &&
    USERS.has(value.users) &&
    typeof value.onRootFs === 'boolean' &&
    Array.isArray(value.parents) &&
    value.parents.every(wellFormedParent)
  );
}

export function wellFormedAbsent(value: unknown): value is MissingPolicyFile {
  if (!exactly(value, ABSENT_FIELDS)) return false;
  return (
    typeof value.path === 'string' &&
    value.absent === true &&
    typeof value.users === 'string' &&
    USERS.has(value.users) &&
    typeof value.onRootFs === 'boolean' &&
    Array.isArray(value.parents) &&
    value.parents.every(wellFormedParent)
  );
}

export function ancestors(path: string): string[] {
  const parts = path.split('/').slice(1, -1);
  return ['/', ...parts.map((_, i) => `/${parts.slice(0, i + 1).join('/')}`)];
}

function safe(mode: number, type: number): boolean {
  return (mode & TYPE) === type && (mode & WRITABLE) === 0;
}

function misplaced(attestation: Attestation | MissingPolicyFile): string | null {
  const expected = ancestors(attestation.path);
  const parents = attestation.parents;
  const listed =
    parents.length === expected.length && parents.every((p, i) => p.path === expected[i]);
  if (!listed) return "its parents aren't exactly the directories above it";
  if (!parents.every((p) => p.uid === 0 && safe(p.mode, DIRECTORY))) {
    return "a parent directory isn't root-owned, or is writable by group or others";
  }
  if (!attestation.onRootFs) return "it isn't on the root file system";
  if (attestation.users !== 'enforce') return 'kernel users must be enforce';
  return null;
}

function problem(attestation: Attestation, sha256: string): string | null {
  if (sha256 !== attestation.sha256) return "its bytes don't match the attestation";
  if (attestation.uid !== 0) return "it isn't root-owned";
  if (!safe(attestation.mode, FILE))
    return "it isn't a regular file, or is writable by group or others";
  return misplaced(attestation);
}

async function digest(bytes: Uint8Array): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(bytes))));
}

export async function verify(value: unknown): Promise<Verdict> {
  const path =
    typeof (value as Fields | null)?.path === 'string' ? ((value as Fields).path as string) : '';
  if (!FILES.includes(path as PolicyFile)) {
    const warning = `rules not trusted: ${path || 'a file'} isn't a policy file`;
    return { trusted: false, path, sha256: null, warning };
  }
  if (wellFormedAbsent(value)) {
    const issue = misplaced(value);
    if (!issue) return { trusted: true, path: path as PolicyFile, absent: true };
    return { trusted: false, path, sha256: null, warning: `rules not trusted: ${path}: ${issue}` };
  }
  if (!wellFormed(value)) {
    const warning = `rules not trusted: ${path}: the attestation isn't in the kernel's format`;
    const bytes = (value as Fields).bytes;
    const sha256 = bytes instanceof Uint8Array ? await digest(bytes) : null;
    return { trusted: false, path, sha256, warning };
  }
  const bytes = new Uint8Array(value.bytes);
  const sha256 = await digest(bytes);
  const issue = problem(value, sha256);
  if (issue)
    return { trusted: false, path, sha256, warning: `rules not trusted: ${path}: ${issue}` };
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    return { trusted: true, path: path as PolicyFile, sha256, text };
  } catch {
    return { trusted: false, path, sha256, warning: `rules not trusted: ${path} isn't UTF-8` };
  }
}
