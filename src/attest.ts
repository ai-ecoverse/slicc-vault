import { hex } from './bytes.ts';
import type { PolicyFile } from './contract.ts';
import { FILES } from './policy.ts';

export interface Attestation {
  path: string;
  uid: number;
  gid: number;
  mode: number;
  ino: number;
  mtimeMs: number;
  sha256: string;
  users: string;
  onRootFs: boolean;
  parents: { path: string; uid: number; mode: number }[];
}

export interface Upload {
  path: string;
  bytes: Uint8Array | string;
  attestation: Attestation;
}

export type Verdict =
  | { trusted: true; path: PolicyFile; sha256: string; text: string }
  | { trusted: false; path: string; sha256: string | null; warning: string };

const WRITABLE = 0o022;

function bytesOf(bytes: unknown): Uint8Array<ArrayBuffer> | null {
  if (typeof bytes === 'string') return new TextEncoder().encode(bytes);
  if (bytes instanceof Uint8Array) return new Uint8Array(bytes);
  if (bytes instanceof ArrayBuffer) return new Uint8Array(bytes.slice(0));
  return null;
}

function problem(path: string, attestation: Partial<Attestation> | undefined, sha256: string) {
  if (!attestation || typeof attestation !== 'object') return 'it has no attestation';
  if (attestation.path !== path) return 'its attestation is for another path';
  if (attestation.sha256 !== sha256) return "its bytes don't match the attestation";
  if (attestation.uid !== 0) return "it isn't root-owned";
  if (typeof attestation.mode !== 'number' || attestation.mode & WRITABLE) {
    return 'it is writable by group or others';
  }
  const parents = Array.isArray(attestation.parents) ? attestation.parents : null;
  if (
    !parents?.length ||
    !parents.every((p) => p.uid === 0 && typeof p.mode === 'number' && !(p.mode & WRITABLE))
  ) {
    return "a parent directory isn't root-owned, or is writable by group or others";
  }
  if (attestation.onRootFs !== true) return "it isn't on the root file system";
  if (attestation.users !== 'enforce') return "the kernel doesn't enforce users";
  return null;
}

export async function verify(upload: Partial<Upload>): Promise<Verdict> {
  const path = typeof upload?.path === 'string' ? upload.path : '';
  if (!FILES.includes(path as PolicyFile)) {
    return {
      trusted: false,
      path,
      sha256: null,
      warning: `rules not trusted: ${path || 'a file'} isn't a policy file`,
    };
  }
  const bytes = bytesOf(upload.bytes);
  if (!bytes)
    return {
      trusted: false,
      path,
      sha256: null,
      warning: `rules not trusted: ${path} came without its bytes`,
    };
  const sha256 = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
  const issue = problem(path, upload.attestation, sha256);
  if (issue)
    return { trusted: false, path, sha256, warning: `rules not trusted: ${path}: ${issue}` };
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    return { trusted: true, path: path as PolicyFile, sha256, text };
  } catch {
    return { trusted: false, path, sha256, warning: `rules not trusted: ${path} isn't UTF-8` };
  }
}
