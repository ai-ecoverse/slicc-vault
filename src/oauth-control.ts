import { compile, type Scrubber } from '@ai-ecoverse/slicc-scrub';
import type { ErrorCode, KernelOAuthError, KernelOAuthErrorCause } from './contract.ts';
import { Refused } from './errors.ts';
import type { Keyring } from './lock.ts';
import type { VaultRecord } from './records.ts';

export const OAUTH_BUDGET = 40000;
export const OAUTH_LOCK = 5000;
export const OAUTH_OPS = new Set([
  'capabilities',
  'oauthGrant',
  'oauthStatus',
  'oauthRefresh',
  'oauthRemove',
]);

const MESSAGES: Record<ErrorCode, string> = {
  EINVAL: 'Invalid OAuth request',
  ENOENT: 'OAuth record not found',
  EEXIST: 'OAuth record conflicts with an existing record',
  EACCES: 'OAuth operation refused',
  EAGAIN: 'OAuth record changed; query its status',
  ENOTSUP: 'OAuth operation is unsupported',
  ENOTCONN: 'Vault is unavailable',
  ETIMEDOUT: 'OAuth operation timed out; query its status',
  EIO: 'Invalid OAuth response',
};

const CAUSES = {
  'vault-locked': 'Vault is locked',
  'oauth-reauth-required': 'OAuth sign-in is required',
  'oauth-refresh-failed': 'OAuth refresh failed',
} as const;

export function oauthError(error: unknown): { v: 1; error: KernelOAuthError } {
  const known =
    error instanceof Refused &&
    Object.hasOwn(MESSAGES, error.code) &&
    (!error.cause || Object.hasOwn(CAUSES, error.cause));
  const code = known ? error.code : 'EIO';
  const cause = (known ? error.cause : undefined) as KernelOAuthErrorCause | undefined;
  return {
    v: 1,
    error: {
      code,
      message: cause ? CAUSES[cause as keyof typeof CAUSES] : MESSAGES[code],
      ...(cause ? { cause } : {}),
    },
  };
}

export function oauthValues(values: string[], metadata: string[]): Scrubber {
  const scrubber = compile(
    values.map((value, i) => ({
      name: `T${i}`,
      value,
      placeholder: `fnox_proxy_${'0'.repeat(23)}${i}`,
    })),
    { version: 0 }
  );
  const leaks = metadata.some((text) =>
    scrubber.text(text).hits.some((hit) => hit.form !== 'fragment')
  );
  const overlaps = values.some((text, i) =>
    scrubber.text(text).hits.some((hit) => hit.name !== `T${i}` && hit.form !== 'fragment')
  );
  if (leaks || overlaps) throw new Refused('EINVAL', '');
  return scrubber;
}

export function oauthRequest(req: unknown, op?: string): boolean {
  try {
    const value = typeof req === 'string' ? JSON.parse(req) : req;
    return Boolean(
      value && typeof value === 'object' && (op ? value.op === op : OAUTH_OPS.has(value.op))
    );
  } catch {
    return false;
  }
}

export class OAuthBudget {
  readonly until: number;
  readonly controller = new AbortController();
  admitted?: Promise<VaultRecord[]>;

  constructor(ms = OAUTH_BUDGET) {
    this.until = performance.now() + ms;
  }

  check(): void {
    if (this.controller.signal.aborted || performance.now() >= this.until) {
      throw new Refused('ETIMEDOUT', MESSAGES.ETIMEDOUT);
    }
  }

  async run<T>(work: Promise<T>): Promise<T> {
    let timer: ReturnType<typeof setTimeout>;
    const expired = new Promise<never>((_, reject) => {
      const fail = () => {
        this.controller.abort();
        reject(new Refused('ETIMEDOUT', MESSAGES.ETIMEDOUT));
      };
      const remaining = this.until - performance.now();
      if (remaining <= 0 || this.controller.signal.aborted) fail();
      else timer = setTimeout(fail, remaining);
    });
    try {
      return await Promise.race([expired, work]);
    } finally {
      clearTimeout(timer!);
    }
  }

  async lock<T>(name: string, work: () => Promise<T>, ms = OAUTH_LOCK): Promise<T> {
    this.check();
    const waiting = new AbortController();
    const timer = setTimeout(() => waiting.abort(), Math.min(ms, this.until - performance.now()));
    let acquired = false;
    try {
      return await navigator.locks.request(
        name,
        { signal: AbortSignal.any([this.controller.signal, waiting.signal]) },
        async () => {
          acquired = true;
          clearTimeout(timer);
          this.check();
          return work();
        }
      );
    } catch (error) {
      if (!acquired && (waiting.signal.aborted || this.controller.signal.aborted)) {
        throw new Refused('ETIMEDOUT', MESSAGES.ETIMEDOUT);
      }
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }
}

export function keyGuard(keyring: Keyring, budget: OAuthBudget): () => void {
  if (keyring.locked) throw new Refused('EACCES', CAUSES['vault-locked'], 'vault-locked');
  const key = keyring.require();
  const revision = keyring.revision;
  return () => {
    budget.check();
    if (keyring.locked) throw new Refused('EACCES', CAUSES['vault-locked'], 'vault-locked');
    if (keyring.key !== key || keyring.revision !== revision) {
      throw new Refused('EAGAIN', MESSAGES.EAGAIN);
    }
  };
}
