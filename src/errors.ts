import type { ErrorCode, VaultError } from './contract.ts';

export class Refused extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message: string) {
    super(message);
    this.code = code;
  }
}

export function refusal(error: unknown): VaultError {
  if (error instanceof Refused) return { code: error.code, message: error.message };
  return { code: 'EINVAL', message: 'the vault could not handle this request' };
}

export const LOCKED = 'vault is locked: unlock it in the vault window';
