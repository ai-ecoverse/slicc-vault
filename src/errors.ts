import type { ErrorCause, ErrorCode, VaultError } from './contract.ts';

export class Refused extends Error {
  readonly code: ErrorCode;
  override readonly cause?: ErrorCause;

  constructor(code: ErrorCode, message: string, cause?: ErrorCause) {
    super(message);
    this.code = code;
    this.cause = cause;
  }
}

export const caused = (cause?: ErrorCause) => (cause ? { cause } : {});

export function refusal(error: unknown): VaultError {
  if (error instanceof Refused) {
    return { code: error.code, message: error.message, ...caused(error.cause) };
  }
  return { code: 'EINVAL', message: 'the vault could not handle this request' };
}

export const LOCKED = 'vault is locked: unlock it in the vault window';
