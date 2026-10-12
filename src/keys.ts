import { random, text, utf8 } from './bytes.ts';

export const ITERATIONS = 600000;
const AES = { name: 'AES-GCM', length: 256 } as const;
const KEK_INFO = utf8('slicc-vault/kek/1');

export interface Sealed {
  iv: Uint8Array<ArrayBuffer>;
  data: ArrayBuffer;
}

export type Kek =
  | { kind: 'passphrase'; salt: Uint8Array<ArrayBuffer>; iterations: number }
  | { kind: 'passkey'; salt: Uint8Array<ArrayBuffer>; credential: string };

export type Keys =
  | { mode: 'auto'; dek: CryptoKey }
  | { mode: Kek['kind']; wrapped: Sealed; kek: Kek };

export function generate(extractable: boolean): Promise<CryptoKey> {
  return crypto.subtle.generateKey(AES, extractable, ['encrypt', 'decrypt']);
}

export async function fromPassphrase(
  passphrase: string,
  salt: Uint8Array<ArrayBuffer>,
  iterations = ITERATIONS
): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey('raw', utf8(passphrase), 'PBKDF2', false, [
    'deriveKey',
  ]);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    base,
    AES,
    false,
    ['wrapKey', 'unwrapKey']
  );
}

export async function fromPrf(
  output: BufferSource,
  salt: Uint8Array<ArrayBuffer>
): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey('raw', output, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: KEK_INFO },
    base,
    AES,
    false,
    ['wrapKey', 'unwrapKey']
  );
}

export async function wrap(dek: CryptoKey, kek: CryptoKey): Promise<Sealed> {
  const iv = random(12);
  return { iv, data: await crypto.subtle.wrapKey('raw', dek, kek, { name: 'AES-GCM', iv }) };
}

export function unwrap(wrapped: Sealed, kek: CryptoKey, extractable = false): Promise<CryptoKey> {
  return crypto.subtle.unwrapKey(
    'raw',
    wrapped.data,
    kek,
    { name: 'AES-GCM', iv: wrapped.iv },
    AES,
    extractable,
    ['encrypt', 'decrypt']
  );
}

export async function encrypt(dek: CryptoKey, value: string, aad: string): Promise<Sealed> {
  const iv = random(12);
  const data = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: utf8(aad) },
    dek,
    utf8(value)
  );
  return { iv, data };
}

export async function decrypt(dek: CryptoKey, sealed: Sealed, aad: string): Promise<string> {
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: sealed.iv, additionalData: utf8(aad) },
    dek,
    sealed.data
  );
  return text(plain);
}
