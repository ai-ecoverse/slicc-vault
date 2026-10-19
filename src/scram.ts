import { utf8 } from './bytes.ts';
import { Refused } from './errors.ts';

export const SCRAM_ITERATIONS = 100000;
export const SCRAM_CANDIDATES = 16;
const MAX = 1024;
const NONCE = '[\\x21-\\x2b\\x2d-\\x7e]+';
const B64 = '(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?';
const FIRST = new RegExp(`^n=[^,]*,r=(${NONCE})$`);
const SERVER = new RegExp(`^r=(${NONCE}),s=(${B64}),i=([1-9][0-9]{0,8})$`);
const FINAL = new RegExp(`^c=biws,r=(${NONCE})$`);
const PROOF = new RegExp(`^${B64}$`);

export interface Scram {
  authMessage: Uint8Array<ArrayBuffer>;
  salt: Uint8Array<ArrayBuffer>;
  iterations: number;
  proof: Uint8Array<ArrayBuffer>;
}

function invalid(message: string): never {
  throw new Refused('EINVAL', `scram: ${message}`);
}

function bytes(b64: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(b64), (char) => char.charCodeAt(0));
}

function field(given: Record<string, unknown>, name: string): string {
  const value = given[name];
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX) {
    invalid(`${name} must be a SCRAM message of at most ${MAX} characters`);
  }
  return value;
}

export function parseScram(value: unknown): Scram {
  const given = (value ?? {}) as Record<string, unknown>;
  const first = field(given, 'clientFirstBare');
  const server = field(given, 'serverFirst');
  const final = field(given, 'clientFinalBare');
  const proof = field(given, 'proof');
  const client = FIRST.exec(first);
  if (!client) invalid('clientFirstBare must be n=…,r=…');
  const offer = SERVER.exec(server);
  if (!offer) invalid('serverFirst must be r=…,s=…,i=…');
  const [, nonce, salt, count] = offer;
  if (!nonce.startsWith(client[1]) || nonce.length === client[1].length) {
    invalid("the server nonce doesn't extend the client nonce");
  }
  const iterations = Number(count);
  if (iterations > SCRAM_ITERATIONS) invalid(`iterations must be at most ${SCRAM_ITERATIONS}`);
  const answer = FINAL.exec(final);
  if (!answer || answer[1] !== nonce) {
    invalid("clientFinalBare must be c=biws,r=<the server's nonce>: no channel binding");
  }
  if (salt.length === 0) invalid('the salt is empty');
  const decoded = PROOF.test(proof) ? bytes(proof) : null;
  if (decoded?.length !== 32) invalid('proof must be base64 of 32 bytes');
  return {
    authMessage: utf8(`${first},${server},${final}`),
    salt: bytes(salt),
    iterations,
    proof: decoded,
  };
}

async function hmac(key: Uint8Array<ArrayBuffer>, data: Uint8Array<ArrayBuffer>) {
  const imported = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', imported, data));
}

export async function clientProof(password: string, scram: Scram): Promise<Uint8Array> {
  const base = await crypto.subtle.importKey('raw', utf8(password), 'PBKDF2', false, [
    'deriveBits',
  ]);
  const salted = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: scram.salt, iterations: scram.iterations },
      base,
      256
    )
  );
  const clientKey = await hmac(salted, utf8('Client Key'));
  const stored = new Uint8Array(await crypto.subtle.digest('SHA-256', clientKey));
  const signature = await hmac(stored, scram.authMessage);
  const proof = clientKey.map((byte, i) => byte ^ signature[i]);
  salted.fill(0);
  clientKey.fill(0);
  return proof;
}

export function same(a: Uint8Array, b: Uint8Array): boolean {
  let diff = a.length ^ b.length;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ (b[i] ?? 0);
  return diff === 0;
}
