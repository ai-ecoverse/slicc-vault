import { base64url, random, unbase64url } from './bytes.ts';
import { Refused } from './errors.ts';

export interface Enrolled {
  credential: string;
  salt: Uint8Array<ArrayBuffer>;
  output: ArrayBuffer;
}

interface PrfOutputs {
  enabled?: boolean;
  results?: { first?: BufferSource };
}

function prf(credential: Credential | null): PrfOutputs | undefined {
  const outputs = (credential as PublicKeyCredential | null)?.getClientExtensionResults?.() as
    | { prf?: PrfOutputs }
    | undefined;
  return outputs?.prf;
}

function bytes(source: BufferSource): ArrayBuffer {
  const view = ArrayBuffer.isView(source)
    ? new Uint8Array(source.buffer, source.byteOffset, source.byteLength)
    : new Uint8Array(source);
  return view.slice().buffer;
}

export async function evaluate(
  credential: string,
  salt: Uint8Array<ArrayBuffer>,
  container: CredentialsContainer = navigator.credentials,
  rpId = location.hostname
): Promise<ArrayBuffer> {
  const assertion = await container.get({
    publicKey: {
      challenge: random(32),
      rpId,
      allowCredentials: [{ type: 'public-key', id: unbase64url(credential) }],
      userVerification: 'required',
      extensions: { prf: { eval: { first: salt } } } as AuthenticationExtensionsClientInputs,
    },
  });
  const first = prf(assertion)?.results?.first;
  if (!first) throw new Refused('ENOTSUP', 'this passkey gave no PRF output');
  return bytes(first);
}

export async function enroll(
  container: CredentialsContainer = navigator.credentials,
  rpId = location.hostname
): Promise<Enrolled> {
  const salt = random(32);
  const created = (await container.create({
    publicKey: {
      challenge: random(32),
      rp: { id: rpId, name: 'SLICC vault' },
      user: { id: random(16), name: 'SLICC vault', displayName: 'SLICC vault' },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 },
      ],
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
      extensions: { prf: { eval: { first: salt } } } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null;
  const outputs = prf(created);
  if (!created || (!outputs?.enabled && !outputs?.results?.first)) {
    throw new Refused('ENOTSUP', 'this passkey has no PRF support; use a passphrase instead');
  }
  const credential = base64url(new Uint8Array(created.rawId));
  const first = outputs.results?.first;
  const output = first ? bytes(first) : await evaluate(credential, salt, container, rpId);
  return { credential, salt, output };
}
