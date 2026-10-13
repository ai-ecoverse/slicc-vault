import { argon2d, argon2id } from 'hash-wasm';
import * as kdbxweb from 'kdbxweb';

export interface Entry {
  title: string;
  value: string;
}

kdbxweb.CryptoEngine.setArgon2Impl(
  async (password, salt, memory, iterations, length, parallelism, type) => {
    const hash = type === kdbxweb.CryptoEngine.Argon2TypeArgon2id ? argon2id : argon2d;
    const out = await hash({
      password: new Uint8Array(password),
      salt: new Uint8Array(salt),
      memorySize: memory,
      iterations,
      hashLength: length,
      parallelism,
      outputType: 'binary',
    });
    return out.slice().buffer;
  }
);

function field(value: string | kdbxweb.ProtectedValue | undefined): string {
  return value instanceof kdbxweb.ProtectedValue ? value.getText() : (value ?? '');
}

function walk(group: kdbxweb.KdbxGroup, out: Entry[]): void {
  for (const entry of group.entries) {
    out.push({
      title: field(entry.fields.get('Title')),
      value: field(entry.fields.get('Password')),
    });
  }
  for (const child of group.groups) walk(child, out);
}

export async function entries(bytes: Uint8Array, password: string): Promise<Entry[]> {
  const credentials = new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(password));
  const db = await kdbxweb.Kdbx.load(new Uint8Array(bytes).buffer, credentials);
  const out: Entry[] = [];
  walk(db.getDefaultGroup(), out);
  return out;
}
