import { argon2d, argon2id } from 'hash-wasm';
import kdbxweb from 'kdbxweb';

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

export async function kdbx(password, entries, kdf = 'Argon2id') {
  const db = kdbxweb.Kdbx.create(
    new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(password)),
    'test'
  );
  db.header.setKdf(kdbxweb.Consts.KdfId[kdf]);
  db.header.kdfParameters.set(
    'M',
    kdbxweb.VarDictionary.ValueType.UInt64,
    kdbxweb.Int64.from(1024 * 1024)
  );
  db.header.kdfParameters.set('I', kdbxweb.VarDictionary.ValueType.UInt64, kdbxweb.Int64.from(2));
  const group = db.createGroup(db.getDefaultGroup(), 'nested');
  entries.forEach(([title, value], i) => {
    const entry = db.createEntry(i % 2 ? group : db.getDefaultGroup());
    if (title === null) entry.fields.delete('Title');
    else entry.fields.set('Title', title);
    if (value === null) entry.fields.delete('Password');
    else if (typeof value === 'object') entry.fields.set('Password', value.plain);
    else entry.fields.set('Password', kdbxweb.ProtectedValue.fromString(value));
  });
  return Buffer.from(await db.save()).toString('base64');
}
