import { hex, random } from './bytes.ts';
import type { LockMode } from './contract.ts';
import { all, request, transact } from './db.ts';
import { Refused } from './errors.ts';
import { type Dek, decrypt, encrypt, generate, type Kek, type Keys, unwrap, wrap } from './keys.ts';
import { aad, type VaultRecord } from './records.ts';

export type KeyMessage =
  | { type: 'key'; key: CryptoKey }
  | { type: 'lock' }
  | { type: 'key?' }
  | { type: 'keys'; key?: CryptoKey };

export interface Bus {
  post(message: KeyMessage): void;
}

export async function loadKeys(db: IDBDatabase): Promise<Keys> {
  const fresh: Keys = { mode: 'auto', dek: await generate(false), id: hex(random(8)) };
  return transact(db, ['meta'], 'readwrite', async (tx) => {
    const meta = tx.objectStore('meta');
    const stored = (await request(meta.get('keys'))) as Keys | undefined;
    if (stored) return stored;
    await request(meta.put(fresh, 'keys'));
    return fresh;
  });
}

async function reseal(
  records: VaultRecord[],
  from: CryptoKey,
  to: CryptoKey
): Promise<VaultRecord[]> {
  const resealed: VaultRecord[] = [];
  for (const record of records) {
    const label = aad(record.ns, record.kind, record.name);
    const value = await decrypt(from, record.sealed, label);
    resealed.push({ ...record, sealed: await encrypt(to, value, label) });
  }
  return resealed;
}

export const WRONG_KEY = "that key doesn't unlock this vault";

export function unchanged(now: VaultRecord[], then: VaultRecord[]): boolean {
  const stamp = (record: VaultRecord) => `${record.updatedAt}:${record.removedAt ?? ''}`;
  const stamps = new Map(then.map((record) => [record.placeholder, stamp(record)]));
  return now.length === then.length && now.every((r) => stamps.get(r.placeholder) === stamp(r));
}

export class Keyring {
  readonly db: IDBDatabase;
  readonly bus: Bus;
  key: CryptoKey | null = null;
  seen = false;
  id = '';
  mode: LockMode = 'auto';
  kek: Kek | null = null;
  private wrapped: Keys | null = null;
  listeners = new Set<() => void>();

  constructor(db: IDBDatabase, bus: Bus) {
    this.db = db;
    this.bus = bus;
  }

  get locked(): boolean {
    return this.key === null;
  }

  async load(key: CryptoKey | null = null): Promise<void> {
    const keys = await loadKeys(this.db);
    this.wrapped = keys;
    this.mode = keys.mode;
    this.id = keys.id;
    if (keys.mode === 'auto') {
      this.kek = null;
      this.set(keys.dek);
      return;
    }
    this.kek = keys.kek;
    this.key = key;
    if (key === null) this.bus.post({ type: 'key?' });
    this.emit();
  }

  require(): CryptoKey {
    if (!this.key) throw new Refused('EACCES', 'vault is locked: unlock it in the vault window');
    return this.key;
  }

  use(): Dek {
    return { key: this.require(), id: this.id };
  }

  async unlock(kek: CryptoKey): Promise<void> {
    if (!this.wrapped || this.wrapped.mode === 'auto') return;
    let key: CryptoKey;
    try {
      key = await unwrap(this.wrapped.wrapped, kek);
    } catch {
      throw new Refused('EACCES', WRONG_KEY);
    }
    this.set(key);
    this.bus.post({ type: 'key', key });
  }

  lock(): void {
    if (this.mode === 'auto' || this.key === null) return;
    this.key = null;
    this.bus.post({ type: 'lock' });
    this.emit();
  }

  async protect(kek: CryptoKey, info: Kek): Promise<void> {
    const from = this.require();
    const fresh = await generate(true);
    const records = await transact(this.db, ['records'], 'readonly', (tx) =>
      all<VaultRecord>(tx, 'records')
    );
    const resealed = await reseal(records, from, fresh);
    const keys: Keys = {
      mode: info.kind,
      wrapped: await wrap(fresh, kek),
      kek: info,
      id: hex(random(8)),
    };
    const key = await unwrap(keys.wrapped, kek);
    await this.commit(keys, resealed);
    this.set(key);
    this.bus.post({ type: 'keys', key });
  }

  async unprotect(): Promise<void> {
    const dek = this.require();
    await this.commit({ mode: 'auto', dek, id: this.id }, null);
    this.bus.post({ type: 'keys' });
  }

  private async commit(keys: Keys, records: VaultRecord[] | null): Promise<void> {
    await transact(this.db, ['meta', 'records'], 'readwrite', async (tx) => {
      if (records) {
        const now = await all<VaultRecord>(tx, 'records');
        if (!unchanged(now, records)) {
          throw new Refused('EAGAIN', 'the vault changed while it was re-keyed; try again');
        }
        for (const record of records) await request(tx.objectStore('records').put(record));
      }
      await request(tx.objectStore('meta').put(keys, 'keys'));
    });
    this.wrapped = keys;
    this.mode = keys.mode;
    this.id = keys.id;
    this.kek = keys.mode === 'auto' ? null : keys.kek;
  }

  private inbox: Promise<void> = Promise.resolve();

  receive(message: KeyMessage): Promise<void> {
    this.inbox = this.inbox.then(() => this.handle(message));
    return this.inbox;
  }

  private async handle(message: KeyMessage): Promise<void> {
    if (message.type === 'keys') return this.load(message.key ?? null);
    if (message.type === 'lock' && this.mode !== 'auto') {
      this.key = null;
      this.emit();
    }
    if (message.type === 'key' && this.mode !== 'auto') this.set(message.key);
    if (message.type === 'key?' && this.key && this.mode !== 'auto') {
      this.bus.post({ type: 'key', key: this.key });
    }
  }

  private set(key: CryptoKey): void {
    this.key = key;
    this.seen = true;
    this.emit();
  }

  private emit(): void {
    for (const listener of this.listeners) listener();
  }
}
