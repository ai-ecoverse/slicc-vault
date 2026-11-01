import { base64url, bytesOf, hex, random, unbase64url } from './bytes.ts';
import { all, mirror, request, transact } from './db.ts';
import { Refused } from './errors.ts';
import { imported, type Keys } from './keys.ts';
import { reseal } from './lock.ts';
import type { VaultRecord } from './records.ts';

export const LOCK = 'slicc-vault-crest';
export const UNSAVED = 'the vault could not save this on the device; it goes when Crest quits';
const DEK = 'dek:';
const META = 'meta:';
const RECORD = 'records:';
const VIEW = '\u0000view';
const BUFFER = '\u0000buffer';
const SESSION_ONLY = /^(announced|sessions):/;

type Call =
  | { op: 'get'; key: string }
  | { op: 'put'; key: string; value: string }
  | { op: 'delete'; key: string }
  | { op: 'list' };

interface Handler {
  postMessage(call: Call): Promise<unknown>;
}

interface Entry {
  value: string;
  print: string;
}

interface Change {
  name: string;
  print: string;
  value: string | null;
}

export function handler(): Handler | undefined {
  const scope = globalThis as { webkit?: { messageHandlers?: { crestVaultStore?: Handler } } };
  return scope.webkit?.messageHandlers?.crestVaultStore;
}

export function encode(value: unknown): string {
  return JSON.stringify(value, (_, item: unknown) => {
    const view = bytesOf(item);
    if (view) return { [VIEW]: base64url(view) };
    return item instanceof ArrayBuffer ? { [BUFFER]: base64url(new Uint8Array(item)) } : item;
  });
}

export function decode(text: string): unknown {
  return JSON.parse(text, (_, item: unknown) => {
    const held = item as { [VIEW]?: string; [BUFFER]?: string } | null;
    if (typeof held?.[VIEW] === 'string') return unbase64url(held[VIEW]);
    return typeof held?.[BUFFER] === 'string' ? unbase64url(held[BUFFER]).buffer : item;
  });
}

function print(name: string, value: unknown): string {
  return encode(name.startsWith(RECORD) ? { ...(value as object), usedAt: undefined } : value);
}

function entry(name: string, value: unknown): [string, Entry] {
  return [name, { value: encode(value), print: print(name, value) }];
}

function recordName(record: VaultRecord): string {
  return `${RECORD}${JSON.stringify([record.ns, record.kind, record.name])}`;
}

async function entries(db: IDBDatabase): Promise<Map<string, Entry>> {
  const tx = db.transaction(['meta', 'records'], 'readonly');
  const meta = tx.objectStore('meta');
  const [keys, values, records] = await Promise.all([
    request(meta.getAllKeys()),
    request(meta.getAll()),
    all<VaultRecord>(tx, 'records'),
  ]);
  const found = new Map<string, Entry>();
  keys.forEach((key, i) => {
    const kept = key !== 'keys' && !SESSION_ONLY.test(String(key));
    if (kept) found.set(...entry(`${META}${String(key)}`, values[i]));
  });
  for (const record of records) found.set(...entry(recordName(record), record));
  return found;
}

class Store {
  readonly db: IDBDatabase;
  readonly native: Handler;
  known = new Map<string, string>();
  refused = new Map<string, string>();
  queued: Promise<void> | null = null;

  constructor(db: IDBDatabase, native: Handler) {
    this.db = db;
    this.native = native;
  }

  async keys(): Promise<Keys | undefined> {
    const tx = this.db.transaction(['meta'], 'readonly');
    return (await request(tx.objectStore('meta').get('keys'))) as Keys | undefined;
  }

  async mint(local: Keys | undefined): Promise<void> {
    if (local && local.mode !== 'auto') throw new Refused('ENOTSUP', 'the vault is protected');
    const raw = random(32);
    const dek = await imported(raw);
    const id = hex(random(8));
    const held = await transact(this.db, ['records'], 'readonly', (tx) =>
      all<VaultRecord>(tx, 'records')
    );
    const records = local ? await reseal(held, local.dek, dek) : [];
    await this.native.postMessage({ op: 'put', key: `${DEK}${id}`, value: base64url(raw) });
    raw.fill(0);
    await transact(this.db, ['meta', 'records'], 'readwrite', async (tx) => {
      for (const record of records) await request(tx.objectStore('records').put(record));
      await request(tx.objectStore('meta').put({ mode: 'auto', dek, id }, 'keys'));
    });
  }

  async restore(name: string, id: string, saved: Map<string, unknown>): Promise<void> {
    const text = await this.native.postMessage({ op: 'get', key: name });
    if (typeof text !== 'string') throw new Refused('EINVAL', 'no data key');
    const raw = unbase64url(text);
    const dek = await imported(raw);
    raw.fill(0);
    await transact(this.db, ['meta', 'records'], 'readwrite', async (tx) => {
      const meta = tx.objectStore('meta');
      const records = tx.objectStore('records');
      await request(meta.clear());
      await request(records.clear());
      await request(meta.put({ mode: 'auto', dek, id }, 'keys'));
      for (const [key, value] of saved) {
        if (key.startsWith(RECORD)) await request(records.put(value));
        else await request(meta.put(value, key.slice(META.length)));
      }
    });
  }

  async hydrate(): Promise<void> {
    const names = (await this.native.postMessage({ op: 'list' })) as string[];
    const dek = names.find((name) => name.startsWith(DEK));
    const saved = new Map<string, unknown>();
    for (const name of names.filter((item) => item !== dek)) {
      const text = await this.native.postMessage({ op: 'get', key: name });
      saved.set(name, decode(text as string));
    }
    const local = await this.keys();
    const id = dek?.slice(DEK.length);
    if (id === undefined) await this.mint(local);
    else if (local?.id !== id) await this.restore(dek as string, id, saved);
    for (const [name, value] of saved) this.known.set(name, print(name, value));
  }

  async apply(changes: Change[]): Promise<boolean> {
    let failed = false;
    for (const { name, print: stamp, value } of changes) {
      try {
        const call: Call =
          value === null ? { op: 'delete', key: name } : { op: 'put', key: name, value };
        await this.native.postMessage(call);
        if (value === null) this.known.delete(name);
        else this.known.set(name, stamp);
        this.refused.delete(name);
      } catch {
        this.refused.set(name, stamp);
        failed = true;
      }
    }
    return failed;
  }

  async write(): Promise<void> {
    const now = await entries(this.db);
    const changes: Change[] = [];
    for (const [name, { value, print: stamp }] of now) {
      if (this.known.get(name) !== stamp) changes.push({ name, print: stamp, value });
    }
    for (const name of this.known.keys()) {
      if (!now.has(name)) changes.push({ name, print: '', value: null });
    }
    const again = (change: Change) => this.refused.get(change.name) === change.print;
    const fresh = changes.filter((change) => !again(change));
    if (fresh.length === 0) return;
    const failed = await this.apply(fresh);
    await this.apply(changes.filter(again));
    if (failed) throw new Refused('EAGAIN', UNSAVED);
  }

  flush(): Promise<void> {
    this.queued ??= Promise.resolve().then(() =>
      navigator.locks.request(LOCK, () => {
        this.queued = null;
        return this.write();
      })
    );
    return this.queued;
  }
}

export async function adopt(db: IDBDatabase): Promise<IDBDatabase> {
  const native = handler();
  if (!native) return db;
  const store = new Store(db, native);
  try {
    await navigator.locks.request(LOCK, () => store.hydrate());
  } catch {
    return db;
  }
  mirror(db, () => store.flush());
  await store.flush().catch(() => {});
  return db;
}
