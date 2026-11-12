export const STORES = ['meta', 'records', 'requests', 'audit', 'intents'] as const;
export type Store = (typeof STORES)[number];

const MIRRORED: Store[] = ['meta', 'records'];
const flushes = new WeakMap<IDBDatabase, () => Promise<void>>();

export function mirror(db: IDBDatabase, flush: () => Promise<void>): void {
  flushes.set(db, flush);
}

export function mirrored(db: IDBDatabase): boolean {
  return flushes.has(db);
}

export function request<T>(pending: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    pending.onsuccess = () => resolve(pending.result);
    pending.onerror = () => reject(pending.error);
  });
}

function upgrade(db: IDBDatabase): void {
  db.createObjectStore('meta');
  const records = db.createObjectStore('records', { keyPath: ['ns', 'kind', 'name'] });
  records.createIndex('placeholder', 'placeholder', { unique: true });
  records.createIndex('ns', 'ns');
  const requests = db.createObjectStore('requests', { keyPath: 'id' });
  requests.createIndex('ns', 'ns');
  const audit = db.createObjectStore('audit', { keyPath: 'seq', autoIncrement: true });
  audit.createIndex('ns', 'ns');
  db.createObjectStore('intents', { keyPath: 'nonce' });
}

export function open(name = 'slicc-vault'): Promise<IDBDatabase> {
  const opening = indexedDB.open(name, 1);
  opening.onupgradeneeded = () => upgrade(opening.result);
  return request(opening);
}

export function transact<T>(
  db: IDBDatabase,
  stores: Store[],
  mode: IDBTransactionMode,
  body: (tx: IDBTransaction) => Promise<T>
): Promise<T> {
  const tx = db.transaction(stores, mode);
  const done = new Promise<void>((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error ?? new Error('transaction aborted'));
  });
  const result = body(tx).catch((error: unknown) => {
    try {
      tx.abort();
    } catch {}
    throw error;
  });
  const settled = Promise.all([result, done]).then(([value]) => value);
  const flush = mode === 'readwrite' && stores.some((store) => MIRRORED.includes(store));
  const saving = flush ? flushes.get(db) : undefined;
  if (!saving) return settled;
  return settled.then(async (value) => {
    await saving();
    return value;
  });
}

export function all<T>(tx: IDBTransaction, store: Store, ns?: string): Promise<T[]> {
  const target = tx.objectStore(store);
  return request(ns === undefined ? target.getAll() : target.index('ns').getAll(ns)) as Promise<
    T[]
  >;
}
