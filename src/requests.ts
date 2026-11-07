import { hex, random } from './bytes.ts';
import type {
  AskMode,
  PendingRequest,
  Requester,
  RequestKind,
  RequestState,
  Stamp,
} from './contract.ts';
import { all, request, transact } from './db.ts';
import { Refused } from './errors.ts';
import type { Binding } from './records.ts';

export const LIFETIME = 300 * 1000;

export interface HumanRequest {
  id: string;
  ns: string;
  kind: RequestKind;
  name?: string;
  provider?: string;
  prompt?: string;
  oauth?: Record<string, unknown>;
  stamp: Stamp;
  state: RequestState;
  record?: 'secret' | 'model' | 'mcp';
  binding?: Binding;
  createdAt: number;
  expiresAt: number;
  placeholder?: string;
  jerk?: Record<string, unknown>;
  jop?: string;
  scope?: string;
  params?: Record<string, unknown>;
  answer?: Record<string, unknown>;
  mode?: AskMode;
  reveal?: boolean;
  replace?: boolean;
  requester?: Requester;
  allowed?: boolean;
  sealedAt?: number;
  holder?: string;
}

export function human(entry: Pick<HumanRequest, 'kind' | 'jop'>): boolean {
  if (entry.kind === 'unseal' || entry.kind === 'enter') return false;
  return entry.kind !== 'jerk' || entry.jop === 'create';
}

export type NewRequest = Pick<HumanRequest, 'ns' | 'kind' | 'stamp'> &
  Partial<
    Pick<
      HumanRequest,
      | 'name'
      | 'provider'
      | 'prompt'
      | 'oauth'
      | 'jop'
      | 'scope'
      | 'params'
      | 'state'
      | 'answer'
      | 'mode'
      | 'reveal'
      | 'replace'
      | 'requester'
      | 'holder'
    >
  >;

export function current(entry: HumanRequest, now: number): RequestState {
  return entry.state === 'pending' && now >= entry.expiresAt ? 'expired' : entry.state;
}

export function pending(entry: HumanRequest): PendingRequest {
  return {
    id: entry.id,
    kind: entry.kind,
    ...(entry.name === undefined ? {} : { name: entry.name }),
    ...(entry.provider === undefined ? {} : { provider: entry.provider }),
    ...(entry.prompt === undefined ? {} : { prompt: entry.prompt }),
    ...(entry.kind === 'ask'
      ? {
          mode: entry.mode,
          reveal: entry.reveal === true,
          replace: entry.replace === true,
          requester: entry.requester,
        }
      : {}),
    uid: entry.stamp.uid,
    tag: entry.stamp.tag,
    createdAt: entry.createdAt,
    expiresAt: entry.expiresAt,
  };
}

export function create(db: IDBDatabase, fields: NewRequest, now: number): Promise<HumanRequest> {
  return transact(db, ['requests'], 'readwrite', async (tx) => {
    const open = (await all<HumanRequest>(tx, 'requests', fields.ns)).filter(
      (entry) =>
        human(entry) && entry.stamp.uid === fields.stamp.uid && current(entry, now) === 'pending'
    );
    if (human(fields) && fields.state !== 'done' && open.length > 0) {
      throw new Refused(
        'EAGAIN',
        `uid ${fields.stamp.uid} already has a request waiting for a human`
      );
    }
    const entry: HumanRequest = {
      ...fields,
      id: `req_${hex(random(12))}`,
      state: fields.state ?? 'pending',
      createdAt: now,
      expiresAt: now + LIFETIME,
    };
    await request(tx.objectStore('requests').put(entry));
    return entry;
  });
}

export interface Entering {
  ns: string;
  name: string;
  record: 'secret' | 'model' | 'mcp';
  binding: Binding;
  replace: boolean;
}

export const PAGE: Stamp = { pid: 0, ppid: 0, uid: -1, gid: -1, tag: null };

export function opening(db: IDBDatabase, fields: Entering, now: number): Promise<HumanRequest> {
  return transact(db, ['requests'], 'readwrite', async (tx) => {
    const entry: HumanRequest = {
      ns: fields.ns,
      kind: 'enter',
      stamp: PAGE,
      name: fields.name,
      record: fields.record,
      binding: fields.binding,
      replace: fields.replace,
      id: `req_${hex(random(12))}`,
      state: 'pending',
      createdAt: now,
      expiresAt: now + LIFETIME,
    };
    await request(tx.objectStore('requests').put(entry));
    return entry;
  });
}

export function get(db: IDBDatabase, ns: string, id: unknown, uid?: number): Promise<HumanRequest> {
  return transact(db, ['requests'], 'readonly', async (tx) => {
    const entry =
      typeof id === 'string'
        ? ((await request(tx.objectStore('requests').get(id))) as HumanRequest | undefined)
        : undefined;
    const foreign =
      uid !== undefined && (entry?.kind === 'enter' || (uid !== 0 && entry?.stamp.uid !== uid));
    if (!entry || entry.ns !== ns || foreign) {
      throw new Refused('ENOENT', 'no such request');
    }
    return entry;
  });
}

export function settle(
  db: IDBDatabase,
  ns: string,
  id: string,
  now: number,
  to: 'done' | 'cancelled' | 'withdrawn',
  placeholder?: string
): Promise<HumanRequest> {
  return transact(db, ['requests'], 'readwrite', async (tx) => {
    const store = tx.objectStore('requests');
    const entry = (await request(store.get(id))) as HumanRequest | undefined;
    if (!entry || entry.ns !== ns) throw new Refused('ENOENT', 'no such request');
    const state = current(entry, now);
    if (state !== 'pending') return { ...entry, state };
    const settled: HumanRequest = {
      ...entry,
      state: to,
      ...(placeholder ? { placeholder } : {}),
    };
    await request(store.put(settled));
    return settled;
  });
}

export function respond(
  db: IDBDatabase,
  ns: string,
  id: unknown,
  clock: () => number,
  answer: Record<string, unknown>,
  done: boolean
): Promise<HumanRequest> {
  return transact(db, ['requests'], 'readwrite', async (tx) => {
    const store = tx.objectStore('requests');
    const entry =
      typeof id === 'string'
        ? ((await request(store.get(id))) as HumanRequest | undefined)
        : undefined;
    if (!entry || entry.ns !== ns) throw new Refused('ENOENT', 'no such request');
    if (entry.kind === 'value') throw new Refused('EINVAL', 'a value request is answered with put');
    if (entry.kind === 'ask' || entry.kind === 'enter') {
      throw new Refused('EINVAL', "this request is answered in the vault's frame");
    }
    const state = current(entry, clock());
    if (state !== 'pending') throw new Refused('EINVAL', `request ${entry.id} is ${state}`);
    const next: HumanRequest = {
      ...entry,
      answer: { ...entry.answer, ...answer },
      ...(done ? { state: 'done' } : {}),
    };
    await request(store.put(next));
    return next;
  });
}

export function allow(
  db: IDBDatabase,
  ns: string,
  id: string,
  now: number,
  placeholder: string
): Promise<HumanRequest> {
  return transact(db, ['requests'], 'readwrite', async (tx) => {
    const store = tx.objectStore('requests');
    const entry = (await request(store.get(id))) as HumanRequest | undefined;
    if (!entry || entry.ns !== ns || entry.kind !== 'ask' || entry.mode !== 'reveal') {
      throw new Refused('ENOENT', 'no such request');
    }
    const state = current(entry, now);
    if (state !== 'pending') throw new Refused('EINVAL', `request ${entry.id} is ${state}`);
    const next: HumanRequest = { ...entry, state: 'done', allowed: true, placeholder };
    await request(store.put(next));
    return next;
  });
}

export async function waiting(db: IDBDatabase, ns: string, now: number): Promise<HumanRequest[]> {
  const entries = await transact(db, ['requests'], 'readonly', (tx) =>
    all<HumanRequest>(tx, 'requests', ns)
  );
  return entries
    .filter((entry) => human(entry) && current(entry, now) === 'pending')
    .sort((a, b) => a.createdAt - b.createdAt);
}

export function sweep(db: IDBDatabase, now: number): Promise<number> {
  return transact(db, ['requests'], 'readwrite', async (tx) => {
    const store = tx.objectStore('requests');
    const stale = (await all<HumanRequest>(tx, 'requests')).filter(
      (entry) => now - entry.expiresAt > LIFETIME
    );
    for (const entry of stale) await request(store.delete(entry.id));
    return stale.length;
  });
}
