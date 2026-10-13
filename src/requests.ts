import { hex, random } from './bytes.ts';
import type { PendingRequest, RequestKind, RequestState, Stamp } from './contract.ts';
import { all, request, transact } from './db.ts';
import { Refused } from './errors.ts';

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
  createdAt: number;
  expiresAt: number;
  placeholder?: string;
  jerk?: Record<string, unknown>;
  jop?: string;
  scope?: string;
  params?: Record<string, unknown>;
  answer?: Record<string, unknown>;
}

export function human(entry: Pick<HumanRequest, 'kind' | 'jop'>): boolean {
  if (entry.kind === 'unseal') return false;
  return entry.kind !== 'jerk' || entry.jop === 'create';
}

export type NewRequest = Pick<HumanRequest, 'ns' | 'kind' | 'stamp'> &
  Partial<
    Pick<
      HumanRequest,
      'name' | 'provider' | 'prompt' | 'oauth' | 'jop' | 'scope' | 'params' | 'state' | 'answer'
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
        entry.stamp.uid === fields.stamp.uid && human(entry) && current(entry, now) === 'pending'
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

export function get(db: IDBDatabase, ns: string, id: unknown, uid?: number): Promise<HumanRequest> {
  return transact(db, ['requests'], 'readonly', async (tx) => {
    const entry =
      typeof id === 'string'
        ? ((await request(tx.objectStore('requests').get(id))) as HumanRequest | undefined)
        : undefined;
    if (!entry || entry.ns !== ns || (uid !== undefined && uid !== 0 && entry.stamp.uid !== uid)) {
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
  to: 'done' | 'cancelled',
  placeholder?: string,
  jerk?: Record<string, unknown>
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
      ...(jerk ? { jerk } : {}),
    };
    await request(store.put(settled));
    return settled;
  });
}

export function respond(
  db: IDBDatabase,
  ns: string,
  id: unknown,
  now: number,
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
    const state = current(entry, now);
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
