import { hex, random } from './bytes.ts';
import type { PopupIntent } from './contract.ts';
import { all, request, transact } from './db.ts';

export const INTENT_LIFETIME = 10 * 60 * 1000;

export interface Handoff {
  nonce: string;
  ns: string;
  intent: PopupIntent;
  createdAt: number;
}

export function nonce(): string {
  return hex(random(16));
}

export function hand(db: IDBDatabase, handoff: Handoff): Promise<void> {
  return transact(db, ['intents'], 'readwrite', async (tx) => {
    const store = tx.objectStore('intents');
    for (const old of await all<Handoff>(tx, 'intents')) {
      if (handoff.createdAt - old.createdAt > INTENT_LIFETIME)
        await request(store.delete(old.nonce));
    }
    await request(store.put(handoff));
  });
}

export function claim(db: IDBDatabase, key: string, now: number): Promise<Handoff | undefined> {
  return transact(db, ['intents'], 'readonly', async (tx) => {
    const found = (await request(tx.objectStore('intents').get(key))) as Handoff | undefined;
    return found && now - found.createdAt <= INTENT_LIFETIME ? found : undefined;
  });
}

export function drop(db: IDBDatabase, key: string): Promise<void> {
  return transact(db, ['intents'], 'readwrite', async (tx) => {
    await request(tx.objectStore('intents').delete(key));
  });
}
