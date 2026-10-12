import type { PopupState } from './contract.ts';
import type { KeyMessage } from './lock.ts';

export type Part = 'secrets' | 'audit' | 'exits' | 'requests';

export type Message =
  | KeyMessage
  | { type: 'changed'; ns: string; parts: Part[] }
  | { type: 'popup'; nonce: string; state: PopupState };

export interface Channel {
  post(message: Message): void;
  listen(listener: (message: Message) => void): () => void;
  close(): void;
}

export function channel(name = 'slicc-vault'): Channel {
  const bc = new BroadcastChannel(name);
  const listeners = new Set<(message: Message) => void>();
  bc.onmessage = (event: MessageEvent<Message>) => {
    for (const listener of listeners) listener(event.data);
  };
  return {
    post: (message) => bc.postMessage(message),
    listen(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    close: () => bc.close(),
  };
}
