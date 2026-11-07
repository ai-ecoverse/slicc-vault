import { hex, random } from './bytes.ts';

export const PREFIX = 'slicc-vault/ask/';

export class Holder {
  readonly id = hex(random(8));
  private taken: Promise<void> | null = null;

  take(): Promise<void> {
    this.taken ??= new Promise((resolve) => {
      void navigator.locks.request(`${PREFIX}${this.id}`, () => {
        resolve();
        return new Promise<void>(() => {});
      });
    });
    return this.taken;
  }
}

export async function alive(holder: string | undefined): Promise<boolean> {
  if (!holder) return false;
  const { held = [] } = await navigator.locks.query();
  return held.some((lock) => lock.name === `${PREFIX}${holder}`);
}
