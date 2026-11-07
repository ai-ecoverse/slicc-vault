import { withdrawOrphans } from './ask.ts';
import { embedder, POPUP_FEATURES } from './button.ts';
import type { RequestState, ValueConfig, ValueEvent } from './contract.ts';
import { button, field, h, prefersDark, themed } from './dom.ts';
import { Refused, refusal } from './errors.ts';
import { alive } from './holders.ts';
import { hand, nonce } from './intents.ts';
import { checkValue, find, removed, seal } from './records.ts';
import { allow, current, get, type HumanRequest } from './requests.ts';
import { start, type Vault } from './vault.ts';

export const INSET = 2;
export const GUARD = 500;

type Payload = ValueEvent extends infer E
  ? E extends unknown
    ? Omit<E, 'type' | 'v'>
    : never
  : never;

type View = 'enter' | 'reveal' | 'locked' | 'gone' | 'done' | 'missing';

export function problem(value: string): string {
  if (value === '') return '';
  try {
    checkValue(value);
    return '';
  } catch (error) {
    return refusal(error).message;
  }
}

export class ValueFrame {
  readonly vault: Vault;
  readonly ns: string;
  readonly win: Window;
  readonly holder: HTMLDivElement;
  id = '';
  config: ValueConfig = {};
  view: View | null = null;
  entry: HumanRequest | null = null;
  input: HTMLInputElement | null = null;
  action: HTMLButtonElement | null = null;
  why: HTMLParagraphElement | null = null;
  armed = false;
  finished = false;
  told = '';
  guard = GUARD;
  private lastSize = '';
  private generation = 0;
  private timers: ReturnType<typeof setTimeout>[] = [];

  constructor(vault: Vault, ns: string, win: Window = window) {
    this.vault = vault;
    this.ns = ns;
    this.win = win;
    this.holder = h('div', { class: 'holder' });
    win.document.body.append(this.holder);
    win.addEventListener('message', (event) => this.receive(event));
    win.document.addEventListener('keydown', (event) => this.key(event));
    win.addEventListener('pagehide', () => this.zero());
    vault.onChange((space) => {
      if (space === ns) void this.render();
    });
    vault.keyring.listeners.add(() => void this.render());
    prefersDark(win).addEventListener('change', () => this.look());
  }

  emit(payload: Payload): void {
    this.win.parent.postMessage({ type: 'slicc-vault', v: 1, ...payload }, this.ns);
  }

  receive(event: MessageEvent): void {
    const data = event.data as Record<string, unknown> | null;
    if (event.source !== this.win.parent || event.origin !== this.ns) return;
    if (data?.type !== 'slicc-vault' || data.v !== 1) return;
    if (data.op === 'focus') this.focusables()[0]?.focus();
    if (data.op !== 'value' || typeof data.request !== 'string') return;
    const given = data.config;
    this.config = given && typeof given === 'object' ? (given as ValueConfig) : {};
    if (data.request !== this.id) this.reset(data.request);
    this.look();
    void this.render();
  }

  reset(id: string): void {
    this.zero();
    this.id = id;
    this.view = null;
    this.finished = false;
    this.told = '';
    for (const timer of this.timers.splice(0)) clearTimeout(timer);
  }

  look(): void {
    themed(this.win.document.body, this.config, prefersDark(this.win).matches);
  }

  focusables(): HTMLElement[] {
    return [this.input, this.action].filter(
      (element): element is HTMLInputElement | HTMLButtonElement => element !== null
    );
  }

  key(event: KeyboardEvent): void {
    if (event.key === 'Escape' && !event.isComposing) {
      this.emit({ event: 'escape' });
      return;
    }
    if (event.key === 'Enter' && event.target === this.input) {
      event.preventDefault();
      void this.save();
      return;
    }
    if (event.key !== 'Tab') return;
    const list = this.focusables().filter((element) => !(element as HTMLButtonElement).disabled);
    const edge = event.shiftKey ? list[0] : list[list.length - 1];
    if (list.length > 0 && event.target !== edge) return;
    event.preventDefault();
    this.emit({ event: 'focus', direction: event.shiftKey ? 'previous' : 'next' });
  }

  async read(): Promise<HumanRequest | null> {
    try {
      const entry = await get(this.vault.db, this.ns, this.id);
      return entry.kind === 'ask' ? entry : null;
    } catch {
      return null;
    }
  }

  async render(): Promise<void> {
    if (!this.id) return;
    const generation = ++this.generation;
    const id = this.id;
    const entry = await this.read();
    if (generation !== this.generation) return;
    const state = entry ? current(entry, this.vault.now()) : null;
    let view: View;
    if (this.finished) view = 'done';
    else if (!entry || !state) view = 'missing';
    else if (state !== 'pending') view = 'gone';
    else if (this.vault.keyring.locked) view = 'locked';
    else view = entry.mode === 'reveal' ? 'reveal' : 'enter';
    this.entry = entry;
    if (view === 'missing' && this.told !== id) {
      this.told = id;
      this.emit({ event: 'error', code: 'ENOENT', message: 'no such request' });
    }
    if (view === 'gone' && this.told !== id) {
      this.told = id;
      this.emit({ event: 'gone', request: id, state: state as RequestState });
    }
    if (
      entry &&
      view !== this.view &&
      (view === 'enter' || view === 'reveal' || view === 'locked')
    ) {
      const wait = Math.max(entry.expiresAt - this.vault.now(), 0) + 10;
      this.timers.push(setTimeout(() => void this.render(), wait));
    }
    if (view !== this.view) this.show(view, entry);
    this.measure();
  }

  show(view: View, entry: HumanRequest | null): void {
    this.zero();
    this.view = view;
    this.input = null;
    this.action = null;
    this.why = null;
    this.armed = false;
    const name = entry?.name ?? '';
    if (view === 'enter') {
      const title = entry?.replace ? `Replace the value of ${name}` : `Value for ${name}`;
      const made = field('value', title, {
        type: 'password',
        autocomplete: 'off',
        autocapitalize: 'off',
        spellcheck: 'false',
      });
      this.input = made.input;
      this.input.addEventListener('input', () => this.update());
      this.why = h('p', { class: 'error', role: 'alert' });
      this.action = button('Save', () => void this.save(), 'accent');
      this.holder.replaceChildren(
        made.field,
        this.why,
        h('div', { class: 'actions' }, this.action)
      );
    } else if (view === 'reveal') {
      const exe = entry?.requester?.exe ?? '';
      this.action = button('Allow', () => void this.allow(), 'negative');
      this.holder.replaceChildren(
        h('p', {}, `${exe} gets the plaintext of ${name}`),
        h('div', { class: 'actions' }, this.action)
      );
    } else if (view === 'locked') {
      this.action = button('Unlock', () => void this.unlock(), 'accent');
      this.holder.replaceChildren(
        h('p', {}, 'Unlock the vault to continue.'),
        h('div', { class: 'actions' }, this.action)
      );
    } else {
      this.holder.replaceChildren();
    }
    if (view === 'enter' || view === 'reveal') {
      this.timers.push(
        setTimeout(() => {
          this.armed = true;
          this.update();
        }, this.guard)
      );
    }
    this.update();
  }

  update(): void {
    if (!this.action) return;
    if (this.view === 'locked') return;
    const why = this.input ? problem(this.input.value) : '';
    if (this.why) this.why.textContent = why;
    const empty = this.input !== null && this.input.value === '';
    this.action.disabled = !this.armed || why !== '' || empty;
  }

  zero(): void {
    if (this.input) this.input.value = '';
  }

  fail(error: unknown): void {
    const { code, message } = refusal(error);
    if (this.why) this.why.textContent = message;
    this.emit({ event: 'error', code, message });
  }

  async save(): Promise<void> {
    const input = this.input;
    const entry = this.entry as HumanRequest;
    if (!input || !this.action || this.action.disabled) return;
    this.action.disabled = true;
    if (await this.orphaned(entry)) return;
    try {
      const value = checkValue(input.value);
      await seal(this.vault.db, this.vault.keyring.use(), {
        ns: this.ns,
        kind: 'secret',
        name: entry.name as string,
        value,
        source: 'settings',
        uid: null,
        tag: null,
        now: this.vault.now(),
        answers: { id: entry.id, clock: () => this.vault.now() },
      });
    } catch (error) {
      this.fail(error);
      this.update();
      return;
    }
    this.zero();
    await this.finish('sealed', ['secrets', 'audit', 'requests']);
  }

  async allow(): Promise<void> {
    const entry = this.entry as HumanRequest;
    if (!this.action || this.action.disabled) return;
    this.action.disabled = true;
    if (await this.orphaned(entry)) return;
    try {
      this.vault.keyring.use();
      const record = await find(this.vault.db, this.ns, 'secret', entry.name as string);
      if (!record || removed(record)) throw new Refused('ENOENT', `${entry.name} was removed`);
      await allow(this.vault.db, this.ns, entry.id, this.vault.now(), record.placeholder);
    } catch (error) {
      this.fail(error);
      return;
    }
    await this.finish('allowed', ['requests']);
  }

  async orphaned(entry: HumanRequest): Promise<boolean> {
    if (await alive(entry.holder)) return false;
    await withdrawOrphans(this.vault.context(this.ns));
    await this.render();
    return true;
  }

  async finish(state: 'sealed' | 'allowed', parts: ('secrets' | 'audit' | 'requests')[]) {
    this.finished = true;
    this.emit({ event: 'done', request: this.id, state });
    await this.vault.changed(this.ns, parts);
    await this.render();
  }

  async unlock(): Promise<void> {
    const key = nonce();
    const intent = { kind: 'unlock' as const };
    await hand(this.vault.db, { nonce: key, ns: this.ns, intent, createdAt: this.vault.now() });
    const popup = this.win.open(`/popup.html#${key}`, `slicc-vault-${key}`, POPUP_FEATURES);
    if (!popup) this.fail(new Refused('EACCES', 'the browser blocked the vault window'));
  }

  measure(): void {
    const box = this.holder.getBoundingClientRect();
    const size = `${Math.ceil(box.width)}x${Math.ceil(box.height)}`;
    if (size === this.lastSize) return;
    this.lastSize = size;
    this.emit({
      event: 'size',
      width: Math.ceil(box.width),
      height: Math.ceil(box.height),
      inset: INSET,
    });
  }
}

export async function bootValue(win: Window = window): Promise<ValueFrame | null> {
  if (win.parent === win) return null;
  const queued: MessageEvent[] = [];
  let wake = () => {};
  const early = (event: MessageEvent) => {
    queued.push(event);
    wake();
  };
  win.addEventListener('message', early);
  const vault = await start();
  let ns = embedder(win, vault);
  const hinted = win.location.ancestorOrigins?.[0];
  if (!ns && hinted && hinted !== 'null') return null;
  const announced = !ns;
  if (announced) win.parent.postMessage({ type: 'slicc-vault', v: 1, event: 'ready' }, '*');
  for (let next = 0; !ns; ) {
    while (!ns && next < queued.length) ns = embedder(win, vault, queued[next++]);
    if (!ns) await new Promise<void>((resolve) => (wake = resolve));
  }
  win.removeEventListener('message', early);
  const frame = new ValueFrame(vault, ns, win);
  frame.look();
  for (const event of queued) frame.receive(event);
  if (typeof ResizeObserver === 'function') {
    new ResizeObserver(() => frame.measure()).observe(frame.holder);
  }
  if (!announced) frame.emit({ event: 'ready' });
  return frame;
}
