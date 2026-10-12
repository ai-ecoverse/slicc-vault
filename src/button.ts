import { embedded } from './config.ts';
import type { ButtonConfig, ButtonEvent, PopupIntent, VaultStatus } from './contract.ts';
import { h, prefersDark, themed } from './dom.ts';
import { hand, nonce } from './intents.ts';
import { start, type Vault } from './vault.ts';

export const POPUP_FEATURES = 'popup,width=460,height=680';
export const INSET = 2;
export const OPEN_GRACE = 3000;

type Payload = ButtonEvent extends infer E
  ? E extends unknown
    ? Omit<E, 'type' | 'v'>
    : never
  : never;

export function summary(status: VaultStatus): { label: string; intent: PopupIntent | null } {
  if (status.locked) return { label: 'Unlock vault', intent: { kind: 'unlock' } };
  return { label: '', intent: null };
}

export function labelFor(intent: PopupIntent): string {
  return intent.kind === 'unlock' ? 'Unlock vault' : 'Vault lock';
}

export function classes(config: ButtonConfig): string {
  const sizes = { s: 'sizeS', m: 'sizeM', l: 'sizeL' };
  return [
    'spectrum-Button',
    `spectrum-Button--${config.variant ?? 'secondary'}`,
    `spectrum-Button--${config.treatment ?? 'fill'}`,
    `spectrum-Button--${sizes[config.size ?? 'm']}`,
    config.quiet ? 'spectrum-Button--quiet' : '',
  ]
    .filter(Boolean)
    .join(' ');
}

export class VaultButton {
  readonly vault: Vault;
  readonly ns: string;
  readonly win: Window;
  config: ButtonConfig = { intent: 'auto' };
  intent: PopupIntent | null = null;
  label = '';
  readonly holder: HTMLDivElement;
  readonly element: HTMLButtonElement;
  readonly text: HTMLSpanElement;
  private lastSize = '';
  private generation = 0;

  constructor(vault: Vault, ns: string, win: Window = window) {
    this.vault = vault;
    this.ns = ns;
    this.win = win;
    this.text = h('span', { class: 'spectrum-Button-label' });
    this.element = h('button', { type: 'button' }, this.text);
    this.holder = h('div', { class: 'holder' }, this.element);
    this.element.addEventListener('click', () => void this.open());
    this.element.addEventListener('keydown', (event) => this.key(event));
    win.document.body.append(this.holder);
    win.addEventListener('message', (event) => this.receive(event));
    vault.onChange((space) => {
      if (space === ns) void this.render();
    });
    vault.keyring.listeners.add(() => void this.render());
    vault.bus.listen((message) => {
      if (message.type === 'popup' && this.pending.has(message.nonce)) {
        const intent = this.pending.get(message.nonce) as PopupIntent;
        if (message.state === 'opened') this.opened.add(message.nonce);
        else this.pending.delete(message.nonce);
        this.emit({ event: 'popup', intent, state: message.state });
      }
    });
    prefersDark(win).addEventListener('change', () => void this.render());
  }

  readonly pending = new Map<string, PopupIntent>();
  readonly opened = new Set<string>();
  grace = OPEN_GRACE;

  emit(payload: Payload): void {
    this.win.parent.postMessage({ type: 'slicc-vault', v: 1, ...payload }, this.ns);
  }

  receive(event: MessageEvent): void {
    const data = event.data as Record<string, unknown> | null;
    if (event.source !== this.win.parent || event.origin !== this.ns) return;
    if (data?.type !== 'slicc-vault' || data.v !== 1) return;
    if (data.op === 'focus') this.element.focus();
    if (data.op === 'button' && data.button && typeof data.button === 'object') {
      const given = data.button as Partial<ButtonConfig>;
      this.config = { ...given, intent: given.intent ?? 'auto' };
      void this.render();
    }
  }

  key(event: KeyboardEvent): void {
    if (event.key !== 'Tab') return;
    event.preventDefault();
    this.emit({ event: 'focus', direction: event.shiftKey ? 'previous' : 'next' });
  }

  async render(): Promise<void> {
    const config = this.config;
    const generation = ++this.generation;
    themed(this.win.document.body, config, prefersDark(this.win).matches);
    let label: string;
    let intent: PopupIntent | null;
    if (config.intent === 'auto') {
      ({ label, intent } = summary(await this.vault.status(this.ns)));
      if (generation !== this.generation) return;
    } else {
      intent = config.intent;
      label = labelFor(intent);
    }
    label = config.label ?? label;
    this.intent = intent;
    this.element.className = classes(config);
    this.element.disabled = config.disabled === true || intent === null;
    this.text.textContent = label;
    this.holder.hidden = intent === null;
    if (label !== this.label) {
      this.label = label;
      this.emit({ event: 'label', label });
    }
    this.measure();
  }

  measure(): void {
    const box = this.holder.hidden ? { width: 0, height: 0 } : this.holder.getBoundingClientRect();
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

  async open(): Promise<void> {
    const intent = this.intent;
    if (!intent || this.element.disabled) return;
    const key = nonce();
    await hand(this.vault.db, { nonce: key, ns: this.ns, intent, createdAt: this.vault.now() });
    this.pending.set(key, intent);
    const popup = this.win.open(`/popup.html#${key}`, `slicc-vault-${key}`, POPUP_FEATURES);
    if (popup) return;
    await new Promise((resolve) => setTimeout(resolve, this.grace));
    if (!this.pending.has(key) || this.opened.has(key)) return;
    this.pending.delete(key);
    this.emit({ event: 'popup', intent, state: 'blocked' });
  }
}

export function embedder(win: Window, vault: Vault, event?: MessageEvent): string | null {
  const hinted = win.location.ancestorOrigins?.[0];
  if (hinted && hinted !== 'null') return embedded(vault.config, hinted) ? hinted : null;
  if (event?.source !== win.parent || !embedded(vault.config, event.origin)) return null;
  return event.origin;
}

export async function bootButton(win: Window = window): Promise<VaultButton | null> {
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
  const button = new VaultButton(vault, ns, win);
  for (const event of queued) button.receive(event);
  await button.render();
  if (typeof ResizeObserver === 'function') {
    new ResizeObserver(() => button.measure()).observe(button.holder);
  }
  if (!announced) button.emit({ event: 'ready' });
  return button;
}
