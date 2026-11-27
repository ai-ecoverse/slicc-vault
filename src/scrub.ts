import type { Scrubber } from '@ai-ecoverse/slicc-scrub';
import { hex, utf8 } from './bytes.ts';
import { type Channel, channel, type Message } from './channel.ts';
import { type Config, loaded } from './config.ts';
import type { ScrubConfig, ScrubReply, ScrubWelcome } from './contract.ts';
import { request, transact } from './db.ts';
import { h, prefersDark, themed } from './dom.ts';
import { type KeyMessage, Keyring } from './lock.ts';
import { records, scrubVersion } from './records.ts';
import { Scrubbers } from './scrubbers.ts';

export const PATH = '/scrub.html';
export const MAX_TEXT = 2048;
export const CHECKS = 3;
export const INTERVAL = 10 * 1000;
export const ARM = 500;
export const HOLD = 10 * 60 * 1000;
export const SLOTS = 8;
export const HOUR = 60 * 60 * 1000;
export const MARKER = '[redacted]';

export const INVALID = 'the request is malformed';
export const TEXT = 'text must be 1 to 2048 bytes of UTF-8 without NUL';
export const UNKNOWN = 'this frame answers only check and recheck';
export const UNSEEN = "this browser can't tell that the button is visible";
export const LOCKED = 'the vault is locked or has no scrubber ready';
export const EMPTY = 'the vault holds no values here, so it checked nothing';
export const BOUND = "this frame's checks are used up or too close together";
export const SPENT = "this hour's checks are used up";
export const CHANGED = "the vault's values changed; check again in a new frame";
export const REPLACED = 'a newer check replaced this one';
export const EXPIRED = 'the check was held too long';
export const UNHELD = 'no checked text is held';
export const REUSED = "this frame's recheck is used up";
export const UNABLE = 'the vault could not handle this request';

type Fields = Record<string, unknown>;
type Id = string | number;
type Code = Extract<ScrubReply, { error: unknown }>['error']['code'];
type Win = Window & {
  IntersectionObserver?: typeof IntersectionObserver;
  IntersectionObserverEntry?: { prototype: object };
};

interface Entry extends IntersectionObserverEntry {
  readonly isVisible?: boolean;
}

interface Tracking extends IntersectionObserverInit {
  trackVisibility: boolean;
  delay: number;
}

interface Held {
  id: Id;
  text: string;
  until: number;
  checked: boolean;
  running: boolean;
  timer: ReturnType<typeof setTimeout>;
}

export interface Parts {
  config: Config;
  db: IDBDatabase | null;
  keyring: Keyring | null;
}

const CHECK_FIELDS = new Set(['v', 'id', 'op', 'text']);
const RECHECK_FIELDS = new Set(['v', 'id', 'op']);
const KEYS = new Set(['key', 'key?', 'lock', 'keys']);
const LANG = /^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*$/;
const NAMED = '\\[redacted:[^\\]\\n]*\\]';
const SPECIAL = /[.*+?^${}()|[\]\\]/g;
const CLASSES =
  'spectrum-Button spectrum-Button--accent spectrum-Button--fill spectrum-Button--sizeM';

export class Denied extends Error {
  readonly code: Code;

  constructor(code: Code, message: string) {
    super(message);
    this.code = code;
  }
}

export function idOf(value: unknown): Id | null {
  if (typeof value === 'string') return value.length > 0 && value.length <= 128 ? value : null;
  return Number.isSafeInteger(value) ? (value as number) : null;
}

export function measured(text: unknown): number {
  if (typeof text !== 'string' || !text.isWellFormed() || text.includes('\u0000')) {
    throw new Denied('EINVAL', TEXT);
  }
  const bytes = utf8(text).length;
  if (bytes < 1 || bytes > MAX_TEXT) throw new Denied('EINVAL', TEXT);
  return bytes;
}

export function look(value: unknown): ScrubConfig {
  const given = (value !== null && typeof value === 'object' ? value : {}) as Fields;
  const out: ScrubConfig = {};
  if (given.theme === 'light' || given.theme === 'dark') out.theme = given.theme;
  if (given.dir === 'ltr' || given.dir === 'rtl') out.dir = given.dir;
  if (typeof given.lang === 'string' && LANG.test(given.lang)) out.lang = given.lang;
  if (given.scale === 'medium' || given.scale === 'large') out.scale = given.scale;
  return out;
}

export function masked(text: string, placeholders: readonly string[]): string {
  const exact = [...new Set(placeholders)]
    .sort((a, b) => b.length - a.length)
    .map((placeholder) => placeholder.replace(SPECIAL, '\\$&'));
  return text.replace(new RegExp([...exact, NAMED].join('|'), 'g'), MARKER);
}

export function residue(text: string, placeholders: readonly string[]): boolean {
  return placeholders.some((placeholder) => text.includes(placeholder.slice(-24)));
}

export function leftover(text: string, values: readonly string[]): boolean {
  return values.some((value) => value.length > 0 && text.includes(value));
}

export function budgetKey(origin: string): string {
  return `scrub-budget:${origin}`;
}

export async function prepay(db: IDBDatabase, origin: string, now: number): Promise<boolean> {
  return transact(db, ['meta'], 'readwrite', async (tx) => {
    const meta = tx.objectStore('meta');
    const key = budgetKey(origin);
    const stored: unknown = (await request(meta.get(key))) ?? [];
    if (!Array.isArray(stored) || !stored.every((at) => Number.isFinite(at))) return false;
    const kept = (stored as number[]).filter((at) => at > now - HOUR);
    if (kept.length + 2 > SLOTS) return false;
    await request(meta.put([...kept, now, now], key));
    return true;
  });
}

export function existing(name = 'slicc-vault'): Promise<IDBDatabase | null> {
  return new Promise((resolve) => {
    const opening = indexedDB.open(name, 1);
    opening.onupgradeneeded = () => opening.transaction?.abort();
    opening.onsuccess = () => {
      const db = opening.result;
      db.onversionchange = () => db.close();
      resolve(db);
    };
    opening.onerror = () => resolve(null);
  });
}

export function hasKeys(db: IDBDatabase): Promise<boolean> {
  return transact(db, ['meta'], 'readonly', async (tx) => {
    return (await request(tx.objectStore('meta').get('keys'))) !== undefined;
  });
}

export function tracks(win: Window): boolean {
  const { IntersectionObserver: Observer, IntersectionObserverEntry: Entry } = win as Win;
  return typeof Observer === 'function' && Entry !== undefined && 'isVisible' in Entry.prototype;
}

export class ScrubFrame {
  readonly win: Win;
  readonly config: Config;
  readonly db: IDBDatabase | null;
  readonly keyring: Keyring | null;
  readonly scrubbers: Scrubbers | null;
  readonly holder: HTMLDivElement;
  port: MessagePort | null = null;
  origin = '';
  ns = '';
  held: Held | null = null;
  checks = 0;
  last = Number.NEGATIVE_INFINITY;
  rechecked = false;
  scrubber: Scrubber | null = null;
  compiled = false;
  armed = false;
  button: HTMLButtonElement | null = null;
  observer: IntersectionObserver | null = null;
  arming: ReturnType<typeof setTimeout> | undefined;
  turn: Promise<void> = Promise.resolve();

  constructor(win: Window, parts: Parts) {
    this.win = win as Win;
    this.config = parts.config;
    this.db = parts.db;
    this.keyring = parts.keyring;
    this.scrubbers =
      parts.db && parts.keyring ? new Scrubbers({ db: parts.db, keyring: parts.keyring }) : null;
    this.holder = h('div', { class: 'holder' });
    win.document.body.append(this.holder);
    win.addEventListener('pagehide', () => this.drop());
  }

  clock(): number {
    return this.win.performance.now();
  }

  accept(event: MessageEvent): boolean {
    const win = this.win;
    const data = event.data as Fields | null;
    const ns = this.config.scrub.get(event.origin);
    const ancestors = win.location.ancestorOrigins;
    if (
      this.port ||
      win.location.pathname !== PATH ||
      win.parent === win ||
      win.parent !== win.top ||
      event.source !== win.parent ||
      !ns ||
      !ancestors ||
      ancestors.length !== 1 ||
      ancestors[0] !== event.origin ||
      data?.type !== 'slicc-vault' ||
      data.v !== 1 ||
      data.op !== 'scrub' ||
      event.ports.length !== 1
    ) {
      return false;
    }
    const [port] = event.ports;
    this.port = port;
    this.origin = event.origin;
    this.ns = ns;
    themed(win.document.body, look(data.config), prefersDark(win).matches);
    port.onmessage = (message) => this.enqueue(() => this.answer(message.data));
    const welcome: ScrubWelcome = {
      v: 1,
      op: 'welcome',
      doc: 'scrub',
      release: this.config.version,
    };
    port.postMessage(welcome);
    return true;
  }

  enqueue(work: () => Promise<void>): void {
    this.turn = this.turn.then(work).catch(() => undefined);
  }

  post(reply: ScrubReply): void {
    this.port?.postMessage(reply);
  }

  fail(id: Id | null, error: unknown): void {
    const { code, message } = error instanceof Denied ? error : new Denied('EINVAL', UNABLE);
    this.post({ id, error: { code, message } });
  }

  async answer(data: unknown): Promise<void> {
    const fields = (data !== null && typeof data === 'object' ? data : {}) as Fields;
    const id = idOf(fields.id);
    try {
      if (id === null || fields.v !== 1) throw new Denied('EINVAL', INVALID);
      if (fields.op === 'check') this.hold(id, fields);
      else if (fields.op === 'recheck') this.post(await this.recheck(id, fields));
      else throw new Denied('ENOTSUP', UNKNOWN);
    } catch (error) {
      this.fail(id, error);
    }
  }

  hold(id: Id, fields: Fields): void {
    if (Object.keys(fields).some((key) => !CHECK_FIELDS.has(key))) {
      throw new Denied('EINVAL', INVALID);
    }
    const bytes = measured(fields.text);
    if (!tracks(this.win)) throw new Denied('EACCES', UNSEEN);
    this.bound();
    this.drop(REPLACED);
    const timer = setTimeout(() => this.drop(EXPIRED), HOLD);
    const text = fields.text as string;
    this.held = { id, text, until: this.clock() + HOLD, checked: false, running: false, timer };
    this.show(bytes);
  }

  bound(): void {
    if (this.checks >= CHECKS || this.clock() - this.last < INTERVAL) {
      throw new Denied('EBUSY', BOUND);
    }
  }

  drop(reason?: string): void {
    const held = this.held;
    if (!held) return;
    this.held = null;
    clearTimeout(held.timer);
    this.hide();
    if (reason && !held.checked)
      this.post({ id: held.id, error: { code: 'EBUSY', message: reason } });
  }

  show(bytes: number): void {
    const label = `Check ${bytes} bytes for stored values`;
    const button = h(
      'button',
      { type: 'button', class: CLASSES, disabled: true, onclick: (event) => this.click(event) },
      h('span', { class: 'spectrum-Button-label' }, label)
    );
    this.holder.replaceChildren(button);
    this.button = button;
    const Observer = this.win.IntersectionObserver as typeof IntersectionObserver;
    const options: Tracking = { threshold: [0, 1], trackVisibility: true, delay: 100 };
    this.observer = new Observer((entries) => this.seen(entries as Entry[]), options);
    this.observer.observe(button);
  }

  seen(entries: readonly Entry[]): void {
    const entry = entries[entries.length - 1];
    const visible =
      entry.isVisible === true && entry.isIntersecting && entry.intersectionRatio >= 1;
    if (!visible) {
      this.disarm();
      return;
    }
    if (this.armed || this.arming !== undefined) return;
    this.arming = setTimeout(() => {
      this.arming = undefined;
      this.armed = true;
      if (this.button) this.button.disabled = false;
    }, ARM);
  }

  disarm(): void {
    clearTimeout(this.arming);
    this.arming = undefined;
    this.armed = false;
    if (this.button) this.button.disabled = true;
  }

  hide(): void {
    this.observer?.disconnect();
    this.observer = null;
    this.disarm();
    this.button = null;
    this.holder.replaceChildren();
  }

  click(event: Event): void {
    const held = this.held;
    if (!event.isTrusted || !this.armed || !held || held.checked || held.running) return;
    held.running = true;
    this.hide();
    this.enqueue(() => this.check(held));
  }

  async check(held: Held): Promise<void> {
    if (this.held !== held) return;
    if (this.clock() >= held.until) {
      this.drop(EXPIRED);
      return;
    }
    try {
      this.bound();
      await this.gate();
      if (!(await this.prepay())) throw new Denied('EBUSY', SPENT);
      this.checks += 1;
      this.last = this.clock();
      const scrubber = await this.compile();
      const text = await this.scrub(scrubber, held.text);
      held.checked = true;
      this.post({ id: held.id, text, scrubVersion: scrubber.version });
    } catch (error) {
      this.drop();
      this.fail(held.id, error);
    }
  }

  async gate(): Promise<void> {
    if (!this.db || (await records(this.db, this.ns)).length === 0) {
      throw new Denied('ENOENT', EMPTY);
    }
    if (this.scrubber) {
      const version = await scrubVersion(this.db, this.ns);
      if (version !== this.scrubber.version) throw new Denied('EBUSY', CHANGED);
      return;
    }
    if (this.compiled) throw new Denied('EINVAL', UNABLE);
    if (!this.keyring || this.keyring.locked) throw new Denied('EACCES', LOCKED);
  }

  prepay(): Promise<boolean> {
    return prepay(this.db as IDBDatabase, this.origin, Date.now()).catch(() => false);
  }

  async compile(): Promise<Scrubber> {
    if (this.scrubber) return this.scrubber;
    this.compiled = true;
    const scrubber = await (this.scrubbers as Scrubbers).get(this.ns).catch(() => {
      throw new Denied('EINVAL', UNABLE);
    });
    if (!scrubber) {
      this.compiled = false;
      throw new Denied('EACCES', LOCKED);
    }
    this.scrubber = scrubber;
    return scrubber;
  }

  async scrub(scrubber: Scrubber, text: string): Promise<string> {
    const secrets = (this.scrubbers as Scrubbers).held.get(scrubber) ?? [];
    const placeholders = secrets.map((secret) => secret.placeholder);
    const values = secrets.map((secret) => secret.value);
    const out = masked(scrubber.text(text).text, placeholders);
    if (placeholders.length === 0 || residue(out, placeholders) || leftover(out, values)) {
      throw new Denied('EINVAL', UNABLE);
    }
    const version = await scrubVersion(this.db as IDBDatabase, this.ns);
    if (version !== scrubber.version) throw new Denied('EBUSY', CHANGED);
    return out;
  }

  async recheck(id: Id, fields: Fields): Promise<ScrubReply> {
    if (Object.keys(fields).some((key) => !RECHECK_FIELDS.has(key))) {
      throw new Denied('EINVAL', INVALID);
    }
    if (this.held && this.clock() >= this.held.until) this.drop(EXPIRED);
    const held = this.held;
    if (!held?.checked) throw new Denied('EINVAL', UNHELD);
    if (this.rechecked) throw new Denied('EBUSY', REUSED);
    this.rechecked = true;
    await this.gate();
    const scrubber = this.scrubber as Scrubber;
    const out = await this.scrub(scrubber, held.text);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', utf8(out)));
    return { id, sha256: hex(digest), scrubVersion: scrubber.version };
  }
}

export async function unlocking(db: IDBDatabase, bus: Channel = channel()): Promise<Keyring> {
  const keyring = new Keyring(db, bus);
  bus.listen((message: Message) => {
    if (KEYS.has(message.type)) void keyring.receive(message as KeyMessage);
  });
  await keyring.load();
  return keyring;
}

export async function bootScrub(
  win: Window = window,
  open: () => Promise<IDBDatabase | null> = existing,
  settings: () => Promise<Config> = loaded
): Promise<ScrubFrame | null> {
  if (win.parent === win) return null;
  const queued: MessageEvent[] = [];
  let frame: ScrubFrame | null = null;
  win.addEventListener('message', (event) => {
    if (frame) frame.accept(event);
    else queued.push(event);
  });
  const [config, db] = await Promise.all([settings(), open()]);
  const keyring = db && (await hasKeys(db)) ? await unlocking(db) : null;
  frame = new ScrubFrame(win, { config, db, keyring });
  for (const event of queued.splice(0)) frame.accept(event);
  return frame;
}
