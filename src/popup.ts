import { random } from './bytes.ts';
import type { PopupIntent, PopupState } from './contract.ts';
import { button, field, h, prefersDark, themed } from './dom.ts';
import { refusal } from './errors.ts';
import { claim, drop, type Handoff } from './intents.ts';
import { fromPassphrase, fromPrf, ITERATIONS, type Kek } from './keys.ts';
import { WRONG_KEY } from './lock.ts';
import { enroll, evaluate } from './passkey.ts';
import { start, type Vault } from './vault.ts';

export const MIN_PASSPHRASE = 12;
const CLAIM_TRIES = 20;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function errorLine(): HTMLParagraphElement {
  return h('p', { class: 'error', role: 'alert' });
}

function show(line: HTMLElement, error: unknown, wrong?: string): void {
  const { message } = refusal(error);
  line.textContent = wrong && message === WRONG_KEY ? wrong : message;
}

export function strength(first: string, second: string): string {
  if (first.length < MIN_PASSPHRASE) {
    return `At least ${MIN_PASSPHRASE} characters: ${MIN_PASSPHRASE - first.length} more.`;
  }
  if (second !== first) return 'Type the same passphrase again.';
  return '';
}

export class Popup {
  readonly vault: Vault;
  readonly win: Window;
  readonly main: HTMLElement;
  handoff: Handoff | null = null;
  finished = false;

  constructor(vault: Vault, win: Window = window) {
    this.vault = vault;
    this.win = win;
    this.main = h('main');
    win.document.body.classList.add('popup');
    const scheme = prefersDark(win);
    themed(win.document.body, {}, scheme.matches);
    scheme.addEventListener('change', () => themed(win.document.body, {}, scheme.matches));
    win.document.body.append(this.main);
    win.addEventListener('pagehide', () => this.post('closed'));
  }

  get ns(): string {
    return this.handoff?.ns ?? '';
  }

  async boot(): Promise<void> {
    const key = this.win.location.hash.slice(1);
    for (let tries = 0; key && !this.handoff && tries < CLAIM_TRIES; tries++) {
      this.handoff = (await claim(this.vault.db, key, this.vault.now())) ?? null;
      if (!this.handoff) await sleep(100);
    }
    this.post('opened');
    if (this.handoff) void this.win.navigator.storage?.persist?.().catch(() => false);
    await this.route();
  }

  post(state: PopupState): void {
    if (!this.handoff || this.finished) return;
    if (state !== 'opened') this.finished = true;
    this.vault.bus.post({ type: 'popup', nonce: this.handoff.nonce, state });
  }

  async finish(state: 'done' | 'cancelled'): Promise<void> {
    this.post(state);
    if (this.handoff) await drop(this.vault.db, this.handoff.nonce);
    this.win.close();
  }

  frame(title: string, ...body: (Node | string | null)[]): void {
    const header = h(
      'header',
      {},
      h('span', { class: 'brand' }, 'SLICC vault'),
      h('span', { class: 'version' }, `v${this.vault.config.version}`)
    );
    const origin = this.handoff
      ? h('p', { class: 'muted' }, 'For ', h('span', { class: 'origin' }, this.ns))
      : null;
    this.main.replaceChildren(
      header,
      h('h1', {}, title),
      origin ?? '',
      ...(body.filter(Boolean) as Node[])
    );
    this.win.document.title = `${title} · SLICC vault`;
  }

  async route(): Promise<void> {
    if (!this.handoff) {
      this.frame(
        'Nothing to do here',
        h('p', {}, 'Open the vault from SLICC: its lock button unlocks it and sets up a passkey.')
      );
      return;
    }
    if (this.vault.keyring.locked) return this.unlockView();
    return this.intentView(this.handoff.intent);
  }

  async intentView(intent: PopupIntent): Promise<void> {
    if (intent.kind === 'unlock') return this.finish('done');
    return this.protectView();
  }

  unlockView(): void {
    const error = errorLine();
    const after = async () => {
      if (this.handoff) await this.intentView(this.handoff.intent);
    };
    const keyring = this.vault.keyring;
    if (keyring.kek?.kind === 'passkey') {
      const kek = keyring.kek;
      this.frame(
        'Unlock the vault',
        h('p', {}, 'The vault is locked with a passkey.'),
        h(
          'div',
          { class: 'actions start' },
          button(
            'Unlock with passkey',
            () => {
              void (async () => {
                try {
                  const output = await evaluate(kek.credential, kek.salt);
                  await keyring.unlock(await fromPrf(output, kek.salt));
                  await after();
                } catch (caught) {
                  show(error, caught, "That passkey doesn't unlock this vault.");
                }
              })();
            },
            'accent'
          )
        ),
        error
      );
      return;
    }
    const pass = field('passphrase', 'Passphrase', {
      type: 'password',
      autocomplete: 'current-password',
    });
    const kek = keyring.kek as Extract<Kek, { kind: 'passphrase' }>;
    const unlock = async () => {
      try {
        await keyring.unlock(await fromPassphrase(pass.input.value, kek.salt, kek.iterations));
        pass.input.value = '';
        await after();
      } catch (caught) {
        show(error, caught, "That passphrase doesn't unlock this vault.");
        pass.input.value = '';
        pass.input.focus();
      }
    };
    pass.input.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') void unlock();
    });
    this.frame(
      'Unlock the vault',
      h('p', {}, 'The vault is locked with a passphrase.'),
      pass.field,
      h(
        'div',
        { class: 'actions' },
        button('Unlock', () => void unlock(), 'accent')
      ),
      error
    );
    pass.input.focus();
  }

  protectView(): void {
    const error = errorLine();
    this.frame(
      'Vault lock',
      this.lockSection(error),
      h(
        'div',
        { class: 'actions' },
        button('Done', () => void this.finish('done'), 'secondary', 'outline')
      ),
      error
    );
  }

  lockSection(error: HTMLElement): HTMLElement {
    const keyring = this.vault.keyring;
    const again = () => this.protectView();
    const run = (work: () => Promise<void>) => async () => {
      try {
        await work();
        await again();
      } catch (caught) {
        show(error, caught);
      }
    };
    if (keyring.mode === 'auto') {
      return h(
        'div',
        {},
        h(
          'p',
          {},
          'The vault unlocks by itself on this device. Protect it to need a passkey or passphrase after every restart.'
        ),
        h(
          'div',
          { class: 'actions start' },
          button(
            'Protect with a passkey',
            () => void run(() => this.protectWithPasskey())(),
            'primary',
            'outline'
          ),
          button('Protect with a passphrase', () => this.passphraseView(), 'secondary', 'outline')
        )
      );
    }
    return h(
      'div',
      {},
      h('p', {}, `Protected with a ${keyring.mode}.`),
      h(
        'div',
        { class: 'actions start' },
        button(
          'Lock now',
          () => {
            keyring.lock();
            void this.route();
          },
          'primary',
          'outline'
        ),
        button('Remove protection', () => this.confirmView(), 'secondary', 'outline')
      )
    );
  }

  async protectWithPasskey(): Promise<void> {
    const enrolled = await enroll();
    const kek = await fromPrf(enrolled.output, enrolled.salt);
    await this.vault.keyring.protect(kek, {
      kind: 'passkey',
      salt: enrolled.salt,
      credential: enrolled.credential,
    });
  }

  confirmView(): void {
    const error = errorLine();
    const remove = async () => {
      try {
        await this.vault.keyring.unprotect();
        this.protectView();
      } catch (caught) {
        show(error, caught);
      }
    };
    this.frame(
      'Remove protection?',
      h('p', {}, 'The vault will unlock by itself on this device.'),
      h(
        'div',
        { class: 'actions' },
        button('Cancel', () => this.protectView(), 'secondary', 'outline'),
        button('Remove protection', () => void remove(), 'negative')
      ),
      error
    );
  }

  passphraseView(): void {
    const error = errorLine();
    const first = field('passphrase', 'New passphrase', {
      type: 'password',
      autocomplete: 'new-password',
    });
    const second = field('confirm', 'Repeat it', {
      type: 'password',
      autocomplete: 'new-password',
    });
    const hint = h('p', { class: 'muted', id: 'strength', 'aria-live': 'polite' });
    const submit = button('Protect', () => void save(), 'accent');
    const check = () => {
      hint.textContent = strength(first.input.value, second.input.value);
      submit.disabled = hint.textContent !== '';
    };
    first.input.setAttribute('aria-describedby', 'strength');
    first.input.addEventListener('input', check);
    second.input.addEventListener('input', check);
    const save = async () => {
      try {
        const salt = random(16);
        const kek = await fromPassphrase(first.input.value, salt);
        await this.vault.keyring.protect(kek, { kind: 'passphrase', salt, iterations: ITERATIONS });
        first.input.value = '';
        second.input.value = '';
        this.protectView();
      } catch (caught) {
        show(error, caught);
      }
    };
    this.frame(
      'Protect with a passphrase',
      h(
        'p',
        {},
        'You’ll need it after every browser restart. A lost passphrase means lost secrets, unless you exported a backup.'
      ),
      first.field,
      second.field,
      hint,
      h(
        'div',
        { class: 'actions' },
        button('Cancel', () => this.protectView(), 'secondary', 'outline'),
        submit
      ),
      error
    );
    check();
    first.input.focus();
  }
}

export async function bootPopup(win: Window = window): Promise<Popup> {
  const popup = new Popup(await start(), win);
  await popup.boot();
  return popup;
}
