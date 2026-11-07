import type { Requester, SealedReply, Stamp } from './contract.ts';
import { transact } from './db.ts';
import { LOCKED, Refused, refusal } from './errors.ts';
import { shown } from './exec.ts';
import { alive } from './holders.ts';
import { decrypt } from './keys.ts';
import type { Keyring } from './lock.ts';
import { PAUSED } from './policy.ts';
import { aad, audit, checkName, find, records, removed, state } from './records.ts';
import { create, current, get, type HumanRequest, settle, waiting } from './requests.ts';
import type { Context } from './sealed.ts';

export const UNLOCK_WAIT = 10 * 1000;
const PROMPT = 200;
const LABEL = 128;
const PATH = 4096;
const ARGS = 4096;
const STDIN = new Set(['tty', 'none', 'pipe', 'file']);
const CONTROL = /[\0-\x1f\x7f-\x9f]/g;

type Fields = Record<string, unknown>;

export class Hold {
  readonly request: string;
  readonly start: () => Promise<SealedReply>;

  constructor(request: string, start: () => Promise<SealedReply>) {
    this.request = request;
    this.start = start;
  }
}

function label(value: unknown, field: string): string {
  if (typeof value !== 'string') throw new Refused('EINVAL', `requester.${field} must be a string`);
  return value.replace(CONTROL, '').slice(0, LABEL);
}

function absolute(value: unknown, field: string): string {
  if (typeof value !== 'string' || !value.startsWith('/') || value.length > PATH) {
    throw new Refused('EINVAL', `requester.${field} must be an absolute path`);
  }
  return value;
}

export function checkRequester(value: unknown): Requester {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Refused('EINVAL', 'an ask needs its requester');
  }
  const given = value as Fields;
  if (given.kind !== 'agent' && given.kind !== 'user') {
    throw new Refused('EINVAL', 'requester.kind must be agent or user');
  }
  const { argv, tty, stdin } = given;
  const listed = Array.isArray(argv) && argv.length <= ARGS;
  if (!listed || !argv.every((arg) => typeof arg === 'string')) {
    throw new Refused('EINVAL', 'requester.argv must be a list of strings');
  }
  if (tty !== null && (typeof tty !== 'string' || tty.length > PATH)) {
    throw new Refused('EINVAL', 'requester.tty must be a path or null');
  }
  if (typeof stdin !== 'string' || !STDIN.has(stdin)) {
    throw new Refused('EINVAL', 'requester.stdin must be tty, none, pipe or file');
  }
  return {
    kind: given.kind,
    name: label(given.name, 'name'),
    ...(given.where === undefined ? {} : { where: label(given.where, 'where') }),
    exe: absolute(given.exe, 'exe'),
    argv: argv as string[],
    cwd: absolute(given.cwd, 'cwd'),
    tty,
    stdin: stdin as Requester['stdin'],
  };
}

function flag(req: Fields, field: string): boolean {
  const value = req[field] ?? false;
  if (typeof value !== 'boolean') throw new Refused('EINVAL', `${field} must be true or false`);
  return value;
}

function prompt(req: Fields): { prompt?: string } {
  const value = req.prompt;
  if (value === undefined) return {};
  if (typeof value !== 'string' || value.length > PROMPT) {
    throw new Refused('EINVAL', `prompt must be a string of at most ${PROMPT} characters`);
  }
  return { prompt: value };
}

async function mayReveal(ctx: Context, requester: Requester): Promise<void> {
  if (requester.kind !== 'agent') return;
  const allowed = (await ctx.loadPolicy()).revealToAgent();
  if (allowed === 'paused') throw new Refused('EACCES', PAUSED, 'policy-paused');
  if (!allowed) {
    throw new Refused('EACCES', 'the policy shows no value to the agent ([reveal] agent = false)');
  }
}

export async function askOp(ctx: Context, req: Fields, stamp: Stamp): Promise<Fields | Hold> {
  const name = checkName(req.name);
  const asked = prompt(req);
  const reveal = flag(req, 'reveal');
  const replace = flag(req, 'replace');
  const requester = checkRequester(req.requester);
  if (stamp.tag === 'agent' && requester.kind !== 'agent') {
    throw new Refused('EINVAL', "requester.kind must be agent for an agent's process");
  }
  const found = await find(ctx.db, ctx.ns, 'secret', name);
  const live = found && !removed(found) ? found : undefined;
  if (live && !reveal && !replace) {
    return {
      state: 'done',
      placeholder: live.placeholder,
      record: state(live, ctx.policy(), ctx.now()),
    };
  }
  if (reveal) await mayReveal(ctx, requester);
  const mode = live && reveal && !replace ? 'reveal' : 'enter';
  await withdrawOrphans(ctx);
  await ctx.holder.take();
  const holder = ctx.holder.id;
  const entry = await create(
    ctx.db,
    { ns: ctx.ns, kind: 'ask', stamp, name, ...asked, mode, reveal, replace, requester, holder },
    ctx.now()
  );
  return new Hold(entry.id, async () => {
    try {
      await ctx.changed();
      return { v: 1, ...(await held(ctx, entry)) };
    } catch (error) {
      return { v: 1, error: refusal(error) };
    }
  });
}

export async function withdrawOrphans(ctx: Context): Promise<void> {
  const open = (await waiting(ctx.db, ctx.ns, ctx.now())).filter((e) => e.kind === 'ask');
  let withdrawn = false;
  for (const entry of open) {
    if (await alive(entry.holder)) continue;
    const settled = await settle(ctx.db, ctx.ns, entry.id, ctx.now(), 'withdrawn');
    if (settled.state !== 'withdrawn') continue;
    withdrawn = true;
    ctx.emit({ v: 1, event: 'cancelled', request: entry.id, kind: 'ask', state: 'withdrawn' });
  }
  if (withdrawn) await ctx.changed();
}

export function ended(ctx: Context, entry: HumanRequest): Promise<HumanRequest> {
  return new Promise((resolve) => {
    let timer: ReturnType<typeof setTimeout>;
    const check = async () => {
      const read = await get(ctx.db, ctx.ns, entry.id).catch(() => null);
      const now = ctx.now();
      if (read && current(read, now) === 'pending') {
        clearTimeout(timer);
        timer = setTimeout(check, Math.max(entry.expiresAt - now, 0) + 10);
        return;
      }
      clearTimeout(timer);
      unwatch();
      resolve(read ? { ...read, state: current(read, now) } : { ...entry, state: 'expired' });
    };
    const unwatch = ctx.watch(() => void check());
    void check();
  });
}

export function unlocked(keyring: Keyring, ms = UNLOCK_WAIT): Promise<CryptoKey> {
  if (keyring.key) return Promise.resolve(keyring.key);
  return new Promise((resolve, reject) => {
    const opened = () => {
      if (!keyring.key) return;
      finish();
      resolve(keyring.key);
    };
    const finish = () => {
      clearTimeout(timer);
      keyring.listeners.delete(opened);
    };
    const timer = setTimeout(() => {
      finish();
      reject(new Refused('EACCES', LOCKED));
    }, ms);
    keyring.listeners.add(opened);
  });
}

export async function held(ctx: Context, entry: HumanRequest): Promise<Fields> {
  const read = await ended(ctx, entry);
  if (read.state === 'expired') {
    ctx.emit({ v: 1, event: 'cancelled', request: entry.id, kind: 'ask', state: 'expired' });
    await ctx.changed();
  }
  if (read.state !== 'done') return { state: read.state };
  return deliver(ctx, read);
}

async function deliver(ctx: Context, read: HumanRequest): Promise<Fields> {
  const name = read.name as string;
  const record = (await records(ctx.db, ctx.ns)).find(
    (r) => r.kind === 'secret' && r.placeholder === read.placeholder && !removed(r)
  );
  if (!record) throw new Refused('ENOENT', `${name} was removed meanwhile`);
  const done = {
    state: 'done',
    placeholder: record.placeholder,
    record: state(record, ctx.policy(), ctx.now()),
  };
  if (!read.reveal) return done;
  const fresh = read.mode === 'enter' ? read.sealedAt === record.updatedAt : read.allowed === true;
  if (!fresh) throw new Refused('EAGAIN', `${name} changed meanwhile; ask again`);
  const requester = read.requester as Requester;
  await mayReveal(ctx, requester);
  const key = await unlocked(ctx.keyring);
  const value = await decrypt(key, record.sealed, aad(record.ns, record.kind, record.name));
  const clean = (await ctx.clean()) as (text: string) => string;
  await transact(ctx.db, ['audit'], 'readwrite', (tx) =>
    audit(tx, ctx.ns, {
      type: 'reveal',
      name,
      uid: read.stamp.uid,
      tag: read.stamp.tag,
      exe: clean(requester.exe),
      argv: shown(requester.argv, clean),
      cwd: clean(requester.cwd),
      requester: requester.kind,
      request: read.id,
      at: ctx.now(),
    })
  );
  await ctx.changed();
  return { ...done, value };
}
