import type { SealedReply, Stamp } from './contract.ts';
import { Refused, refusal } from './errors.ts';
import type { Keyring } from './lock.ts';
import type { Policy } from './policy.ts';
import { checkName, checkValue, find, records, removed, seal, state } from './records.ts';
import { create, current, get, settle } from './requests.ts';

export const MAX_REQUEST = 64 * 1024;
const PROMPT = 200;

export interface Context {
  db: IDBDatabase;
  ns: string;
  keyring: Keyring;
  policy(): Policy;
  now(): number;
  changed(): Promise<void>;
}

type Fields = Record<string, unknown>;
type Handler = (ctx: Context, req: Fields, stamp: Stamp) => Promise<Fields>;

function integer(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0;
}

export function checkStamp(stamp: unknown): Stamp {
  const given = (stamp ?? {}) as Fields;
  const ids = [given.pid, given.ppid, given.uid, given.gid];
  const tag = given.tag ?? null;
  if (!ids.every(integer) || (tag !== null && typeof tag !== 'string')) {
    throw new Refused('EINVAL', 'the request carries no valid kernel stamp');
  }
  const [pid, ppid, uid, gid] = ids as number[];
  return { pid, ppid, uid, gid, tag };
}

function string(req: Fields, field: string, max = 4096): string {
  const value = req[field];
  if (typeof value !== 'string' || value.length === 0 || value.length > max) {
    throw new Refused('EINVAL', `${field} must be a non-empty string`);
  }
  return value;
}

function optional(req: Fields, field: string, max: number): string | undefined {
  return req[field] === undefined ? undefined : string(req, field, max);
}

async function record(ctx: Context, name: string) {
  const found = await find(ctx.db, ctx.ns, 'secret', name);
  if (!found) throw new Refused('ENOENT', `no record named ${name}`);
  return found;
}

const sealOp: Handler = async (ctx, req, stamp) => {
  const name = checkName(req.name);
  const value = checkValue(req.value);
  const now = ctx.now();
  const { record: sealed } = await seal(ctx.db, ctx.keyring.use(), {
    ns: ctx.ns,
    kind: 'secret',
    name,
    value,
    source: 'process',
    uid: stamp.uid,
    tag: stamp.tag,
    now,
  });
  await ctx.changed();
  return { placeholder: sealed.placeholder, state: state(sealed, ctx.policy(), now) };
};

const placeholderOp: Handler = async (ctx, req) => {
  const found = await record(ctx, checkName(req.name));
  return { placeholder: found.placeholder, state: state(found, ctx.policy(), ctx.now()) };
};

const listOp: Handler = async (ctx) => {
  const now = ctx.now();
  const policy = ctx.policy();
  const secrets = (await records(ctx.db, ctx.ns))
    .filter((entry) => entry.kind === 'secret' && !removed(entry, now))
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((entry) => ({
      name: entry.name,
      placeholder: entry.placeholder,
      state: state(entry, policy, now),
      exec: policy.exec(entry.name),
      rules: policy.rules(entry.name),
      ...(entry.expiresAt === undefined ? {} : { expiresAt: entry.expiresAt }),
    }));
  return { secrets };
};

const testOp: Handler = async (ctx, req) => {
  const name = checkName(req.name);
  const url = URL.parse(string(req, 'url', 8192));
  if (!url) throw new Refused('EINVAL', 'url must be an absolute URL');
  optional(req, 'method', 32);
  optional(req, 'header', 256);
  const found = await record(ctx, name);
  if (removed(found, ctx.now())) return { verdict: 'refuse', reason: `${name} was removed` };
  return { verdict: 'refuse', reason: `no rule in /etc/fnox/config.toml names ${name}` };
};

function requestFields(req: Fields): {
  kind: 'value' | 'oauth' | 'jerk-seal';
  name?: string;
  provider?: string;
  prompt?: string;
  oauth?: Fields;
} {
  if (req.kind === 'value') {
    const prompt = optional(req, 'prompt', PROMPT);
    return { kind: 'value', name: checkName(req.name), ...(prompt ? { prompt } : {}) };
  }
  if (req.kind === 'oauth') {
    const oauth = req.oauth;
    if (!oauth || typeof oauth !== 'object' || Array.isArray(oauth)) {
      throw new Refused('EINVAL', 'oauth must be an object');
    }
    return { kind: 'oauth', provider: string(req, 'provider', 128), oauth: oauth as Fields };
  }
  if (req.kind === 'jerk-seal')
    return { kind: 'jerk-seal', provider: string(req, 'provider', 128) };
  throw new Refused('EINVAL', 'kind must be value, oauth or jerk-seal');
}

const requestOp: Handler = async (ctx, req, stamp) => {
  const entry = await create(ctx.db, { ns: ctx.ns, stamp, ...requestFields(req) }, ctx.now());
  await ctx.changed();
  return { state: 'pending', id: entry.id };
};

const statusOp: Handler = async (ctx, req, stamp) => {
  const entry = await get(ctx.db, ctx.ns, req.id, stamp.uid);
  const now = ctx.now();
  const reply: Fields = { state: current(entry, now) };
  if (reply.state !== 'done' || entry.kind !== 'value' || !entry.name) return reply;
  const found = await find(ctx.db, ctx.ns, 'secret', entry.name);
  if (!found) return reply;
  const recordState = state(found, ctx.policy(), now);
  return { ...reply, placeholder: found.placeholder, record: recordState };
};

const cancelOp: Handler = async (ctx, req, stamp) => {
  const entry = await get(ctx.db, ctx.ns, req.id, stamp.uid);
  const settled = await settle(ctx.db, ctx.ns, entry.id, ctx.now(), 'cancelled');
  await ctx.changed();
  return { state: settled.state };
};

const materializeOp: Handler = async (_ctx, req) => {
  const names = req.names;
  if (!Array.isArray(names) || names.length === 0) {
    throw new Refused('EINVAL', 'names must be a non-empty list');
  }
  names.forEach(checkName);
  if (!string(req, 'path').startsWith('/') || !string(req, 'cwd').startsWith('/')) {
    throw new Refused('EINVAL', 'path and cwd must be absolute');
  }
  if (!Array.isArray(req.argv) || !req.argv.every((arg) => typeof arg === 'string')) {
    throw new Refused('EINVAL', 'argv must be a list of strings');
  }
  throw new Refused('EACCES', 'materialize is not supported by this vault version');
};

export const OPS: Record<string, Handler> = {
  seal: sealOp,
  placeholder: placeholderOp,
  list: listOp,
  test: testOp,
  request: requestOp,
  status: statusOp,
  cancel: cancelOp,
  materialize: materializeOp,
};

export function parse(req: unknown): Fields {
  const parsed = typeof req === 'string' ? JSON.parse(req) : req;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Refused('EINVAL', 'a request is one JSON object');
  }
  return parsed as Fields;
}

export function size(req: unknown): number {
  return new TextEncoder().encode(typeof req === 'string' ? req : JSON.stringify(req)).length;
}

export async function sealed(ctx: Context, req: unknown, stamp: unknown): Promise<SealedReply> {
  try {
    if (size(req) > MAX_REQUEST) throw new Refused('EINVAL', 'a request is at most 64 KiB');
    const fields = parse(req);
    if (fields.v !== 1) throw new Refused('EINVAL', 'unknown protocol version');
    const handler = typeof fields.op === 'string' ? OPS[fields.op] : undefined;
    if (!handler || !Object.hasOwn(OPS, fields.op as string)) {
      throw new Refused('EINVAL', 'unknown op');
    }
    return { v: 1, ...(await handler(ctx, fields, checkStamp(stamp))) };
  } catch (error) {
    if (error instanceof SyntaxError) {
      return { v: 1, error: { code: 'EINVAL', message: 'a request is one JSON object' } };
    }
    return { v: 1, error: refusal(error) };
  }
}
