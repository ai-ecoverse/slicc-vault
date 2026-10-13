import type { ExitName, SealedReply, Stamp, VaultEvent } from './contract.ts';
import { Refused, refusal } from './errors.ts';
import type { Exec } from './exec.ts';
import { prepare } from './inject.ts';
import type { Keyring } from './lock.ts';
import type { Policy } from './policy.ts';
import { checkName, checkValue, find, records, removed, rulesFor, seal, state } from './records.ts';
import { kernelPort } from './refusal.ts';
import { create, current, get, settle } from './requests.ts';
import { loadRegistered } from './rules.ts';

export const MAX_REQUEST = 64 * 1024;
const PROMPT = 200;

export interface Context {
  db: IDBDatabase;
  ns: string;
  keyring: Keyring;
  exec: Exec;
  policy(): Policy;
  now(): number;
  changed(): Promise<void>;
  emit(event: VaultEvent): void;
  sudoGid(): number | null;
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
  const users = typeof given.users === 'string' ? { users: given.users } : {};
  const groups =
    Array.isArray(given.groups) && given.groups.every(integer)
      ? { groups: given.groups as number[] }
      : {};
  return { pid, ppid, uid, gid, tag, ...users, ...groups };
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

function bridge(req: Fields): { server: string; url: string } | null {
  if (req.kind === undefined || req.kind === 'secret') return null;
  if (req.kind !== 'mcp')
    throw new Refused('EINVAL', 'a program seals a secret or an mcp bridge token');
  const url = typeof req.url === 'string' ? URL.parse(req.url) : null;
  if (typeof req.server !== 'string' || !req.server || req.server.length > 128) {
    throw new Refused('EINVAL', 'an mcp bridge token needs its server');
  }
  if (!url || kernelPort(url) === null) {
    throw new Refused('EACCES', 'a program binds an MCP credential only to a kernel-loopback URL');
  }
  return { server: req.server, url: url.href };
}

const sealOp: Handler = async (ctx, req, stamp) => {
  const name = checkName(req.name);
  const value = checkValue(req.value);
  const bound = bridge(req);
  const now = ctx.now();
  const { record: sealed } = await seal(ctx.db, ctx.keyring.use(), {
    ns: ctx.ns,
    kind: bound ? 'mcp' : 'secret',
    name,
    value,
    source: 'process',
    uid: stamp.uid,
    tag: stamp.tag,
    now,
    ...(bound ?? {}),
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
    .filter((entry) => entry.kind === 'secret' && !removed(entry))
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((entry) => ({
      name: entry.name,
      placeholder: entry.placeholder,
      state: state(entry, policy, now),
      exec: policy.exec(entry.name),
      rules: rulesFor(entry, policy),
      ...(entry.expiresAt === undefined ? {} : { expiresAt: entry.expiresAt }),
    }));
  return { secrets };
};

const testOp: Handler = async (ctx, req, stamp) => {
  const name = checkName(req.name);
  const url = URL.parse(string(req, 'url', 8192));
  if (!url) throw new Refused('EINVAL', 'url must be an absolute URL');
  const method = optional(req, 'method', 32) ?? 'GET';
  const header = optional(req, 'header', 256) ?? 'authorization';
  const exit = optional(req, 'exit', 128) ?? 'page';
  const found = await record(ctx, name);
  const [held, registered] = await Promise.all([
    records(ctx.db, ctx.ns),
    loadRegistered(ctx.db, ctx.ns),
  ]);
  const prepared = await prepare({
    ns: ctx.ns,
    head: { method, url: url.href, headers: [[header, `Bearer ${found.placeholder}`]] },
    owner: stamp,
    exit: exit as ExitName,
    traits: { manualRedirects: exit !== 'page', encodedBodies: false },
    records: held,
    policy: ctx.policy(),
    registered,
    key: ctx.keyring.key,
    now: ctx.now(),
  });
  if (!prepared.ok) return { verdict: 'refuse', reason: prepared.reason };
  return {
    verdict: 'inject',
    reason: `${name} would be sent in ${header.toLowerCase()} to ${prepared.host}`,
  };
};

const JOPS = new Set(['list', 'status', 'create']);

function jerkFields(req: Fields): Fields {
  if (typeof req.jop !== 'string' || !JOPS.has(req.jop)) {
    throw new Refused('EINVAL', 'jop must be list, status or create');
  }
  const provider = optional(req, 'provider', 128);
  const scope = optional(req, 'scope', 1024);
  if (req.jop !== 'list' && !provider)
    throw new Refused('EINVAL', `jop ${req.jop} needs a provider`);
  const params = req.params;
  if (params !== undefined && (!params || typeof params !== 'object' || Array.isArray(params))) {
    throw new Refused('EINVAL', 'params must be an object');
  }
  return {
    kind: 'jerk',
    jop: req.jop,
    ...(provider ? { provider } : {}),
    ...(scope ? { scope } : {}),
    ...(params ? { params } : {}),
  };
}

export function mayManage(stamp: Stamp, sudoGid: number | null): boolean {
  if (stamp.users !== 'enforce') return false;
  if (stamp.uid === 0) return true;
  return sudoGid !== null && Array.isArray(stamp.groups) && stamp.groups.includes(sudoGid);
}

function requestFields(req: Fields): {
  kind: 'value' | 'oauth' | 'jerk-seal' | 'jerk' | 'unseal';
  name?: string;
  provider?: string;
  prompt?: string;
  oauth?: Fields;
  jop?: string;
  scope?: string;
  params?: Fields;
} {
  if (req.kind === 'jerk') return jerkFields(req) as ReturnType<typeof requestFields>;
  if (req.kind === 'unseal') return { kind: 'unseal', provider: string(req, 'provider', 128) };
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
  throw new Refused('EINVAL', 'kind must be value, oauth, jerk-seal, jerk or unseal');
}

const requestOp: Handler = async (ctx, req, stamp) => {
  const fields = requestFields(req);
  const managing = fields.kind === 'unseal' || (fields.kind === 'jerk' && fields.jop === 'create');
  const refused = managing && !mayManage(stamp, ctx.sudoGid());
  const answer = {
    exit: 2,
    message: `${fields.provider} can be signed in or dropped only by root or a cone (J2)`,
  };
  const entry = await create(
    ctx.db,
    { ns: ctx.ns, stamp, ...fields, ...(refused ? { state: 'done', answer } : {}) },
    ctx.now()
  );
  await ctx.changed();
  return refused ? { state: 'done', id: entry.id, ...answer } : { state: 'pending', id: entry.id };
};

const statusOp: Handler = async (ctx, req, stamp) => {
  const entry = await get(ctx.db, ctx.ns, req.id, stamp.uid);
  const now = ctx.now();
  const reply: Fields = {
    state: current(entry, now),
    ...(entry.jerk ? { jerk: entry.jerk } : {}),
    ...entry.answer,
  };
  if (reply.state !== 'done') return reply;
  const held = await records(ctx.db, ctx.ns);
  const found = held.find((r) => r.kind === 'secret' && r.placeholder === entry.placeholder);
  if (!found) return reply;
  const recordState = state(found, ctx.policy(), now);
  return { ...reply, placeholder: found.placeholder, record: recordState };
};

const cancelOp: Handler = async (ctx, req, stamp) => {
  const entry = await get(ctx.db, ctx.ns, req.id, stamp.uid);
  const now = ctx.now();
  const settled = await settle(ctx.db, ctx.ns, entry.id, now, 'cancelled');
  await ctx.changed();
  if (current(entry, now) === 'pending' && settled.state === 'cancelled')
    ctx.emit({ v: 1, event: 'cancelled', request: entry.id, kind: entry.kind });
  return { state: settled.state };
};

const materializeOp: Handler = (ctx, req, stamp) => ctx.exec.materialize(ctx.ns, req, stamp);

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
