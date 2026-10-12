import type { Part } from './channel.ts';
import { embedded } from './config.ts';
import type {
  AuditEntry,
  AuditPage,
  RecordKind,
  RecordSource,
  Reply,
  Role,
  SealResult,
  VaultEvent,
  VaultList,
} from './contract.ts';
import { all, transact } from './db.ts';
import { Refused, refusal } from './errors.ts';
import {
  checkName,
  checkValue,
  placeholders,
  records,
  remove,
  restore,
  seal,
  state,
  type VaultRecord,
  view,
} from './records.ts';
import { get, settle } from './requests.ts';
import { sealed } from './sealed.ts';
import type { Vault } from './vault.ts';

export const AUDIT_PAGE = 100;
export const AGENT_OPS = new Set([
  'redact',
  'redactStream',
  'push',
  'end',
  'drop',
  'model',
  'mcp',
  'endpoints',
  'records',
  'grant',
  'refresh',
]);
const KINDS = new Set<RecordKind>(['secret', 'grant', 'model', 'mcp']);
const SOURCE = /^(?:settings|process|jerk:[^@\s]+@\S+|oauth:\S+|import:\S+)$/;

type Fields = Record<string, unknown>;

interface Session {
  ns: string;
  role: Role;
  port: MessagePort;
  last: string;
  queue: Promise<void>;
}

type StoredAudit = AuditEntry & { ns: string };

export async function audit(
  vault: Vault,
  ns: string,
  before?: number,
  limit = AUDIT_PAGE
): Promise<AuditPage> {
  const stored = await transact(vault.db, ['audit'], 'readonly', (tx) =>
    all<StoredAudit>(tx, 'audit', ns)
  );
  const older = stored
    .filter((entry) => before === undefined || entry.seq < before)
    .sort((a, b) => b.seq - a.seq);
  const page = older.slice(0, limit);
  const more = older.length > page.length;
  const entries = page.map(({ ns: _ns, ...entry }) => entry as AuditEntry);
  return { audit: entries, more, ...(more ? { next: page[page.length - 1].seq } : {}) };
}

export async function list(vault: Vault, ns: string): Promise<VaultList> {
  const now = vault.now();
  const policy = vault.policy(ns);
  const secrets = (await records(vault.db, ns))
    .sort((a, b) => a.name.localeCompare(b.name) || a.kind.localeCompare(b.kind))
    .map((record) => view(record, policy, now));
  const { audit: entries, more } = await audit(vault, ns);
  return { secrets, refused: [], audit: entries, auditMore: more, exits: policy.view() };
}

async function live(vault: Vault, ns: string): Promise<string[]> {
  return placeholders(await records(vault.db, ns), vault.now());
}

function limit(value: unknown): number {
  if (value === undefined) return AUDIT_PAGE;
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1 || value > 1000) {
    throw new Refused('EINVAL', 'limit must be an integer from 1 to 1000');
  }
  return value;
}

function result(vault: Vault, ns: string, record: VaultRecord): SealResult {
  return {
    name: record.name,
    placeholder: record.placeholder,
    state: state(record, vault.policy(ns), vault.now()),
  };
}

async function put(vault: Vault, ns: string, request: Fields): Promise<Fields> {
  const name = checkName(request.name);
  const value = checkValue(request.value);
  const pending = request.request === undefined ? null : await get(vault.db, ns, request.request);
  if (pending && (pending.kind !== 'value' || pending.name !== name)) {
    throw new Refused('EINVAL', `request ${pending.id} asks for another value`);
  }
  const now = vault.now();
  const { record } = await seal(vault.db, vault.keyring.require(), {
    ns,
    kind: 'secret',
    name,
    value,
    source: 'settings',
    uid: null,
    tag: null,
    now,
  });
  if (pending) await settle(vault.db, ns, pending.id, now, 'done', record.placeholder);
  await vault.changed(ns, ['secrets', 'audit', 'requests']);
  return { ...result(vault, ns, record) };
}

function optionalNumber(value: unknown, field: string): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new Refused('EINVAL', `${field} must be a number`);
  }
  return value;
}

async function sealFromPage(vault: Vault, ns: string, request: Fields): Promise<Fields> {
  const name = checkName(request.name);
  const value = checkValue(request.value);
  const kind = (request.kind ?? 'secret') as RecordKind;
  if (!KINDS.has(kind)) throw new Refused('EINVAL', 'kind must be secret, grant, model or mcp');
  if (typeof request.source !== 'string' || !SOURCE.test(request.source)) {
    throw new Refused('EINVAL', 'source must be settings, process, jerk:, oauth: or import:');
  }
  if (request.refresh !== undefined && typeof request.refresh !== 'string') {
    throw new Refused('EINVAL', 'refresh must be a string');
  }
  const expiresAt = optionalNumber(request.expiresAt, 'expiresAt');
  const { record } = await seal(vault.db, vault.keyring.require(), {
    ns,
    kind,
    name,
    value,
    source: request.source as RecordSource,
    uid: null,
    tag: null,
    now: vault.now(),
    ...(expiresAt === undefined ? {} : { expiresAt }),
    ...(request.refresh === undefined ? {} : { refresh: request.refresh as string }),
  });
  await vault.changed(ns, ['secrets', 'audit']);
  return { ...result(vault, ns, record) };
}

async function mark(vault: Vault, ns: string, request: Fields, removing: boolean) {
  const name = checkName(request.name);
  const record = await (removing ? remove : restore)(vault.db, ns, name, vault.now());
  await vault.changed(ns, ['secrets', 'audit']);
  return { ...result(vault, ns, record) };
}

async function cancel(vault: Vault, ns: string, request: Fields): Promise<Fields> {
  const pending = await get(vault.db, ns, request.request);
  const settled = await settle(vault.db, ns, pending.id, vault.now(), 'cancelled');
  await vault.changed(ns, ['requests']);
  return { state: settled.state };
}

export async function answer(vault: Vault, ns: string, request: Fields): Promise<Fields> {
  switch (request.op) {
    case 'sealed':
      return { reply: await sealed(vault.context(ns), request.req, request.stamp) };
    case 'status':
      return { status: await vault.status(ns) };
    case 'placeholders':
      return { placeholders: await live(vault, ns), scrub: await vault.scrub(ns) };
    case 'list':
      return { list: await list(vault, ns) };
    case 'audit': {
      const before = typeof request.before === 'number' ? request.before : undefined;
      return { ...(await audit(vault, ns, before, limit(request.limit))) };
    }
    case 'put':
      return put(vault, ns, request);
    case 'seal':
      return sealFromPage(vault, ns, request);
    case 'remove':
    case 'restore':
      return mark(vault, ns, request, request.op === 'remove');
    case 'cancel':
      return cancel(vault, ns, request);
    case 'lock':
      vault.keyring.lock();
      return {};
    default:
      throw new Refused('ENOTSUP', `this vault has no op ${String(request.op)}`);
  }
}

export function forRole(role: Role, op: unknown): void {
  if (role === 'agent' && !AGENT_OPS.has(op as string)) {
    throw new Refused('EACCES', `the agent's port can't use ${String(op)}`);
  }
}

export class Server {
  readonly vault: Vault;
  readonly sessions = new Set<Session>();

  constructor(vault: Vault) {
    this.vault = vault;
    vault.onChange((ns, parts) => this.changed(ns, parts));
    vault.keyring.listeners.add(() => void this.locked());
  }

  accept(event: MessageEvent, parent: unknown): boolean {
    const data = event.data as Fields | null;
    if (event.source !== parent || data?.type !== 'slicc-vault' || data.op !== 'hello')
      return false;
    if (!embedded(this.vault.config, event.origin)) return false;
    const [port] = event.ports;
    if (!port) return false;
    const role = (data.role ?? 'page') as Role;
    if (data.v !== 1 || (role !== 'page' && role !== 'agent')) {
      const message = data.v !== 1 ? 'this vault speaks protocol 1' : 'role must be page or agent';
      port.postMessage({ v: 1, op: 'refused', error: { code: 'EINVAL', message } });
      return false;
    }
    const session: Session = { ns: event.origin, role, port, last: '', queue: Promise.resolve() };
    this.sessions.add(session);
    port.onmessage = (message) => void this.handle(session, message.data);
    port.start();
    void this.welcome(session);
    return true;
  }

  async welcome(session: Session): Promise<void> {
    const status = await this.vault.status(session.ns);
    session.port.postMessage({ v: 1, op: 'welcome', role: session.role, status });
  }

  handle(session: Session, data: unknown): Promise<void> {
    session.queue = session.queue.then(() => this.reply(session, data));
    return session.queue;
  }

  async reply(session: Session, data: unknown): Promise<void> {
    const request = (data ?? {}) as Fields;
    const id = typeof request.id === 'number' ? request.id : -1;
    let reply: Reply;
    try {
      if (request.v !== 1) throw new Refused('EINVAL', 'this vault speaks protocol 1');
      forRole(session.role, request.op);
      const fields = await answer(this.vault, session.ns, request);
      reply = { v: 1, id, op: request.op, ...fields } as Reply;
    } catch (error) {
      reply = { v: 1, id, error: refusal(error) };
    }
    session.port.postMessage(reply);
  }

  push(ns: string, event: VaultEvent): void {
    for (const session of this.sessions) {
      if (session.ns === ns && session.role === 'page') session.port.postMessage(event);
    }
  }

  async changed(ns: string, parts: Part[]): Promise<void> {
    if (![...this.sessions].some((session) => session.ns === ns)) return;
    const shown = parts.filter((part) => part !== 'requests') as ('secrets' | 'audit' | 'exits')[];
    const [current, scrub, status] = await Promise.all([
      live(this.vault, ns),
      this.vault.scrub(ns),
      this.vault.status(ns),
    ]);
    const key = `${current.join(',')}#${scrub.version}#${scrub.ready}`;
    for (const session of this.sessions) {
      if (session.ns !== ns || session.role !== 'page' || session.last === key) continue;
      session.last = key;
      session.port.postMessage({ v: 1, event: 'placeholders', placeholders: current, scrub });
    }
    if (shown.length) this.push(ns, { v: 1, event: 'changed', parts: shown });
    this.push(ns, { v: 1, event: 'status', status });
  }

  async locked(): Promise<void> {
    const spaces = new Set([...this.sessions].map((session) => session.ns));
    await Promise.all([...spaces].map((ns) => this.changed(ns, [])));
  }
}
