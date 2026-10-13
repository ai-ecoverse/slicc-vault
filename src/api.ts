import { AgentPort } from './agent.ts';
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
import { forward } from './forward.ts';
import {
  checkName,
  checkValue,
  dismissBackup,
  NAME,
  placeholders,
  records,
  remove,
  restore,
  SOURCE,
  seal,
  state,
  type VaultRecord,
  view,
} from './records.ts';
import {
  checkOAuth,
  type EgressRequest,
  type EgressResponse,
  egressOver,
  JERK,
} from './refresh.ts';
import { current, get, type HumanRequest, respond, settle } from './requests.ts';
import { apply } from './rules.ts';
import { sealed } from './sealed.ts';
import { exporter, importer } from './transfer.ts';
import type { Vault } from './vault.ts';

export const AUDIT_PAGE = 100;
export const AGENT_OPS = new Set([
  'redact',
  'redactStream',
  'push',
  'idle',
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

type Fields = Record<string, unknown>;

interface Session {
  ns: string;
  role: Role;
  port: MessagePort;
  last: string;
  queue: Promise<void>;
  agent?: AgentPort;
  silent?: boolean;
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
  const entries = page.map(({ ns: _ns, ...entry }) => {
    const known = entry as AuditEntry & { uid?: number | null; tag?: string | null };
    return { ...known, uid: known.uid ?? null, tag: known.tag ?? null } as AuditEntry;
  });
  return { audit: entries, more, ...(more ? { next: page[page.length - 1].seq } : {}) };
}

export async function list(vault: Vault, ns: string): Promise<VaultList> {
  const now = vault.now();
  const policy = vault.policy(ns);
  const secrets = (await records(vault.db, ns))
    .sort((a, b) => a.name.localeCompare(b.name) || a.kind.localeCompare(b.kind))
    .map((record) => view(record, policy, now));
  const { audit: entries, more } = await audit(vault, ns);
  return {
    secrets,
    refused: policy.refused(),
    audit: entries,
    auditMore: more,
    exits: policy.view(),
  };
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
  const ended = pending ? current(pending, vault.now()) : 'pending';
  if (ended !== 'pending') throw new Refused('EINVAL', `request ${pending?.id} is ${ended}`);
  const now = vault.now();
  const { record } = await seal(vault.db, vault.keyring.use(), {
    ns,
    kind: 'secret',
    name,
    value,
    source: 'settings',
    uid: null,
    tag: null,
    now,
    ...(pending ? { answers: { id: pending.id, clock: () => vault.now() } } : {}),
  });
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

function text(value: unknown, field: string, max: number): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || value.length > max) {
    throw new Refused('EINVAL', `${field} must be a string of at most ${max} characters`);
  }
  return value;
}

function strings(value: unknown, field: string): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || !value.every((item) => typeof item === 'string')) {
    throw new Refused('EINVAL', `${field} must be a list of strings`);
  }
  return value as string[];
}

function row(value: unknown): Fields {
  const given = (value ?? {}) as Fields;
  if (typeof given.provider !== 'string') {
    throw new Refused(
      'EINVAL',
      'rows are { provider, name?, env, device?, signedIn?, user?, scopes? }'
    );
  }
  const out: Fields = { provider: given.provider, env: strings(given.env, 'env') ?? [] };
  for (const field of ['name', 'device', 'user']) {
    const value = text(given[field], field, 256);
    if (value !== undefined) out[field] = value;
  }
  if (typeof given.signedIn === 'boolean') out.signedIn = given.signedIn;
  const scopes = strings(given.scopes, 'scopes');
  if (scopes !== undefined) out.scopes = scopes;
  return out;
}

async function placeholderFor(
  vault: Vault,
  ns: string,
  provider: string | undefined,
  given: unknown
) {
  const own = (await records(vault.db, ns)).filter(
    (r) =>
      r.kind === 'secret' &&
      !r.removedAt &&
      (r.source === `oauth:${provider}` || r.source.startsWith(`jerk:${provider}@`))
  );
  if (given !== undefined) {
    if (!own.some((r) => r.placeholder === given))
      throw new Refused('EINVAL', "placeholder is not one of this provider's records");
    return given as string;
  }
  return own[0]?.placeholder;
}

async function answerRequest(vault: Vault, ns: string, request: Fields): Promise<Fields> {
  if (request.state !== 'progress' && request.state !== 'done') {
    throw new Refused('EINVAL', 'state must be progress or done');
  }
  if (
    request.exit !== undefined &&
    (!Number.isInteger(request.exit) || (request.exit as number) < 0)
  ) {
    throw new Refused('EINVAL', 'exit must be a non-negative integer');
  }
  if (request.rows !== undefined && !Array.isArray(request.rows))
    throw new Refused('EINVAL', 'rows must be a list');
  const answer: Fields = {};
  const progress = text(request.progress, 'progress', 200);
  const message = text(request.message, 'message', 500);
  const user = text(request.user, 'user', 256);
  const scopes = strings(request.scopes, 'scopes');
  if (progress !== undefined) answer.progress = progress;
  if (request.exit !== undefined) answer.exit = request.exit;
  if (user !== undefined) answer.user = user;
  if (scopes !== undefined) answer.scopes = scopes;
  if (message !== undefined) answer.message = message;
  if (request.rows !== undefined) answer.rows = (request.rows as unknown[]).map(row);
  const entry = await get(vault.db, ns, request.request);
  const status = entry.kind === 'jerk' && entry.jop === 'status';
  const success = request.state === 'done' && (request.exit ?? 0) === 0;
  if (success && (entry.kind === 'oauth' || entry.kind === 'jerk-seal'))
    throw new Refused('EINVAL', 'a sign-in completes with seal, not answer');
  if (request.placeholder !== undefined && !status)
    throw new Refused('EINVAL', 'only jop status answers carry a placeholder');
  if (status && success) {
    const placeholder = await placeholderFor(vault, ns, entry.provider, request.placeholder);
    if (placeholder) answer.placeholder = placeholder;
  }
  const updated = await respond(
    vault.db,
    ns,
    request.request,
    () => vault.now(),
    answer,
    request.state === 'done'
  );
  await vault.changed(ns, ['requests']);
  return { state: updated.state };
}

function signIn(pending: HumanRequest, source: string, now: number): boolean {
  if (current(pending, now) !== 'pending') return false;
  if (pending.kind === 'oauth') return source === `oauth:${pending.provider}`;
  if (pending.kind === 'jerk-seal') return source.startsWith(`jerk:${pending.provider}@`);
  return false;
}

function checkJerk(value: unknown): Fields {
  const given = (value ?? {}) as Fields;
  if (typeof given !== 'object' || Array.isArray(given) || typeof given.exit !== 'number') {
    throw new Refused('EINVAL', 'jerk must be { exit, user?, scopes?, expires_at? }');
  }
  const out: Fields = { exit: given.exit };
  if (typeof given.user === 'string') out.user = given.user;
  if (Array.isArray(given.scopes) && given.scopes.every((s) => typeof s === 'string'))
    out.scopes = given.scopes;
  if (typeof given.expires_at === 'string') out.expires_at = given.expires_at;
  return out;
}

async function sealFromPage(vault: Vault, ns: string, request: Fields): Promise<Fields> {
  const name = checkName(request.name);
  const value = checkValue(request.value);
  const kind = (request.kind ?? 'secret') as RecordKind;
  if (!KINDS.has(kind)) throw new Refused('EINVAL', 'kind must be secret, grant, model or mcp');
  if (typeof request.source !== 'string' || !SOURCE.test(request.source)) {
    throw new Refused('EINVAL', 'source must be settings, process, jerk:, oauth: or import:');
  }
  const refresh = request.refresh;
  if (
    refresh !== undefined &&
    (typeof refresh !== 'string' || (refresh !== JERK && !NAME.test(refresh)))
  ) {
    throw new Refused('EINVAL', 'refresh must be jerk-seal or the name of a grant');
  }
  const mode = refresh === JERK ? 'jerk:' : 'oauth:';
  if (refresh !== undefined && !(request.source as string).startsWith(mode))
    throw new Refused('EINVAL', `refresh ${refresh} needs a ${mode} source`);
  if (request.oauth !== undefined && kind !== 'grant')
    throw new Refused('EINVAL', 'only a grant carries oauth');
  const oauth = request.oauth === undefined ? undefined : checkOAuth(request.oauth);
  const jerk = request.jerk === undefined ? undefined : checkJerk(request.jerk);
  const pending = request.request === undefined ? null : await get(vault.db, ns, request.request);
  if (pending && (kind !== 'secret' || !signIn(pending, request.source as string, vault.now()))) {
    throw new Refused(
      'EINVAL',
      `request ${pending.id} isn't a pending sign-in or lease of this provider`
    );
  }
  const expiresAt = optionalNumber(request.expiresAt, 'expiresAt');
  const { record } = await seal(vault.db, vault.keyring.use(), {
    ns,
    kind,
    name,
    value,
    source: request.source as RecordSource,
    uid: null,
    tag: null,
    now: vault.now(),
    ...(expiresAt === undefined ? {} : { expiresAt }),
    ...(refresh === undefined ? {} : { refresh: refresh as string }),
    ...(oauth === undefined ? {} : { oauth }),
    ...(pending
      ? { answers: { id: pending.id, clock: () => vault.now(), ...(jerk ? { jerk } : {}) } }
      : {}),
  });
  await vault.changed(ns, ['secrets', 'audit', 'requests']);
  return { ...result(vault, ns, record) };
}

async function mark(vault: Vault, ns: string, request: Fields, removing: boolean) {
  const name = checkName(request.name);
  const kind = (request.kind ?? 'secret') as RecordKind;
  if (!KINDS.has(kind)) throw new Refused('EINVAL', 'kind must be secret, grant, model or mcp');
  const record = await (removing ? remove : restore)(vault.db, ns, name, vault.now(), kind);
  await vault.changed(ns, ['secrets', 'audit']);
  return { ...result(vault, ns, record) };
}

async function cancel(vault: Vault, ns: string, request: Fields): Promise<Fields> {
  const pending = await get(vault.db, ns, request.request);
  const settled = await settle(vault.db, ns, pending.id, vault.now(), 'cancelled');
  await vault.changed(ns, ['requests']);
  return { state: settled.state };
}

export async function answer(
  vault: Vault,
  ns: string,
  request: Fields,
  port?: MessagePort
): Promise<Fields> {
  switch (request.op) {
    case 'forward':
      return forward(vault, ns, request, port);
    case 'materializeConsume':
      return vault.exec.consume(ns, request);
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
    case 'import':
      return importer(vault, ns, request);
    case 'export':
      return exporter(vault, ns, request);
    case 'answer':
      return answerRequest(vault, ns, request);
    case 'refresh':
      return vault.refresher.refresh(ns, checkName(request.name));
    case 'lock':
      vault.keyring.lock();
      return {};
    case 'policy': {
      const { result, changed } = await apply(vault.db, ns, request.files, vault.now());
      await vault.loadPolicy(ns);
      if (changed) await vault.changed(ns, ['secrets', 'exits', 'audit']);
      return { ...result };
    }
    case 'dismissBackupReminder': {
      await dismissBackup(vault.db, ns);
      await vault.changed(ns, []);
      return { backupReminder: (await vault.status(ns)).backupReminder };
    }
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
    vault.onEvent((ns, event) => this.push(ns, event));
    vault.refresher.send = (ns, req) => this.egress(ns, req);
    vault.refresher.announce = (ns, name, source, expiresAt) =>
      this.push(ns, { v: 1, event: 'refresh', name, source: source as RecordSource, expiresAt });
  }

  egress(ns: string, req: EgressRequest): Promise<EgressResponse> {
    const session = [...this.sessions]
      .reverse()
      .find((s) => s.ns === ns && s.role === 'page' && !s.silent);
    if (!session)
      return Promise.reject(new Refused('ENOTCONN', 'no page is connected to send the refresh'));
    const channel = new MessageChannel();
    const answer = egressOver(channel.port1);
    session.port.postMessage({ v: 1, event: 'egress', request: req }, [channel.port2]);
    answer.catch((error: Refused) => {
      if (error.code === 'ETIMEDOUT') session.silent = true;
    });
    return answer;
  }

  sweep(): Promise<void[]> {
    const spaces = new Set([...this.sessions].filter((s) => s.role === 'page').map((s) => s.ns));
    return Promise.all([...spaces].map((ns) => this.vault.refresher.sweep(ns)));
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
    const agent = role === 'agent' ? new AgentPort(this.vault, event.origin) : undefined;
    if (role === 'page') {
      if (Number.isInteger(data.sudoGid))
        this.vault.sudoGids.set(event.origin, data.sudoGid as number);
      else this.vault.sudoGids.delete(event.origin);
    }
    const session: Session = {
      ns: event.origin,
      role,
      port,
      last: '',
      queue: Promise.resolve(),
      ...(agent ? { agent } : {}),
    };
    this.sessions.add(session);
    port.onmessage = (message) => void this.handle(session, message.data, message.ports);
    port.start();
    session.queue = this.welcome(session);
    return true;
  }

  async welcome(session: Session): Promise<void> {
    await this.vault.loadPolicy(session.ns);
    await this.vault.scrubbers.get(session.ns);
    const status = await this.vault.status(session.ns);
    session.port.postMessage({ v: 1, op: 'welcome', role: session.role, status });
  }

  handle(session: Session, data: unknown, ports: readonly MessagePort[] = []): Promise<void> {
    session.queue = session.queue.then(() => this.reply(session, data, ports));
    return session.queue;
  }

  async reply(session: Session, data: unknown, ports: readonly MessagePort[] = []): Promise<void> {
    const request = (data ?? {}) as Fields;
    const id = typeof request.id === 'number' ? request.id : -1;
    let reply: Reply;
    try {
      if (request.v !== 1) throw new Refused('EINVAL', 'this vault speaks protocol 1');
      forRole(session.role, request.op);
      const fields = session.agent
        ? await session.agent.answer(request)
        : await answer(this.vault, session.ns, request, ports[0]);
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
    await this.vault.scrubbers.get(ns);
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
