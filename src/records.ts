import { hex, random } from './bytes.ts';
import type {
  BackupReminder,
  RecordKind,
  RecordSource,
  RecordState,
  Rule,
  SecretView,
} from './contract.ts';
import { all, request, type Store, transact } from './db.ts';
import { Refused } from './errors.ts';
import { type Dek, encrypt, type Keys, type Sealed } from './keys.ts';
import type { Policy } from './policy.ts';

export const NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
export const PROVIDER = /^[a-z0-9][a-z0-9._-]{0,63}$/;
export const SOURCE = /^(?:settings|process|jerk:[^@\s]+@\S+|oauth:\S+|import:\S+)$/;
export const PLACEHOLDER = /^fnox_proxy_[0-9a-f]{24}$/;
export const RESTORABLE = 30 * 24 * 60 * 60 * 1000;
export const MIN_VALUE = 8;
const CONTAINS_PLACEHOLDER = /fnox_proxy_[0-9a-f]{24}/;

export interface VaultRecord {
  ns: string;
  kind: RecordKind;
  name: string;
  placeholder: string;
  sealed: Sealed;
  source: RecordSource;
  createdAt: number;
  updatedAt: number;
  usedAt?: number;
  expiresAt?: number;
  refresh?: string;
  oauth?: OAuthConfig;
  provider?: string;
  server?: string;
  settings?: Record<string, string>;
  url?: string;
  pinned?: boolean;
  unpins?: number;
  sealedBy?: number;
  removedAt?: number;
  removedWith?: string;
}

export interface OAuthConfig {
  tokenUrl: string;
  clientId: string;
  scope?: string;
  resource?: string;
}

export interface Binding {
  provider?: string;
  server?: string;
  settings?: Record<string, string>;
}

const SETTINGS = 16;

export function binding(kind: RecordKind, request: Record<string, unknown>): Binding {
  const { provider, server, settings } = request;
  if (
    provider !== undefined &&
    (kind !== 'model' || typeof provider !== 'string' || !PROVIDER.test(provider))
  )
    throw new Refused('EINVAL', 'provider is a pi-ai provider id, for a model record');
  if (
    server !== undefined &&
    (kind !== 'mcp' ||
      typeof server !== 'string' ||
      !server ||
      server.length > 128 ||
      /[\0-\x1f]/.test(server))
  )
    throw new Refused('EINVAL', 'server is the MCP server name, for an mcp record');
  const out: Binding = {};
  if (provider !== undefined) out.provider = provider as string;
  if (server !== undefined) out.server = server as string;
  if (settings === undefined) return out;
  const entries =
    settings && typeof settings === 'object' && !Array.isArray(settings)
      ? Object.entries(settings)
      : null;
  const valid =
    (kind === 'model' || kind === 'mcp') &&
    entries !== null &&
    entries.length <= SETTINGS &&
    entries.every(
      ([key, value]) =>
        NAME.test(key) &&
        typeof value === 'string' &&
        value.length <= 256 &&
        !/[\0-\x1f]/.test(value)
    );
  if (!valid)
    throw new Refused(
      'EINVAL',
      `settings are at most ${SETTINGS} NAME = text pairs, for a model or mcp record`
    );
  out.settings = Object.fromEntries(entries as [string, string][]);
  return out;
}

export interface SealInput {
  ns: string;
  kind: RecordKind;
  name: string;
  value: string;
  source: RecordSource;
  uid: number | null;
  tag: string | null;
  expiresAt?: number;
  refresh?: string;
  oauth?: OAuthConfig;
  provider?: string;
  server?: string;
  settings?: Record<string, string>;
  url?: string;
  exclusive?: boolean;
  placeholder?: string;
  answers?: Answers;
  now: number;
}

export interface Sealing {
  record: VaultRecord;
  rotated: boolean;
}

export function mint(): string {
  return `fnox_proxy_${hex(random(12))}`;
}

export function aad(ns: string, kind: RecordKind, name: string): string {
  return `slicc-vault/1\0${ns}\0${kind}\0${name}`;
}

export function checkName(name: unknown): string {
  if (typeof name !== 'string' || !NAME.test(name) || name.length > 128) {
    throw new Refused('EINVAL', 'name must match ^[A-Za-z_][A-Za-z0-9_]*$');
  }
  return name;
}

export function checkValue(value: unknown): string {
  if (typeof value !== 'string') throw new Refused('EINVAL', 'value must be a string');
  if (new TextEncoder().encode(value).length < MIN_VALUE) {
    throw new Refused('EINVAL', "values shorter than 8 bytes can't be protected from the model");
  }
  if (/[\r\n\0]/.test(value)) throw new Refused('EINVAL', 'value must not contain CR, LF or NUL');
  if (CONTAINS_PLACEHOLDER.test(value)) {
    throw new Refused('EINVAL', 'a value must not contain a placeholder');
  }
  return value;
}

export function removed(record: VaultRecord): boolean {
  return record.removedAt !== undefined;
}

export function rulesFor(record: VaultRecord, policy: Policy): Rule[] {
  if (record.kind !== 'secret' || policy.placeholder(record.name) !== record.placeholder) return [];
  return policy.rules(record.name);
}

export function state(record: VaultRecord, policy: Policy, now: number): RecordState {
  if (removed(record)) return 'removed';
  return rulesFor(record, policy).length > 0 ? 'active' : 'inert';
}

export function device(source: RecordSource): string | null {
  const at = source.startsWith('jerk:') ? source.lastIndexOf('@') : -1;
  return at < 0 ? null : source.slice(at + 1);
}

export type Clean = ((text: string) => string) | null;

function shownBinding(record: VaultRecord, clean: Clean): Partial<SecretView> {
  if (!clean) return {};
  const out: Partial<SecretView> = {};
  if (record.provider !== undefined) out.provider = clean(record.provider);
  if (record.server !== undefined) out.server = clean(record.server);
  if (record.kind === 'mcp' && record.url !== undefined) out.url = clean(record.url);
  if (record.pinned) out.pinned = true;
  if (record.settings !== undefined) {
    out.settings = Object.fromEntries(
      Object.entries(record.settings)
        .filter(([key]) => clean(key) === key)
        .map(([key, value]) => [key, clean(value)])
    );
  }
  return out;
}

export function view(
  record: VaultRecord,
  policy: Policy,
  now: number,
  clean: Clean = null
): SecretView {
  const secret = record.kind === 'secret';
  const rules = rulesFor(record, policy);
  const exits = secret ? policy.exits(record.name) : null;
  const argv = secret ? policy.argv(record.name) : null;
  return {
    name: record.name,
    kind: record.kind,
    placeholder: record.placeholder,
    state: state(record, policy, now),
    source: record.source,
    sourceDevice: device(record.source),
    ...shownBinding(record, clean),
    domains: [...new Set(rules.map((rule) => rule.domain))],
    rules,
    ...(exits ? { exits } : {}),
    exec: secret ? policy.exec(record.name) : false,
    ...(argv ? { execArgv: argv } : {}),
    createdAt: record.createdAt,
    ...(record.usedAt === undefined ? {} : { usedAt: record.usedAt }),
    ...(record.expiresAt === undefined ? {} : { expiresAt: record.expiresAt }),
    ...(record.removedAt === undefined ? {} : { removedAt: record.removedAt }),
  };
}

function kept(existing: VaultRecord, wanted: string | undefined): string {
  if (wanted !== undefined && wanted !== existing.placeholder) {
    throw new Refused('EEXIST', `${existing.name} has another placeholder in this vault`);
  }
  return existing.placeholder;
}

async function chosen(store: IDBObjectStore, wanted: string | undefined): Promise<string> {
  if (wanted === undefined) return unused(store);
  if ((await request(store.index('placeholder').count(wanted))) > 0) {
    throw new Refused('EEXIST', 'that placeholder is already in use in this vault');
  }
  return wanted;
}

async function unused(store: IDBObjectStore): Promise<string> {
  for (;;) {
    const placeholder = mint();
    if ((await request(store.index('placeholder').count(placeholder))) === 0) return placeholder;
  }
}

function guard(existing: VaultRecord | undefined, input: SealInput): void {
  if (!existing) return;
  if (input.kind === 'mcp' && input.source === 'process') {
    const mine =
      existing.source === 'process' && (input.uid === 0 || existing.sealedBy === input.uid);
    if (mine) return;
    throw new Refused(
      'EEXIST',
      `${input.name} belongs to someone else; seal the bridge under another name`
    );
  }
  if (removed(existing)) return;
  if (existing.source === 'process' || input.uid === 0 || input.source !== 'process') return;
  throw new Refused(
    'EEXIST',
    `${input.name} holds a value entered outside a program; replace it with sudo fnox set`
  );
}

export interface Answers {
  id: string;
  jerk?: Record<string, unknown>;
  clock?: () => number;
}

async function answered(
  tx: IDBTransaction,
  ns: string,
  answers: Answers,
  placeholder: string,
  sealedAt: number
): Promise<void> {
  const store = tx.objectStore('requests');
  const entry = (await request(store.get(answers.id))) as Record<string, unknown> | undefined;
  const now = answers.clock ? answers.clock() : sealedAt;
  const live = entry?.ns === ns && entry.state === 'pending' && now < (entry.expiresAt as number);
  if (!entry || !live) throw new Refused('EINVAL', `request ${answers.id} is no longer pending`);
  const jerk = answers.jerk ? { jerk: answers.jerk } : {};
  await request(store.put({ ...entry, state: 'done', placeholder, ...jerk }));
}

function bound(existing: VaultRecord | undefined, input: SealInput): Partial<VaultRecord> {
  const out: Partial<VaultRecord> = {};
  const provider = input.provider ?? existing?.provider;
  const server = input.server ?? existing?.server;
  const settings = input.settings ?? existing?.settings;
  const bridge = input.source === 'process' && input.kind === 'mcp';
  if (input.url !== undefined) out.url = input.url;
  const kept =
    existing?.pinned === true &&
    input.url === undefined &&
    server === existing.server &&
    input.source !== 'oauth:mcp';
  if (kept) {
    out.url = existing.url;
    out.pinned = true;
  }
  if (bridge) out.sealedBy = input.uid as number;
  if (provider !== undefined) out.provider = provider;
  if (server !== undefined) out.server = server;
  if (settings !== undefined) out.settings = settings;
  return out;
}

async function keyed(tx: IDBTransaction, dek: Dek): Promise<void> {
  const keys = (await request(tx.objectStore('meta').get('keys'))) as Keys | undefined;
  if ((keys?.id ?? '') !== dek.id)
    throw new Refused('EAGAIN', 'the vault was re-keyed meanwhile; try again');
}

export async function seal(db: IDBDatabase, dek: Dek, input: SealInput): Promise<Sealing> {
  const [sealing] = await sealAll(db, dek, [input]);
  return sealing;
}

export async function sealAll(db: IDBDatabase, dek: Dek, inputs: SealInput[]): Promise<Sealing[]> {
  const sealed = await Promise.all(
    inputs.map((input) => encrypt(dek.key, input.value, aad(input.ns, input.kind, input.name)))
  );
  const stores: Store[] = inputs.some((input) => input.answers)
    ? ['records', 'audit', 'meta', 'requests']
    : ['records', 'audit', 'meta'];
  return transact(db, stores, 'readwrite', async (tx) => {
    await keyed(tx, dek);
    const out: Sealing[] = [];
    for (const [i, input] of inputs.entries()) out.push(await write(tx, input, sealed[i]));
    return out;
  });
}

async function write(tx: IDBTransaction, input: SealInput, sealed: Sealed): Promise<Sealing> {
  const store = tx.objectStore('records');
  const existing = (await request(store.get([input.ns, input.kind, input.name]))) as
    | VaultRecord
    | undefined;
  guard(existing, input);
  if (input.exclusive && existing?.server !== undefined && existing.server !== input.server) {
    throw new Refused(
      'EEXIST',
      `${input.name} belongs to another MCP server; give this one another name`
    );
  }
  const record: VaultRecord = {
    ns: input.ns,
    kind: input.kind,
    name: input.name,
    placeholder: existing
      ? kept(existing, input.placeholder)
      : await chosen(store, input.placeholder),
    sealed,
    source: input.source,
    createdAt: existing && !removed(existing) ? existing.createdAt : input.now,
    updatedAt: existing ? Math.max(input.now, existing.updatedAt + 1) : input.now,
    ...(input.expiresAt === undefined ? {} : { expiresAt: input.expiresAt }),
    ...(input.refresh === undefined ? {} : { refresh: input.refresh }),
    ...(input.oauth === undefined ? {} : { oauth: input.oauth }),
    ...bound(existing, input),
  };
  if (record.kind === 'model' && record.provider === undefined) {
    throw new Refused('EINVAL', 'a model record needs its provider');
  }
  await request(store.put(record));
  if (input.answers) await answered(tx, input.ns, input.answers, record.placeholder, input.now);
  await bump(tx, input.ns);
  const rotated = existing !== undefined && !removed(existing);
  await audit(tx, input.ns, {
    type: 'seal',
    name: input.name,
    uid: input.uid,
    tag: input.tag,
    source: input.source,
    rotated,
    at: input.now,
  });
  return { record, rotated };
}

export interface Rotation {
  record: VaultRecord;
  value?: string;
  expiresAt?: number | null;
}

export async function rotate(
  db: IDBDatabase,
  dek: Dek,
  ns: string,
  rotations: Rotation[],
  entry: Record<string, unknown>,
  now: number
): Promise<void> {
  const sealed = await Promise.all(
    rotations.map((r) =>
      r.value === undefined
        ? null
        : encrypt(dek.key, checkValue(r.value), aad(ns, r.record.kind, r.record.name))
    )
  );
  await transact(db, ['records', 'audit', 'meta'], 'readwrite', async (tx) => {
    await keyed(tx, dek);
    const store = tx.objectStore('records');
    for (const [i, rotation] of rotations.entries()) {
      const { record } = rotation;
      const current = (await request(store.get([ns, record.kind, record.name]))) as
        | VaultRecord
        | undefined;
      const same =
        current?.updatedAt === record.updatedAt &&
        current.placeholder === record.placeholder &&
        current.removedAt === undefined &&
        record.removedAt === undefined;
      if (!same) {
        throw new Refused('EAGAIN', `${record.name} changed meanwhile`);
      }
      const fresh = sealed[i];
      if (!fresh) continue;
      const { expiresAt: old, ...rest } = current;
      const kept = rotation.expiresAt === undefined ? old : rotation.expiresAt;
      const expiry = kept === null || kept === undefined ? {} : { expiresAt: kept };
      const updatedAt = Math.max(now, current.updatedAt + 1);
      await request(store.put({ ...rest, sealed: fresh, updatedAt, ...expiry }));
    }
    await bump(tx, ns);
    await audit(tx, ns, { ...entry, at: now });
  });
}

export async function bump(tx: IDBTransaction, ns: string): Promise<number> {
  const meta = tx.objectStore('meta');
  const next = (((await request(meta.get(`scrub:${ns}`))) as number | undefined) ?? 0) + 1;
  await request(meta.put(next, `scrub:${ns}`));
  return next;
}

export async function scrubIn(tx: IDBTransaction, ns: string): Promise<number> {
  return ((await request(tx.objectStore('meta').get(`scrub:${ns}`))) as number | undefined) ?? 0;
}

export function scrubVersion(db: IDBDatabase, ns: string): Promise<number> {
  return transact(db, ['meta'], 'readonly', (tx) => scrubIn(tx, ns));
}

export interface Backup {
  exportedAt: number | null;
  dismissed: boolean;
}

export function backupState(db: IDBDatabase, ns: string): Promise<Backup> {
  return transact(db, ['meta'], 'readonly', async (tx) => {
    const stored = (await request(tx.objectStore('meta').get(`backup:${ns}`))) as
      | Backup
      | undefined;
    return stored ?? { exportedAt: null, dismissed: false };
  });
}

export function dismissBackup(db: IDBDatabase, ns: string): Promise<Backup> {
  return transact(db, ['meta'], 'readwrite', async (tx) => {
    const meta = tx.objectStore('meta');
    const stored = (await request(meta.get(`backup:${ns}`))) as Backup | undefined;
    const next = { exportedAt: stored?.exportedAt ?? null, dismissed: true };
    await request(meta.put(next, `backup:${ns}`));
    return next;
  });
}

export function reminder(backup: Backup, secrets: boolean): BackupReminder {
  if (backup.exportedAt !== null || !secrets) return null;
  return backup.dismissed ? 'dismissed' : 'due';
}

export async function audit(
  tx: IDBTransaction,
  ns: string,
  entry: Record<string, unknown> & { at: number }
): Promise<void> {
  await request(tx.objectStore('audit').add({ ns, id: hex(random(8)), ...entry }));
}

export function rebind(
  db: IDBDatabase,
  ns: string,
  kind: RecordKind,
  name: string,
  bound: Binding,
  now: number
): Promise<VaultRecord> {
  return transact(db, ['records', 'audit', 'meta'], 'readwrite', async (tx) => {
    const store = tx.objectStore('records');
    const record = (await request(store.get([ns, kind, name]))) as VaultRecord | undefined;
    if (!record || removed(record)) throw new Refused('ENOENT', `no ${kind} record named ${name}`);
    if (kind === 'model' && bound.provider !== undefined && bound.provider !== record.provider) {
      const meta = tx.objectStore('meta');
      const endpoints = (await request(meta.get(`endpoints:${ns}`))) as
        | { page?: { custom: { name: string }[] } }
        | undefined;
      if (endpoints?.page?.custom.some((entry) => entry.name === name)) {
        const custom = endpoints.page.custom.filter((entry) => entry.name !== name);
        await request(
          meta.put({ ...endpoints, page: { ...endpoints.page, custom } }, `endpoints:${ns}`)
        );
      }
    }
    const next: VaultRecord = {
      ...record,
      ...bound,
      updatedAt: Math.max(now, record.updatedAt + 1),
    };
    if (record.pinned && next.server !== record.server) {
      delete next.url;
      delete next.pinned;
    }
    await request(store.put(next));
    await audit(tx, ns, {
      type: 'seal',
      name,
      source: 'settings',
      rotated: false,
      rebound: true,
      uid: null,
      tag: null,
      at: now,
    });
    return next;
  });
}

export function find(
  db: IDBDatabase,
  ns: string,
  kind: RecordKind,
  name: string
): Promise<VaultRecord | undefined> {
  return transact(db, ['records'], 'readonly', async (tx) => {
    return (await request(tx.objectStore('records').get([ns, kind, name]))) as
      | VaultRecord
      | undefined;
  });
}

export function records(db: IDBDatabase, ns: string): Promise<VaultRecord[]> {
  return transact(db, ['records'], 'readonly', (tx) => all<VaultRecord>(tx, 'records', ns));
}

export function withGrantBindings(held: VaultRecord[]): VaultRecord[] {
  const owners = new Map<string, VaultRecord[]>();
  for (const r of held) {
    if (r.kind === 'grant' || !r.refresh || removed(r)) continue;
    const key = `${r.source}\u0000${r.refresh}`;
    owners.set(key, [...(owners.get(key) ?? []), r]);
  }
  const agreed = (list: VaultRecord[], field: 'server' | 'provider') => {
    const values = new Set(list.map((r) => r[field]));
    return values.size === 1 ? [...values][0] : undefined;
  };
  return held.map((r) => {
    const list = r.kind === 'grant' ? owners.get(`${r.source}\u0000${r.name}`) : undefined;
    if (!list) return r;
    const { server: _server, provider: _provider, ...rest } = r;
    const server = agreed(list, 'server');
    const provider = agreed(list, 'provider');
    return {
      ...rest,
      ...(server === undefined ? {} : { server }),
      ...(provider === undefined ? {} : { provider }),
    };
  });
}

async function linked(
  store: IDBObjectStore,
  record: VaultRecord,
  now: number,
  removing: boolean
): Promise<string | null> {
  if (!record.refresh || record.kind === 'grant') return null;
  const grant = (await request(store.get([record.ns, 'grant', record.refresh]))) as
    | VaultRecord
    | undefined;
  if (!grant || grant.source !== record.source) return null;
  if (removing) {
    const all = (await request(store.getAll())) as VaultRecord[];
    const shared = all.some(
      (other) =>
        other.ns === record.ns &&
        other.kind !== 'grant' &&
        !(other.kind === record.kind && other.name === record.name) &&
        other.refresh === grant.name &&
        other.source === grant.source &&
        !removed(other)
    );
    if (shared) return null;
  }
  const gone = grant.removedAt !== undefined && now - grant.removedAt > RESTORABLE;
  if (gone || removed(grant) === removing) return null;
  const owner = `${record.kind}\u0000${record.name}`;
  if (!removing && grant.removedWith !== owner) return null;
  if (removing) {
    grant.removedAt = now;
    grant.removedWith = owner;
  } else {
    delete grant.removedAt;
    delete grant.removedWith;
  }
  grant.updatedAt = Math.max(now, grant.updatedAt + 1);
  await request(store.put(grant));
  return grant.name;
}

async function mark(
  db: IDBDatabase,
  ns: string,
  kind: RecordKind,
  name: string,
  now: number,
  removing: boolean
): Promise<VaultRecord> {
  return transact(db, ['records', 'audit', 'meta'], 'readwrite', async (tx) => {
    const store = tx.objectStore('records');
    const record = (await request(store.get([ns, kind, name]))) as VaultRecord | undefined;
    const gone = record?.removedAt !== undefined && now - record.removedAt > RESTORABLE;
    if (!record || gone) throw new Refused('ENOENT', `no record named ${name}`);
    if (removing === removed(record)) return record;
    if (removing) record.removedAt = now;
    else delete record.removedAt;
    delete record.removedWith;
    record.updatedAt = Math.max(now, record.updatedAt + 1);
    await request(store.put(record));
    const grant = await linked(store, record, now, removing);
    await bump(tx, ns);
    await audit(tx, ns, {
      type: removing ? 'remove' : 'restore',
      name,
      uid: null,
      tag: null,
      at: now,
      ...(grant ? { grant } : {}),
    });
    return record;
  });
}

export function remove(
  db: IDBDatabase,
  ns: string,
  name: string,
  now: number,
  kind: RecordKind = 'secret'
): Promise<VaultRecord> {
  return mark(db, ns, kind, name, now, true);
}

export function restore(
  db: IDBDatabase,
  ns: string,
  name: string,
  now: number,
  kind: RecordKind = 'secret'
): Promise<VaultRecord> {
  return mark(db, ns, kind, name, now, false);
}

export function purge(db: IDBDatabase, now: number): Promise<number> {
  return transact(db, ['records', 'meta'], 'readwrite', async (tx) => {
    const store = tx.objectStore('records');
    const stale = (await all<VaultRecord>(tx, 'records')).filter(
      (record) => record.removedAt !== undefined && now - record.removedAt > RESTORABLE
    );
    for (const record of stale) await request(store.delete([record.ns, record.kind, record.name]));
    for (const ns of new Set(stale.map((record) => record.ns))) await bump(tx, ns);
    return stale.length;
  });
}

export function placeholders(list: VaultRecord[], now: number): string[] {
  return list
    .filter((record) => !removed(record))
    .map((record) => record.placeholder)
    .sort();
}
