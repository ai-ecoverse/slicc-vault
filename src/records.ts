import { hex, random } from './bytes.ts';
import type {
  BackupReminder,
  RecordKind,
  RecordSource,
  RecordState,
  Rule,
  SecretView,
} from './contract.ts';
import { all, request, transact } from './db.ts';
import { Refused } from './errors.ts';
import { type Dek, encrypt, type Keys, type Sealed } from './keys.ts';
import type { Policy } from './policy.ts';

export const NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
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
  removedAt?: number;
}

export interface OAuthConfig {
  tokenUrl: string;
  clientId: string;
  scope?: string;
  resource?: string;
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
  placeholder?: string;
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

export function view(record: VaultRecord, policy: Policy, now: number): SecretView {
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
  if (!existing || removed(existing)) return;
  if (existing.source === 'process' || input.uid === 0 || input.source !== 'process') return;
  throw new Refused(
    'EEXIST',
    `${input.name} holds a value entered outside a program; replace it with sudo fnox set`
  );
}

export async function seal(db: IDBDatabase, dek: Dek, input: SealInput): Promise<Sealing> {
  const sealed = await encrypt(dek.key, input.value, aad(input.ns, input.kind, input.name));
  return transact(db, ['records', 'audit', 'meta'], 'readwrite', async (tx) => {
    const keys = (await request(tx.objectStore('meta').get('keys'))) as Keys | undefined;
    if ((keys?.id ?? '') !== dek.id) {
      throw new Refused('EAGAIN', 'the vault was re-keyed meanwhile; try again');
    }
    const store = tx.objectStore('records');
    const existing = (await request(store.get([input.ns, input.kind, input.name]))) as
      | VaultRecord
      | undefined;
    guard(existing, input);
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
      updatedAt: input.now,
      ...(input.expiresAt === undefined ? {} : { expiresAt: input.expiresAt }),
      ...(input.refresh === undefined ? {} : { refresh: input.refresh }),
      ...(input.oauth === undefined ? {} : { oauth: input.oauth }),
    };
    await request(store.put(record));
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
  });
}

export async function bump(tx: IDBTransaction, ns: string): Promise<number> {
  const meta = tx.objectStore('meta');
  const next = (((await request(meta.get(`scrub:${ns}`))) as number | undefined) ?? 0) + 1;
  await request(meta.put(next, `scrub:${ns}`));
  return next;
}

export function scrubVersion(db: IDBDatabase, ns: string): Promise<number> {
  return transact(db, ['meta'], 'readonly', async (tx) => {
    return ((await request(tx.objectStore('meta').get(`scrub:${ns}`))) as number | undefined) ?? 0;
  });
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
    if (removing) record.removedAt = now;
    else delete record.removedAt;
    await request(store.put(record));
    await bump(tx, ns);
    await audit(tx, ns, {
      type: removing ? 'remove' : 'restore',
      name,
      uid: null,
      tag: null,
      at: now,
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
