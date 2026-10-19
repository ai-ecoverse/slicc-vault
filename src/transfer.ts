import { base64url, random, text, unbase64url, utf8 } from './bytes.ts';
import type {
  ImportCandidate,
  ImportKind,
  RecordKind,
  RecordSource,
  SealResult,
} from './contract.ts';
import { request, transact } from './db.ts';
import { Refused } from './errors.ts';
import { type Dek, decrypt, ITERATIONS } from './keys.ts';
import {
  aad,
  type Binding,
  binding,
  checkValue,
  NAME,
  PLACEHOLDER,
  records,
  SOURCE,
  seal,
  state,
  type VaultRecord,
} from './records.ts';
import type { Vault } from './vault.ts';

export const FORMAT = 'slicc-vault-bundle';
export const MIN_PASSPHRASE = 12;
const BUNDLED: RecordKind[] = ['secret', 'model', 'mcp'];

type Fields = Record<string, unknown>;

export interface Item {
  name: string;
  value: string;
  kind: RecordKind;
  source: RecordSource;
  placeholder?: string;
  expiresAt?: number;
  rules?: string;
  bound?: Binding;
  invalid?: string;
}

interface Bundled {
  name: string;
  kind: RecordKind;
  value: string;
  placeholder: string;
  source: RecordSource;
  createdAt: number;
  expiresAt?: number;
  provider?: string;
  server?: string;
  settings?: Record<string, string>;
}

function passphrase(value: unknown): string {
  if (typeof value !== 'string' || [...value].length < MIN_PASSPHRASE) {
    throw new Refused('EINVAL', `the passphrase needs at least ${MIN_PASSPHRASE} characters`);
  }
  return value;
}

async function key(
  secret: string,
  salt: Uint8Array<ArrayBuffer>,
  iterations: number
): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey('raw', utf8(secret), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function seal64(
  items: Bundled[],
  secret: string,
  iterations = ITERATIONS
): Promise<Uint8Array> {
  const salt = random(16);
  const iv = random(12);
  const plain = utf8(JSON.stringify({ records: items }));
  const data = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: utf8(FORMAT) },
    await key(secret, salt, iterations),
    plain
  );
  const bundle = {
    format: FORMAT,
    v: 1,
    kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations, salt: base64url(salt) },
    cipher: { name: 'AES-GCM', iv: base64url(iv) },
    data: base64url(new Uint8Array(data)),
  };
  return utf8(JSON.stringify(bundle));
}

export async function open64(bytes: Uint8Array, secret: string): Promise<Bundled[]> {
  let bundle: Fields;
  try {
    bundle = JSON.parse(text(bytes));
  } catch {
    throw new Refused('EINVAL', "this isn't a vault backup");
  }
  const kdf = (bundle?.kdf ?? {}) as Fields;
  const cipher = (bundle?.cipher ?? {}) as Fields;
  const iterations = kdf.iterations;
  const valid =
    bundle?.format === FORMAT &&
    bundle.v === 1 &&
    typeof bundle.data === 'string' &&
    typeof kdf.salt === 'string' &&
    typeof cipher.iv === 'string' &&
    typeof iterations === 'number' &&
    Number.isInteger(iterations) &&
    iterations >= 100000 &&
    iterations <= 10000000;
  if (!valid) throw new Refused('EINVAL', "this isn't a vault backup");
  let plain: ArrayBuffer;
  try {
    const derived = await key(secret, unbase64url(kdf.salt as string), iterations as number);
    plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: unbase64url(cipher.iv as string), additionalData: utf8(FORMAT) },
      derived,
      unbase64url(bundle.data as string)
    );
  } catch {
    throw new Refused('EACCES', "that passphrase doesn't open this backup");
  }
  const parsed = JSON.parse(text(plain)) as { records?: Bundled[] };
  return Array.isArray(parsed.records) ? parsed.records : [];
}

export function nameOf(title: string): string {
  const name = title
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9_]+/g, '_')
    .replace(/^_+|_+$/g, '');
  return /^[0-9]/.test(name) ? `_${name}` : name;
}

export function parseSix(source: string): Item[] {
  const values = new Map<string, string>();
  const domains = new Map<string, string[]>();
  for (const raw of source.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const match = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!match) continue;
    const value = match[2].replace(/^(['"])(.*)\1$/, '$2');
    if (match[1].endsWith('_DOMAINS'))
      domains.set(
        match[1].slice(0, -8),
        value
          .split(',')
          .map((d) => d.trim())
          .filter(Boolean)
      );
    else values.set(match[1], value);
  }
  return [...values].map(([name, value]) => {
    const list = domains.get(name) ?? [];
    const exact = list.filter((domain) => !domain.includes('*'));
    const wild = list.filter((domain) => domain.includes('*'));
    const stanzas = exact.map(
      (domain) => `[[proxy.rules]]\nsecret = "${name}"\ndomain = "${domain}"\n`
    );
    const notes = wild.map(
      (domain) => `# ${domain} is a wildcard and isn't carried over: list exact hosts\n`
    );
    const rules = [...stanzas, ...notes].join('\n');
    return {
      name,
      value,
      kind: 'secret' as const,
      source: 'import:six' as const,
      ...(rules ? { rules } : {}),
    };
  });
}

async function keepass(bytes: Uint8Array, password: unknown): Promise<Item[]> {
  if (typeof password !== 'string')
    throw new Refused('EINVAL', 'a KeePass import needs its master password');
  const { entries } = await import('./keepass.ts');
  let found: { title: string; value: string }[];
  try {
    found = await entries(bytes, password);
  } catch {
    throw new Refused('EACCES', "that password doesn't open this KeePass file");
  }
  const used = new Set<string>();
  const unique = (title: string) => {
    const base = nameOf(title);
    let name = base;
    for (let n = 2; used.has(name); n++) name = `${base}_${n}`;
    used.add(name);
    return name;
  };
  return found
    .filter((entry) => entry.value)
    .map((entry) => ({
      name: unique(entry.title),
      value: entry.value,
      kind: 'secret' as const,
      source: 'import:keepass' as const,
    }));
}

async function items(kind: ImportKind, bytes: Uint8Array, password: unknown): Promise<Item[]> {
  if (kind === 'six') return parseSix(text(bytes));
  if (kind === 'keepass') return keepass(bytes, password);
  const opened = await open64(bytes, passphrase(password));
  return opened
    .filter(
      (entry) =>
        BUNDLED.includes(entry.kind) &&
        typeof entry.value === 'string' &&
        typeof entry.name === 'string'
    )
    .map((entry) => ({
      name: entry.name,
      value: entry.value,
      kind: entry.kind,
      source:
        typeof entry.source === 'string' && SOURCE.test(entry.source)
          ? entry.source
          : ('import:bundle' as const),
      placeholder: entry.placeholder,
      ...(typeof entry.expiresAt === 'number' ? { expiresAt: entry.expiresAt } : {}),
      ...bindingOf(entry),
    }));
}

function bindingOf(entry: Bundled): Pick<Item, 'bound' | 'invalid'> {
  try {
    return { bound: binding(entry.kind, entry as unknown as Record<string, unknown>) };
  } catch (error) {
    return { invalid: (error as Error).message };
  }
}

export function problem(
  item: Item,
  held: VaultRecord[],
  taken: Set<string> = new Set()
): string | null {
  if (!NAME.test(item.name) || item.name.length > 128) return 'not a valid name';
  if (item.invalid) return item.invalid;
  const providedHere = held.some((r) => r.kind === 'model' && r.name === item.name && r.provider);
  if (item.kind === 'model' && !item.bound?.provider && !providedHere) {
    return 'a model record needs its provider';
  }
  try {
    checkValue(item.value);
  } catch (error) {
    return (error as Error).message;
  }
  if (item.placeholder === undefined) return null;
  if (!PLACEHOLDER.test(item.placeholder))
    return "the file is damaged: this secret's placeholder isn't valid";
  if (taken.has(item.placeholder))
    return 'another app that uses this vault already has this secret; use it there, or add it here by hand';
  const same = held.find((r) => r.placeholder === item.placeholder);
  if (same && (same.name !== item.name || same.kind !== item.kind))
    return 'this app already has this secret under another name';
  const named = held.find((r) => r.name === item.name && r.kind === item.kind);
  if (named && named.placeholder !== item.placeholder)
    return 'this app already has a different secret with this name';
  return null;
}

function candidate(item: Item, held: VaultRecord[], taken: Set<string>): ImportCandidate {
  const reason = problem(item, held, taken);
  return {
    name: item.name,
    kind: item.kind,
    exists: held.some((r) => r.name === item.name && r.kind === item.kind),
    ...(item.rules ? { suggestedRules: item.rules } : {}),
    ...(reason ? { refused: reason } : {}),
  };
}

function elsewhere(db: IDBDatabase, ns: string): Promise<Set<string>> {
  return transact(db, ['records'], 'readonly', async (tx) => {
    const all = (await request(tx.objectStore('records').getAll())) as VaultRecord[];
    return new Set(all.filter((r) => r.ns !== ns).map((r) => r.placeholder));
  });
}

function identity(kind: string, name: string): string {
  return `${kind}\0${name}`;
}

function picks(value: unknown): Map<string, string> {
  if (!Array.isArray(value))
    throw new Refused('EINVAL', 'pick must be a list of names or { name, kind }');
  const out = new Map<string, string>();
  for (const entry of value) {
    const item =
      typeof entry === 'string' ? { name: entry, kind: 'secret' } : (entry as Fields | null);
    if (typeof item?.name !== 'string' || typeof item.kind !== 'string') {
      throw new Refused('EINVAL', 'pick must be a list of names or { name, kind }');
    }
    out.set(identity(item.kind, item.name), item.name);
  }
  return out;
}

async function store(vault: Vault, ns: string, dek: Dek, item: Item): Promise<VaultRecord | null> {
  try {
    const { record } = await seal(vault.db, dek, {
      ns,
      kind: item.kind,
      name: item.name,
      value: item.value,
      source: item.source,
      uid: null,
      tag: null,
      now: vault.now(),
      ...(item.expiresAt === undefined ? {} : { expiresAt: item.expiresAt }),
      ...(item.placeholder === undefined ? {} : { placeholder: item.placeholder }),
      ...item.bound,
    });
    return record;
  } catch {
    return null;
  }
}

export async function importer(vault: Vault, ns: string, req: Fields): Promise<Fields> {
  const kind = req.kind as ImportKind;
  if (!['bundle', 'keepass', 'six'].includes(kind))
    throw new Refused('EINVAL', 'kind must be bundle, keepass or six');
  if (!(req.bytes instanceof Uint8Array)) throw new Refused('EINVAL', 'bytes must be the file');
  const dek = vault.keyring.use();
  const found = await items(kind, req.bytes, req.password);
  const held = await records(vault.db, ns);
  const taken = await elsewhere(vault.db, ns);
  if (req.pick === undefined) {
    return { stage: 'pick', candidates: found.map((item) => candidate(item, held, taken)) };
  }
  const picked = picks(req.pick);
  const imported: SealResult[] = [];
  const skipped: string[] = [];
  const reasons: Record<string, string> = Object.create(null);
  const outcomes: Fields[] = [];
  const skip = (name: string, reason: string, kind?: RecordKind) => {
    skipped.push(name);
    reasons[name] = reason;
    outcomes.push({ name, ...(kind ? { kind } : {}), imported: false, reason });
  };
  for (const item of found) {
    if (!picked.has(identity(item.kind, item.name))) continue;
    const reason = problem(item, held, taken);
    if (reason) {
      skip(item.name, reason, item.kind);
      continue;
    }
    const record = await store(vault, ns, dek, item);
    if (!record) {
      skip(item.name, "it couldn't be stored; try again", item.kind);
      continue;
    }
    imported.push({
      name: record.name,
      placeholder: record.placeholder,
      state: state(record, vault.policy(ns), vault.now()),
    });
    outcomes.push({ name: record.name, kind: record.kind, imported: true });
  }
  for (const [id, name] of picked) {
    if (!found.some((item) => identity(item.kind, item.name) === id))
      skip(name, "it isn't in the file");
  }
  if (imported.length) await vault.changed(ns, ['secrets', 'audit']);
  return {
    stage: 'done',
    imported,
    skipped,
    reasons: Object.fromEntries(Object.entries(reasons)),
    outcomes,
  };
}

function underlying(record: VaultRecord): VaultRecord {
  if (!record.replaced) return record;
  const pasted: VaultRecord = { ...record, ...record.replaced };
  if (record.replaced.expiresAt === undefined) delete pasted.expiresAt;
  return pasted;
}

export async function exporter(vault: Vault, ns: string, req: Fields): Promise<Fields> {
  const secret = passphrase(req.passphrase);
  const dek = vault.keyring.require();
  const held = (await records(vault.db, ns)).filter(
    (r) => BUNDLED.includes(r.kind) && r.removedAt === undefined
  );
  const items: Bundled[] = [];
  for (const stored of held) {
    const record = underlying(stored);
    items.push({
      name: record.name,
      kind: record.kind,
      value: await decrypt(dek, record.sealed, aad(record.ns, record.kind, record.name)),
      placeholder: record.placeholder,
      source: record.source,
      createdAt: record.createdAt,
      ...(record.expiresAt === undefined ? {} : { expiresAt: record.expiresAt }),
      ...(record.provider === undefined ? {} : { provider: record.provider }),
      ...(record.server === undefined ? {} : { server: record.server }),
      ...(record.settings === undefined ? {} : { settings: record.settings }),
    });
  }
  const bundle = await seal64(items, secret);
  await transact(vault.db, ['meta'], 'readwrite', async (tx) => {
    const meta = tx.objectStore('meta');
    const stored = ((await request(meta.get(`backup:${ns}`))) as Fields | undefined) ?? {
      dismissed: false,
    };
    await request(meta.put({ ...stored, exportedAt: vault.now() }, `backup:${ns}`));
  });
  await vault.changed(ns, []);
  return { bundle, count: items.length };
}
