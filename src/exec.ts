import type { Scrubber } from '@ai-ecoverse/slicc-scrub';
import { hex, random, utf8 } from './bytes.ts';
import type { ExecMode, Stamp } from './contract.ts';
import { all, request, transact } from './db.ts';
import { Refused } from './errors.ts';
import { decrypt } from './keys.ts';
import { type Policy, running } from './policy.ts';
import { aad, audit, checkName, records, removed, type VaultRecord } from './records.ts';
import { policyIn } from './rules.ts';
import type { Vault } from './vault.ts';

export const TICKET_LIFETIME = 30 * 1000;
export const ARGV_SHOWN = 200;
const MINUTE = 60 * 1000;
const DAY = 24 * 60 * MINUTE;

const WRAPPERS = /^(env|printenv|xargs|sudo|su|nohup|timeout|time|nice|strace)$/;

function basename(path: string): string {
  return path.slice(path.lastIndexOf('/') + 1);
}

export const REFUSED_PROGRAMS = [
  /^(sh|bash|dash|zsh|fish|busybox|jsh)$/,
  /^python[0-9.]*$/,
  /^(node|deno|bun|perl|ruby|php|lua|wasmer)$/,
  /^([gmn]?awk|sed|tclsh|expect|R|Rscript|irb)$/,
  WRAPPERS,
];

type Fields = Record<string, unknown>;

export interface Ticket {
  ticket: string;
  ns: string;
  names: string[];
  path: string;
  argv: string[];
  cwd: string;
  pid: number;
  interpreter: string | null;
  expiresAt: number;
}

interface Asked {
  names: string[];
  shellGrants: boolean;
  path: string;
  argv: string[];
  cwd: string;
  interpreter: string | null;
}

interface StoredReveal {
  seq: number;
  ns: string;
  type: string;
  name: string;
  uid: number | null;
  exec: ExecMode;
  at: number;
}

function absolute(value: unknown, field: string): string {
  if (typeof value !== 'string' || !value.startsWith('/') || value.includes('\0')) {
    throw new Refused('EINVAL', `${field} must be an absolute path`);
  }
  return value;
}

function strings(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || !value.every((item) => typeof item === 'string')) {
    throw new Refused('EINVAL', `${field} must be a list of strings`);
  }
  return value as string[];
}

export function asked(req: Fields): Asked {
  const shellGrants = req.shellGrants === true;
  const names = req.names === undefined && shellGrants ? [] : strings(req.names, 'names');
  if (!shellGrants && names.length === 0)
    throw new Refused('EINVAL', 'names must be a non-empty list');
  names.forEach(checkName);
  const argv = strings(req.argv, 'argv');
  if (argv.length === 0) throw new Refused('EINVAL', 'argv must include argv[0]');
  const interpreter =
    req.interpreter === undefined ? null : absolute(req.interpreter, 'interpreter');
  return {
    names: [...new Set(names)],
    shellGrants,
    path: absolute(req.path, 'path'),
    argv,
    cwd: absolute(req.cwd, 'cwd'),
    interpreter,
  };
}

export function refusedProgram(path: string): boolean {
  return REFUSED_PROGRAMS.some((pattern) => pattern.test(basename(path)));
}

export function listed(prefixes: string[][], path: string, argv: string[]): boolean {
  const line = [path, ...argv.slice(1)];
  return prefixes.some(
    (prefix) => prefix.length <= line.length && prefix.every((part, i) => line[i] === part)
  );
}

export async function argvSha256(argv: string[]): Promise<string> {
  const bytes = utf8(argv.map((arg) => `${arg}\0`).join(''));
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
}

export interface Ran {
  resolved: string;
  interpreters: string[];
  trusted: boolean;
}

const UNTRUSTED = 'the program or its interpreter can be changed by a non-root user';

export function allowedChain(policy: Policy, name: string, path: string, ran: Ran): string | null {
  const mode = policy.exec(name);
  if (mode === 'shell') return null;
  const { resolved, interpreters, trusted } = ran;
  if (mode === 'argv') {
    const wrapper = interpreters.find((program) => WRAPPERS.test(basename(program)));
    if (wrapper) return `${name} isn't revealed to ${wrapper}: env and other wrappers stay refused`;
    if (trusted || ![resolved, ...interpreters].some(refusedProgram)) return null;
    return `${name} isn't revealed: ${UNTRUSTED}`;
  }
  const blocked = [path, resolved, ...interpreters].find(refusedProgram);
  if (blocked) return `${name} isn't revealed to ${blocked}`;
  return trusted ? null : `${name} isn't revealed: ${UNTRUSTED}`;
}

function real(policy: Policy, name: string, ask: Asked): boolean {
  const mode = policy.exec(name);
  if (mode === 'shell') return true;
  if (mode === 'argv') return listed(policy.argv(name) as string[][], ask.path, ask.argv);
  if (mode !== 'any') return false;
  const programs = [ask.path, ...(ask.interpreter ? [ask.interpreter] : [])];
  if (programs.some(refusedProgram)) {
    throw new Refused(
      'EACCES',
      `${name} isn't revealed to ${programs.find(refusedProgram)}: shells, interpreters and env dumpers need an exact argv in [exec]`
    );
  }
  return true;
}

function limit(
  policy: Policy,
  name: string,
  uid: number,
  history: StoredReveal[],
  now: number
): void {
  const mine = history.filter((entry) => entry.name === name && entry.uid === uid);
  const limits = policy.limits();
  const day = mine.filter((entry) => now - entry.at < DAY).length;
  if (policy.exec(name) === 'shell') {
    if (day >= limits.shell_per_day) {
      throw new Refused('EAGAIN', `materialize limit for ${name} (${limits.shell_per_day}/day)`);
    }
    return;
  }
  const minute = mine.filter((entry) => now - entry.at < MINUTE).length;
  if (minute >= limits.materialize_per_minute) {
    throw new Refused(
      'EAGAIN',
      `materialize limit for ${name} (${limits.materialize_per_minute}/min)`
    );
  }
  if (day >= limits.materialize_per_day) {
    throw new Refused(
      'EAGAIN',
      `materialize limit for ${name} (${limits.materialize_per_day}/day)`
    );
  }
}

function shown(argv: string[], redact: (text: string) => string): string {
  const text = redact(argv.join(' '));
  return text.length > ARGV_SHOWN ? `${text.slice(0, ARGV_SHOWN - 1)}…` : text;
}

const ENFORCE = 'kernel users must be enforce';

function fail(why: string): never {
  throw new Refused('EACCES', `ticket refused: ${why}`);
}

function matching(found: Ticket, req: Fields, now: number): void {
  const stamp = req.stamp as Partial<Stamp>;
  const argv = Array.isArray(req.argv) ? req.argv : null;
  if (now >= found.expiresAt) fail('expired');
  if (stamp.ppid !== found.pid) fail("the exec'ing process isn't a child of the one that asked");
  if (req.path !== found.path) fail('another program');
  if (!argv || argv.length !== found.argv.length || argv.some((a, i) => a !== found.argv[i])) {
    fail('another argv');
  }
  if (req.cwd !== found.cwd) fail('another cwd');
}

function chainOf(found: Ticket, req: Fields): Ran {
  const resolved = req.resolved;
  if (typeof resolved !== 'string' || !resolved.startsWith('/')) {
    fail('the kernel sent no resolved program');
  }
  const chain = req.interpreters;
  if (!Array.isArray(chain) || !chain.every((p) => typeof p === 'string' && p.startsWith('/'))) {
    fail('the kernel sent no interpreter chain');
  }
  const interpreters = chain as string[];
  if (typeof req.trusted !== 'boolean') fail('the kernel sent no trusted flag');
  if (found.interpreter !== null && found.interpreter !== interpreters[0]) {
    fail("fnox's interpreter isn't the one the kernel resolved");
  }
  return { resolved, interpreters, trusted: req.trusted as boolean };
}

function granted(policy: Policy, found: Ticket, ran: Ran): void {
  for (const name of found.names) {
    const mode = policy.exec(name);
    if (mode === false) fail(`${name} is no longer granted in [exec]`);
    const prefixes = (mode === 'argv' ? policy.argv(name) : []) as string[][];
    if (mode === 'argv' && !listed(prefixes, found.path, found.argv)) {
      fail(`${name}'s [exec] grant no longer lists this command`);
    }
    const linked = ran.resolved !== found.path && refusedProgram(ran.resolved);
    if (mode === 'argv' && linked && !listed(prefixes, ran.resolved, found.argv)) {
      fail(`${name} isn't revealed to ${ran.resolved}: list it in [exec] by its real path`);
    }
    const blocked = allowedChain(policy, name, found.path, ran);
    if (blocked) fail(blocked);
  }
}

function expired(record: VaultRecord, now: number): boolean {
  return record.expiresAt !== undefined && record.expiresAt <= now;
}

export class Exec {
  readonly vault: Vault;
  readonly tickets = new Map<string, Ticket>();

  constructor(vault: Vault) {
    this.vault = vault;
  }

  async materialize(ns: string, req: Fields, stamp: Stamp): Promise<Fields> {
    if (stamp.users !== 'enforce') throw new Refused('EACCES', ENFORCE);
    this.sweep(this.vault.now());
    const ask = asked(req);
    const policy = running(await this.vault.loadPolicy(ns));
    if (this.vault.keyring.locked)
      throw new Refused('EACCES', 'vault is locked: unlock it in the vault window');
    const names = [...new Set([...ask.names, ...(ask.shellGrants ? policy.shells() : [])])];
    const held = new Map(
      (await records(this.vault.db, ns)).filter((r) => r.kind === 'secret').map((r) => [r.name, r])
    );
    const answer: Record<string, boolean> = Object.create(null);
    for (const name of names) {
      const record = held.get(name);
      if (!record) throw new Refused('ENOENT', `no record named ${name}`);
      if (expired(record, this.vault.now()))
        throw new Refused('EACCES', `${name} expired; refreshing`);
      answer[name] = !removed(record) && real(policy, name, ask);
    }
    const now = this.vault.now();
    const revealed = names.filter((name) => answer[name]);
    const scrubber = (await this.vault.scrubbers.get(ns)) as Scrubber;
    const redact = (text: string) => scrubber.text(text).text;
    const sha = await argvSha256(ask.argv);
    const ticket = hex(random(16));
    await transact(this.vault.db, ['audit'], 'readwrite', async (tx) => {
      const history = (await all<StoredReveal>(tx, 'audit', ns)).filter(
        (e) => e.type === 'materialize'
      );
      for (const name of revealed) limit(policy, name, stamp.uid, history, now);
      for (const name of revealed) {
        await audit(tx, ns, {
          type: 'materialize',
          name,
          exec: policy.exec(name),
          path: ask.path,
          argv: shown(ask.argv, redact),
          argvSha256: sha,
          cwd: ask.cwd,
          pid: stamp.pid,
          ppid: stamp.ppid,
          uid: stamp.uid,
          tag: stamp.tag,
          ticket,
          consumed: false,
          at: now,
        });
      }
    });
    const expiresAt = now + TICKET_LIFETIME;
    this.tickets.set(ticket, {
      ticket,
      ns,
      names: revealed,
      path: ask.path,
      argv: ask.argv,
      cwd: ask.cwd,
      pid: stamp.pid,
      interpreter: ask.interpreter,
      expiresAt,
    });
    if (revealed.length) await this.vault.changed(ns, ['audit']);
    return { ticket, expiresAt, real: Object.fromEntries(Object.entries(answer)) };
  }

  async consume(ns: string, req: Fields): Promise<Fields> {
    const id = typeof req.ticket === 'string' ? req.ticket : '';
    const found = this.tickets.get(id);
    this.tickets.delete(id);
    if (!found || found.ns !== ns) return fail('unknown or already used');
    if ((req.stamp as Partial<Stamp> | undefined)?.users !== 'enforce') fail(ENFORCE);
    matching(found, req, this.vault.now());
    const { policy, accepted } = await transact(this.vault.db, ['meta'], 'readonly', (tx) =>
      policyIn(tx, ns)
    );
    if (policy.paused()) this.tickets.set(id, found);
    running(policy);
    granted(policy, found, chainOf(found, req));
    const key = this.vault.keyring.key;
    if (!key) throw new Refused('EACCES', 'vault is locked: unlock it in the vault window');
    const held = await records(this.vault.db, ns);
    const values: Record<string, string> = Object.create(null);
    for (const name of found.names) {
      const record = held.find((r) => r.kind === 'secret' && r.name === name) as
        | VaultRecord
        | undefined;
      if (!record || removed(record)) continue;
      if (expired(record, this.vault.now())) fail(`${name} expired`);
      values[name] = await decrypt(key, record.sealed, aad(record.ns, record.kind, record.name));
    }
    await this.mark(ns, found, JSON.stringify(accepted));
    return {
      values: Object.fromEntries(Object.entries(values)),
      placeholders: Object.fromEntries(
        held
          .filter((r) => r.name in values && r.kind === 'secret')
          .map((r) => [r.name, r.placeholder])
      ),
    };
  }

  async mark(ns: string, found: Ticket, print: string): Promise<void> {
    await transact(this.vault.db, ['meta', 'audit'], 'readwrite', async (tx) => {
      const { policy, accepted } = await policyIn(tx, ns);
      if (JSON.stringify(accepted) !== print) {
        this.tickets.set(found.ticket, found);
        running(policy);
        throw new Refused('EACCES', 'ticket refused: the policy changed meanwhile');
      }
      const store = tx.objectStore('audit');
      for (const entry of await all<StoredReveal & { ticket: string }>(tx, 'audit', ns)) {
        if (entry.type === 'materialize' && entry.ticket === found.ticket) {
          await request(store.put({ ...entry, consumed: true }));
        }
      }
    });
    await this.vault.changed(ns, ['audit']);
  }

  sweep(now: number): void {
    for (const [id, ticket] of this.tickets) if (now >= ticket.expiresAt) this.tickets.delete(id);
  }
}
