import type { ExitName, Rule, Stamp } from './contract.ts';
import { request, transact } from './db.ts';
import { Refused } from './errors.ts';
import { checkExit } from './forward.ts';
import { AMBIGUOUS, matches } from './inject.ts';
import { decrypt } from './keys.ts';
import type { Policy } from './policy.ts';
import { aad, audit, PLACEHOLDER, records, removed, type VaultRecord } from './records.ts';
import { type Registered, refusedUrl } from './refusal.ts';
import { policyIn } from './rules.ts';
import { clientProof, parseScram, SCRAM_CANDIDATES, type Scram, same } from './scram.ts';
import { checkStamp } from './sealed.ts';
import type { Vault } from './vault.ts';

type Fields = Record<string, unknown>;

export const SESSION_DEADLINE = 60 * 1000;
const ID = /^[A-Za-z0-9_-]{16,128}$/;
const HOST = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/;
const METHOD = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const TARGET = /^\/[\x21-\x7e]*$/;
const POSITIONS: Record<string, RegExp> = {
  http1: /^header:[!#$%&'*+.^_`|~0-9a-z-]+$/,
  smtp: /^(?:auth-plain|auth-login)$/,
  pg: /^(?:password-cleartext|scram-sha-256)$/,
};

interface Asked {
  stamp: Stamp;
  session: string;
  host: string;
  port: number;
  protocol: string;
  position: string;
  verified: boolean;
  handshakeAt: number;
  exit: ExitName;
  placeholders: string[];
  head: { method: string; target: string; path: string } | null;
  scram: Scram | null;
  verifiedBy: 'roots' | 'anchored';
  anchor: string | null;
  ids: Map<string, string>;
}

interface Target {
  stamp: Stamp;
  session: string;
  host: string;
  port: number;
  protocol: 'http1' | 'smtp' | 'pg';
  exit: ExitName;
}

const PIN = /^[A-Za-z0-9+/]{43}=$/;

interface Handed {
  record: VaultRecord;
  index: number;
  value: string;
}

function invalid(message: string): never {
  throw new Refused('EINVAL', message);
}

function fail(why: string): never {
  throw new Refused('EACCES', `session refused: ${why}`);
}

function integer(value: unknown, min: number, max: number): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= min && value <= max;
}

function head(req: Fields, host: string): Asked['head'] {
  if (req.protocol !== 'http1') return null;
  const given = (req.head ?? {}) as Fields;
  const method = given.method;
  const target = given.path;
  if (typeof method !== 'string' || !METHOD.test(method)) invalid('head.method must be a method');
  if (typeof target !== 'string' || !TARGET.test(target)) {
    invalid('head.path must be the request target, starting with /');
  }
  const path = new URL(`https://${host}${target}`).pathname;
  return { method: method.toUpperCase(), target, path };
}

export function target(req: Fields): Target {
  const stamp = checkStamp(req.stamp);
  if (stamp.users !== 'enforce') throw new Refused('EACCES', 'kernel users must be enforce');
  if (typeof req.session !== 'string' || !ID.test(req.session)) {
    invalid('session must be 16 to 128 characters of A-Z, a-z, 0-9, _ and -');
  }
  const host = typeof req.host === 'string' ? req.host.toLowerCase().replace(/\.$/, '') : '';
  if (!HOST.test(host)) invalid('host must be the host name the kernel verified');
  if (!integer(req.port, 1, 65535)) invalid('port must be from 1 to 65535');
  const protocol = req.protocol;
  if (protocol !== 'http1' && protocol !== 'smtp' && protocol !== 'pg') {
    invalid('protocol must be http1, smtp or pg');
  }
  return { stamp, session: req.session, host, port: req.port, protocol, exit: checkExit(req.exit) };
}

function trustOf(req: Fields): Pick<Asked, 'verifiedBy' | 'anchor'> {
  const verifiedBy = req.verifiedBy ?? 'roots';
  if (verifiedBy === 'roots') {
    if (req.anchor !== undefined) invalid('only an anchored session names its anchor');
    return { verifiedBy, anchor: null };
  }
  if (verifiedBy !== 'anchored') invalid("verifiedBy must be 'roots' or 'anchored'");
  if (typeof req.anchor !== 'string' || !PIN.test(req.anchor)) {
    invalid('anchor must be base64 of the 32-byte SHA-256 of the anchor or pin used');
  }
  return { verifiedBy, anchor: req.anchor };
}

export function asked(req: Fields): Asked {
  const { stamp, host, protocol, exit } = target(req);
  if (typeof req.position !== 'string' || !POSITIONS[protocol].test(req.position)) {
    invalid(`position isn't a ${protocol} position`);
  }
  if (typeof req.verified !== 'boolean') invalid('verified must be a boolean');
  if (!integer(req.handshakeAt, 0, Number.MAX_SAFE_INTEGER)) invalid('handshakeAt must be a time');
  const scram = req.position === 'scram-sha-256' ? parseScram(req.scram) : null;
  if (scram && req.placeholders !== undefined) {
    invalid('a scram-sha-256 session names no placeholders: the proof does');
  }
  if (!scram && req.scram !== undefined) invalid('only a scram-sha-256 session has scram');
  const list = scram ? [] : req.placeholders;
  if (!scram && (!Array.isArray(list) || list.length === 0 || list.length > 16)) {
    invalid('placeholders must be a list of 1 to 16 placeholders');
  }
  if (!(list as unknown[]).every((item) => typeof item === 'string' && PLACEHOLDER.test(item))) {
    invalid('placeholders must be vault placeholders');
  }
  return {
    stamp,
    session: req.session as string,
    host,
    port: req.port as number,
    protocol,
    position: req.position,
    verified: req.verified,
    handshakeAt: req.handshakeAt,
    exit,
    ...trustOf(req),
    ids: new Map(),
    placeholders: [...new Set(list as string[])],
    head: head(req, host),
    scram,
  };
}

export function positionOf(rule: Rule): string {
  return rule.protocol === 'http1' ? `header:${rule.header}` : (rule.position as string);
}

function expired(record: VaultRecord, now: number): boolean {
  return record.expiresAt !== undefined && record.expiresAt <= now;
}

function fits(rule: Rule, ask: Asked): boolean {
  const same =
    rule.protocol === ask.protocol &&
    rule.domain === ask.host &&
    rule.port === ask.port &&
    positionOf(rule) === ask.position;
  if (!same || !ask.head) return same;
  return matches(rule, ask.head.method, ask.host, ask.head.path, rule.header);
}

function trusts(rule: Rule, ask: Asked): boolean {
  const anchored = rule.anchors !== undefined || rule.pins !== undefined;
  if (ask.verifiedBy === 'roots') return !anchored || rule.roots === true;
  const ids = [...(rule.pins ?? []), ...(rule.anchors ?? []).map((der) => ask.ids.get(der))];
  return ids.includes(ask.anchor as string);
}

async function digest(der: string): Promise<string> {
  const bytes = Uint8Array.from(atob(der), (char) => char.charCodeAt(0));
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return btoa(String.fromCharCode(...hash));
}

function current(stored: VaultRecord | undefined, seen: VaultRecord, now: number): boolean {
  return (
    stored !== undefined &&
    stored.placeholder === seen.placeholder &&
    stored.updatedAt === seen.updatedAt &&
    !removed(stored) &&
    !expired(stored, now)
  );
}

export class Sessions {
  readonly vault: Vault;
  prove = clientProof;

  constructor(vault: Vault) {
    this.vault = vault;
  }

  async burn(ns: string, ask: Asked, now: number): Promise<void> {
    await transact(this.vault.db, ['meta'], 'readwrite', async (tx) => {
      const meta = tx.objectStore('meta');
      const key = `sessions:${ns}`;
      const stored = ((await request(meta.get(key))) ?? {}) as Record<string, number>;
      const used = Object.fromEntries(Object.entries(stored).filter(([, until]) => until >= now));
      if (Object.hasOwn(used, ask.session)) fail('this session already had its request');
      used[ask.session] = Math.max(now, ask.handshakeAt) + SESSION_DEADLINE;
      await request(meta.put(used, key));
    });
  }

  timely(ask: Asked, now: number): void {
    if (ask.handshakeAt > now || now - ask.handshakeAt > SESSION_DEADLINE) {
      fail('the session is past its 60 s deadline');
    }
  }

  endpoint(ask: Asked, registered: Registered): void {
    if (!ask.head) return;
    const raw = ask.head.target.split(/[?#]/)[0];
    if (AMBIGUOUS.test(raw)) fail(`ambiguous path ${raw}`);
    if (refusedUrl(registered, new URL(`https://${ask.host}${ask.head.path}`))) {
      fail(`${ask.host} is a model or MCP endpoint; the vault never injects there`);
    }
  }

  pick(record: VaultRecord | undefined, policy: Policy, ask: Asked, now: number): number {
    if (!record) fail('a placeholder of no record of this vault');
    const name = record.name;
    if (record.kind !== 'secret') fail(`${name} isn't a secret`);
    if (policy.placeholder(name) !== record.placeholder) {
      fail(`${name}'s placeholder isn't the one /etc/fnox/config.toml names`);
    }
    if (removed(record)) fail(`${name} was removed`);
    if (expired(record, now)) fail(`${name} expired`);
    const rules = policy.sessionRules(name);
    if (!rules.length) fail(`no session rule in /etc/fnox/config.toml lets ${name} be used`);
    const fitting = rules.filter((entry) => fits(entry.rule, ask));
    const where = `${ask.protocol} ${ask.position} on ${ask.host}:${ask.port}`;
    const what = ask.head ? ` for ${ask.head.method} ${ask.head.path}` : '';
    if (!fitting.length) fail(`no session rule lets ${name} at ${where}${what}`);
    const found = fitting.find((entry) => trusts(entry.rule, ask));
    if (!found && ask.verifiedBy === 'roots') {
      fail(`${name}'s session rule accepts only its anchors and pins, not public roots`);
    }
    if (!found) fail(`the anchor that verified the session isn't one of ${name}'s session rule`);
    const exits = policy.exits(name);
    if (exits && !exits.includes(ask.exit)) {
      fail(`${name} isn't allowed on ${ask.exit} (/etc/slicc/secrets-policy.toml)`);
    }
    return found.index;
  }

  still(stored: VaultRecord | undefined, policy: Policy, ask: Asked, now: number): number | null {
    try {
      return this.pick(stored, policy, ask, now);
    } catch {
      return null;
    }
  }

  async prover(
    held: Map<string, VaultRecord>,
    policy: Policy,
    ask: Asked,
    now: number
  ): Promise<string[]> {
    const candidates = [...held].filter(
      ([, record]) => this.still(record, policy, ask, now) !== null
    );
    if (candidates.length > SCRAM_CANDIDATES) {
      fail(`more than ${SCRAM_CANDIDATES} session rules' placeholders to try for SCRAM`);
    }
    const found: string[] = [];
    for (const [placeholder] of candidates) {
      const proof = await this.prove(placeholder, ask.scram as Scram);
      if (same(proof, (ask.scram as Scram).proof)) found.push(placeholder);
    }
    if (found.length === 0) fail("no session rule's placeholder matches the SCRAM proof");
    if (found.length > 1) fail('more than one placeholder matches the SCRAM proof');
    return found;
  }

  async anchors(ns: string, req: Fields): Promise<Fields> {
    const want = target(req);
    const policy = await this.vault.loadPolicy(ns);
    const anchors = new Set<string>();
    const pins = new Set<string>();
    for (const { secret, rule } of policy.everySessionRule()) {
      const exits = policy.exits(secret);
      const same =
        rule.protocol === want.protocol && rule.domain === want.host && rule.port === want.port;
      if (!same || (exits && !exits.includes(want.exit))) continue;
      for (const der of rule.anchors ?? []) anchors.add(der);
      for (const pin of rule.pins ?? []) pins.add(pin);
    }
    return { anchors: [...anchors], pins: [...pins] };
  }

  async materialize(ns: string, req: Fields): Promise<Fields> {
    const ask = asked(req);
    const now = this.vault.now();
    await this.burn(ns, ask, now);
    if (!ask.verified) fail("the kernel didn't verify the session's host");
    this.timely(ask, now);
    const key = this.vault.keyring.key;
    if (!key) throw new Refused('EACCES', 'vault is locked: unlock it in the vault window');
    const { policy, registered } = await transact(this.vault.db, ['meta'], 'readonly', (tx) =>
      policyIn(tx, ns)
    );
    this.endpoint(ask, registered);
    for (const { rule } of policy.everySessionRule()) {
      for (const der of rule.anchors ?? []) ask.ids.set(der, await digest(der));
    }
    const held = new Map((await records(this.vault.db, ns)).map((r) => [r.placeholder, r]));
    if (ask.scram) ask.placeholders = await this.prover(held, policy, ask, now);
    const handed: Handed[] = [];
    const reasons: string[] = [];
    for (const placeholder of ask.placeholders) {
      const record = held.get(placeholder);
      try {
        const index = this.pick(record, policy, ask, now);
        const seen = record as VaultRecord;
        const value = await decrypt(key, seen.sealed, aad(seen.ns, seen.kind, seen.name));
        handed.push({ record: seen, index, value });
      } catch (error) {
        if (!(error instanceof Refused)) throw error;
        reasons.push(error.message);
      }
    }
    const kept = await this.record(ns, ask, handed, key);
    if (!kept.length) {
      throw new Refused(
        'EACCES',
        reasons[0] ?? 'session refused: the secret or its rule changed meanwhile'
      );
    }
    return { values: Object.fromEntries(kept.map((h) => [h.record.placeholder, h.value])) };
  }

  async record(ns: string, ask: Asked, handed: Handed[], key: CryptoKey): Promise<Handed[]> {
    const kept: Handed[] = [];
    await transact(this.vault.db, ['meta', 'records', 'audit'], 'readwrite', async (tx) => {
      const { policy, registered } = await policyIn(tx, ns);
      const now = this.vault.now();
      this.timely(ask, now);
      this.endpoint(ask, registered);
      const store = tx.objectStore('records');
      for (const entry of handed) {
        const { record } = entry;
        const stored = (await request(store.get([ns, 'secret', record.name]))) as
          | VaultRecord
          | undefined;
        const index = current(stored, record, now) ? this.still(stored, policy, ask, now) : null;
        if (index === null) continue;
        kept.push({ ...entry, index });
        await request(store.put({ ...stored, usedAt: now }));
        await audit(tx, ns, {
          type: 'session',
          name: record.name,
          session: ask.session,
          domain: ask.host,
          port: ask.port,
          protocol: ask.protocol,
          position: ask.position,
          rule: index,
          verifiedBy: ask.verifiedBy,
          ...(ask.anchor === null ? {} : { anchor: ask.anchor }),
          exit: ask.exit,
          uid: ask.stamp.uid,
          tag: ask.stamp.tag,
          at: now,
        });
      }
      if (this.vault.keyring.key !== key) {
        throw new Refused('EACCES', 'vault is locked: unlock it in the vault window');
      }
    });
    if (kept.length) await this.vault.changed(ns, ['secrets', 'audit']);
    return kept;
  }
}
