import type { ExitName, Rule, Stamp } from './contract.ts';
import { all, request, transact } from './db.ts';
import { Refused } from './errors.ts';
import { checkExit } from './forward.ts';
import { AMBIGUOUS, matches } from './inject.ts';
import { decrypt } from './keys.ts';
import { aad, audit, PLACEHOLDER, records, removed, type VaultRecord } from './records.ts';
import { refusedUrl } from './refusal.ts';
import { loadRegistered } from './rules.ts';
import { checkStamp } from './sealed.ts';
import type { Vault } from './vault.ts';

type Fields = Record<string, unknown>;

export const SESSION_DEADLINE = 60 * 1000;
const ID = /^[A-Za-z0-9_-]{16,128}$/;
const HOST = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/;
const METHOD = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const TARGET = /^\/[\x21-\x7e]*$/;

interface Asked {
  stamp: Stamp;
  session: string;
  rule: number;
  host: string;
  port: number;
  protocol: string;
  position: string;
  verified: boolean;
  handshakeAt: number;
  exit: ExitName;
  placeholders: string[];
  head: { method: string; target: string } | null;
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

function head(req: Fields): Asked['head'] {
  if (req.protocol !== 'http1') return null;
  const given = (req.head ?? {}) as Fields;
  const method = given.method;
  const target = given.path;
  if (typeof method !== 'string' || !METHOD.test(method)) invalid('head.method must be a method');
  if (typeof target !== 'string' || !TARGET.test(target)) {
    invalid('head.path must be the request target, starting with /');
  }
  return { method: method.toUpperCase(), target };
}

export function asked(req: Fields): Asked {
  const stamp = checkStamp(req.stamp);
  if (stamp.users !== 'enforce') throw new Refused('EACCES', 'kernel users must be enforce');
  if (typeof req.session !== 'string' || !ID.test(req.session)) {
    invalid('session must be 16 to 128 characters of A-Z, a-z, 0-9, _ and -');
  }
  if (!integer(req.rule, 1, 1e6)) invalid('rule must be a rule number');
  const host = typeof req.host === 'string' ? req.host.toLowerCase().replace(/\.$/, '') : '';
  if (!HOST.test(host)) invalid('host must be the host name the kernel verified');
  if (!integer(req.port, 1, 65535)) invalid('port must be from 1 to 65535');
  if (typeof req.protocol !== 'string' || typeof req.position !== 'string') {
    invalid('protocol and position must be strings');
  }
  if (typeof req.verified !== 'boolean') invalid('verified must be a boolean');
  if (!integer(req.handshakeAt, 0, Number.MAX_SAFE_INTEGER)) invalid('handshakeAt must be a time');
  const list = req.placeholders;
  if (!Array.isArray(list) || list.length === 0 || list.length > 16) {
    invalid('placeholders must be a list of 1 to 16 placeholders');
  }
  if (!list.every((item) => typeof item === 'string' && PLACEHOLDER.test(item))) {
    invalid('placeholders must be vault placeholders');
  }
  return {
    stamp,
    session: req.session,
    rule: req.rule,
    host,
    port: req.port,
    protocol: req.protocol,
    position: req.position,
    verified: req.verified,
    handshakeAt: req.handshakeAt,
    exit: checkExit(req.exit),
    placeholders: [...new Set(list as string[])],
    head: head(req),
  };
}

export function positionOf(rule: Rule): string {
  return rule.protocol === 'http1' ? `header:${rule.header}` : (rule.position as string);
}

function expired(record: VaultRecord, now: number): boolean {
  return record.expiresAt !== undefined && record.expiresAt <= now;
}

export class Sessions {
  readonly vault: Vault;
  readonly used = new Map<string, number>();

  constructor(vault: Vault) {
    this.vault = vault;
  }

  sweep(now: number): void {
    for (const [key, until] of this.used) if (now >= until) this.used.delete(key);
  }

  burn(ns: string, ask: Asked, now: number): void {
    const key = JSON.stringify([ns, ask.session]);
    if (this.used.has(key)) fail('this session already had its request');
    this.used.set(key, now + SESSION_DEADLINE);
  }

  async allowed(ns: string, ask: Asked) {
    const policy = await this.vault.loadPolicy(ns);
    const found = policy.rule(ask.rule);
    if (!found) fail(`rule ${ask.rule} of /etc/fnox/config.toml isn't in effect`);
    const { secret, rule } = found;
    const where = `${ask.protocol} ${ask.position} on ${ask.host}:${ask.port}`;
    if (
      rule.protocol !== ask.protocol ||
      rule.domain !== ask.host ||
      rule.port !== ask.port ||
      positionOf(rule) !== ask.position
    ) {
      fail(`rule ${ask.rule} doesn't allow ${secret} at ${where}`);
    }
    if (ask.head) {
      const registered = await loadRegistered(this.vault.db, ns);
      const raw = ask.head.target.split(/[?#]/)[0];
      if (AMBIGUOUS.test(raw)) fail(`ambiguous path ${raw}`);
      const url = new URL(`https://${ask.host}${ask.head.target}`);
      if (refusedUrl(registered, url)) {
        fail(`${ask.host} is a model or MCP endpoint; the vault never injects there`);
      }
      if (!matches(rule, ask.head.method, ask.host, url.pathname, rule.header)) {
        fail(`rule ${ask.rule} doesn't allow ${secret} for ${ask.head.method} ${url.pathname}`);
      }
    }
    const exits = policy.exits(secret);
    if (exits && !exits.includes(ask.exit)) {
      fail(`${secret} isn't allowed on ${ask.exit} (/etc/slicc/secrets-policy.toml)`);
    }
    return { ...found, policy };
  }

  async materialize(ns: string, req: Fields): Promise<Fields> {
    const ask = asked(req);
    const now = this.vault.now();
    this.sweep(now);
    this.burn(ns, ask, now);
    if (!ask.verified) fail("the kernel didn't verify the session's host");
    if (ask.handshakeAt > now || now - ask.handshakeAt > SESSION_DEADLINE) {
      fail('the session is past its 60 s deadline');
    }
    const key = this.vault.keyring.key;
    if (!key) throw new Refused('EACCES', 'vault is locked: unlock it in the vault window');
    const { secret, rule, policy } = await this.allowed(ns, ask);
    const values: Record<string, string> = Object.create(null);
    for (const record of await records(this.vault.db, ns)) {
      const wanted =
        record.kind === 'secret' &&
        record.name === secret &&
        ask.placeholders.includes(record.placeholder) &&
        policy.placeholder(secret) === record.placeholder;
      if (!wanted || removed(record) || expired(record, now)) continue;
      values[record.placeholder] = await decrypt(
        key,
        record.sealed,
        aad(record.ns, record.kind, record.name)
      );
    }
    await this.record(ns, ask, secret, rule, Object.keys(values).length > 0, now);
    return { values: Object.fromEntries(Object.entries(values)) };
  }

  async record(ns: string, ask: Asked, secret: string, rule: Rule, used: boolean, now: number) {
    await transact(this.vault.db, ['records', 'audit'], 'readwrite', async (tx) => {
      const history = await all<{ type: string; session?: string }>(tx, 'audit', ns);
      if (history.some((entry) => entry.type === 'session' && entry.session === ask.session)) {
        fail('this session already had its request');
      }
      if (!used) return;
      const store = tx.objectStore('records');
      const stored = (await request(store.get([ns, 'secret', secret]))) as VaultRecord;
      await request(store.put({ ...stored, usedAt: now }));
      await audit(tx, ns, {
        type: 'session',
        name: secret,
        session: ask.session,
        domain: ask.host,
        port: ask.port,
        protocol: rule.protocol,
        position: ask.position,
        rule: ask.rule,
        exit: ask.exit,
        uid: ask.stamp.uid,
        tag: ask.stamp.tag,
        at: now,
      });
    });
    if (used) await this.vault.changed(ns, ['secrets', 'audit']);
  }
}
