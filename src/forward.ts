import type { Scrubber, Stream } from '@ai-ecoverse/slicc-scrub';
import type { ExitName, Stamp } from './contract.ts';
import { all, request, transact } from './db.ts';
import { caused, Refused } from './errors.ts';
import { type Head, type Prepared, prepare, type Traits } from './inject.ts';
import { MAX_BODY } from './prepare.ts';
import { atVersion, audit, records, scrubIn, scrubVersion, type VaultRecord } from './records.ts';
import { type McpServer, tofu } from './refusal.ts';
import { loadRegistered, migrate, pin, policyIn } from './rules.ts';
import { checkStamp } from './sealed.ts';
import type { Vault } from './vault.ts';

type Fields = Record<string, unknown>;

const EXIT = /^(?:page|proxy|tailscale|device:[A-Za-z0-9._:-]+)$/;
const CANCELLED = "the vault's values changed; send the request again";

export function checkHead(value: unknown): Head {
  const head = (value ?? {}) as Fields;
  const headers = head.headers;
  const valid =
    typeof head.method === 'string' &&
    /^[A-Za-z]+$/.test(head.method) &&
    typeof head.url === 'string' &&
    Array.isArray(headers) &&
    headers.every(
      (pair) =>
        Array.isArray(pair) && pair.length === 2 && pair.every((part) => typeof part === 'string')
    );
  if (!valid) throw new Refused('EINVAL', 'head must be { method, url, headers: [name, value][] }');
  return {
    method: head.method as string,
    url: head.url as string,
    headers: headers as [string, string][],
  };
}

export function checkTraits(value: unknown): Traits {
  const traits = (value ?? {}) as Fields;
  return {
    manualRedirects: traits.manualRedirects === true,
    encodedBodies: traits.encodedBodies === true,
  };
}

export function checkExit(value: unknown): ExitName {
  if (typeof value !== 'string' || !EXIT.test(value)) {
    throw new Refused('EINVAL', 'exit must be page, proxy, tailscale or device:<id>');
  }
  return value as ExitName;
}

function bodyOf(value: unknown): Uint8Array | null {
  if (value === undefined || value === null) return null;
  if (typeof value === 'string') return new TextEncoder().encode(value);
  if (value instanceof Uint8Array) return value;
  throw new Refused('EINVAL', 'body must be bytes or a string');
}

function unsendable(present: unknown, body: Uint8Array | null): Fields | null {
  if (typeof present !== 'boolean') {
    return { refused: { status: 400, reason: 'an MCP request must say whether it has a body' } };
  }
  if (present && !body) return { needsBody: true };
  if (!present && body) {
    return {
      refused: { status: 400, reason: 'an MCP request that says it has no body carries one' },
    };
  }
  if (body && body.byteLength > MAX_BODY) {
    throw new Refused('EINVAL', 'request bodies are at most 32 MiB');
  }
  return null;
}

type Ready = Extract<Prepared, { ok: true }>;

async function stateIn(tx: IDBTransaction, ns: string) {
  const [{ policy, registered, accepted }, live, version] = await Promise.all([
    policyIn(tx, ns),
    all<VaultRecord>(tx, 'records', ns),
    scrubIn(tx, ns),
  ]);
  const held = live.map((r) => [
    r.kind,
    r.name,
    r.placeholder,
    r.updatedAt,
    r.unpins,
    r.removedAt,
    r.expiresAt,
    r.url,
  ]);
  const print = JSON.stringify([accepted, registered, version, held]);
  return { policy, registered, live, version, print };
}

function shape(prepared: Ready): string {
  const { head, injected, server } = prepared;
  const used = injected.map(({ name, record }) => [
    record.kind,
    name,
    record.placeholder,
    record.updatedAt,
    record.unpins,
  ]);
  return JSON.stringify([head, used, server?.server, server?.url]);
}

async function record(
  vault: Vault,
  ns: string,
  prepared: Ready,
  owner: Stamp,
  exit: ExitName,
  scrubber: Scrubber,
  still: (print: string) => boolean
): Promise<boolean> {
  const now = vault.now();
  const clean = (text: string) => scrubber.text(text).text;
  const method = clean(prepared.head.method.toUpperCase());
  const { uid, tag } = owner;
  const tidy = (value: unknown): unknown => {
    if (typeof value === 'string') return clean(value);
    if (Array.isArray(value)) return value.map(tidy);
    if (!value || typeof value !== 'object') return value;
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, tidy(item)]));
  };
  return transact(vault.db, ['meta', 'records', 'audit'], 'readwrite', async (tx) => {
    const expired = prepared.injected.some(
      ({ record }) => record.expiresAt !== undefined && record.expiresAt <= now
    );
    if (expired || !still((await stateIn(tx, ns)).print)) return false;
    const store = tx.objectStore('records');
    for (const injection of prepared.injected) {
      const kind = prepared.server ? 'mcp' : 'secret';
      const stored = (await request(store.get([ns, kind, injection.name]))) as
        | VaultRecord
        | undefined;
      if (stored) await request(store.put({ ...stored, usedAt: now }));
      await audit(tx, ns, {
        type: prepared.server ? 'mcp' : 'forward',
        name: clean(injection.name),
        domain: clean(prepared.host),
        method,
        path: clean(prepared.path),
        rule: tidy(injection.rule),
        exit: clean(exit),
        uid,
        tag: tidy(tag),
        ...(prepared.server ? { server: clean(prepared.server.server) } : {}),
        at: now,
      });
    }
    return true;
  });
}

export function relay(
  port: MessagePort,
  scrubber: Scrubber,
  succeeded: () => void = () => {},
  credit = false,
  guard: (work: () => void, stale: () => void) => void | Promise<void> = (work) => work()
): void {
  const stream: Stream = scrubber.stream();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let turn = Promise.resolve();
  let seen = 0;
  let done = false;
  const text = (value: unknown) => (typeof value === 'string' ? scrubber.text(value).text : '');
  const send = (chunk: Uint8Array) => {
    if (chunk.length) port.postMessage({ op: 'body', chunk }, [chunk.buffer]);
  };
  const finish = (message: Fields) => {
    done = true;
    clearTimeout(timer);
    port.onmessage = null;
    port.postMessage(message);
    port.close();
  };
  const cancel = () => {
    if (!done) finish({ op: 'error', message: CANCELLED });
  };
  const inOrder = (work: () => void) => {
    const step = async () => {
      if (done) return;
      await guard(() => {
        if (!done) work();
      }, cancel);
    };
    turn = turn.then(step).catch(cancel);
  };
  const handle = (data: Fields) => {
    clearTimeout(timer);
    if (data.op === 'response') {
      if (typeof data.status === 'number' && data.status >= 200 && data.status < 300) succeeded();
      const headers = Array.isArray(data.headers) ? (data.headers as unknown[][]) : [];
      port.postMessage({
        op: 'response',
        status: data.status,
        statusText: text(data.statusText),
        url: text(data.url),
        redirected: data.redirected === true,
        headers: headers.map((pair) => [text(pair[0]), text(pair[1])]),
      });
    } else if (data.op === 'body' && data.chunk instanceof Uint8Array) {
      const bytes = data.chunk.byteLength;
      send(stream.push(data.chunk));
      if (credit) port.postMessage({ op: 'credit', bytes });
      const armed = seen;
      timer = setTimeout(() => {
        inOrder(() => {
          if (armed === seen) send(stream.idle());
        });
      }, scrubber.idleMs);
    } else if (data.op === 'end') {
      send(stream.end());
      finish({ op: 'end' });
    } else if (data.op === 'error') {
      send(stream.end());
      finish({ op: 'error', message: text(data.message) });
    }
  };
  port.onmessage = (event: MessageEvent) => {
    const data = (event.data ?? {}) as Fields;
    seen += 1;
    clearTimeout(timer);
    inOrder(() => handle(data));
  };
  port.start();
}

export async function forward(
  vault: Vault,
  ns: string,
  fields: Fields,
  port?: MessagePort
): Promise<Fields> {
  const owner = checkStamp(fields.owner);
  const head = checkHead(fields.head);
  const exit = checkExit(fields.exit);
  const traits = checkTraits(fields.rawTraits);
  const early = await vault.scrubbers.get(ns);
  const tidy = early ? (text: string) => early.text(text).text : null;
  if (tidy && (await migrate(vault.db, ns, vault.now(), tidy))) {
    await vault.loadPolicy(ns);
    await vault.changed(ns, ['secrets', 'audit', 'exits']);
  }
  const epoch = vault.scrubbers.epoch(ns);
  const started = await scrubVersion(vault.db, ns);
  const [held, registered] = await Promise.all([
    records(vault.db, ns),
    loadRegistered(vault.db, ns),
  ]);
  const asked = {
    ns,
    head,
    owner,
    exit,
    traits,
    holdsAnother: (found: VaultRecord, value: string) =>
      vault.scrubbers.holdsAnother(ns, found, value),
  };
  const prepared = await prepare({
    ...asked,
    records: held,
    policy: await vault.loadPolicy(ns),
    registered,
    key: vault.keyring.key,
    now: vault.now(),
  });
  if (!prepared.ok) {
    const { status, reason, cause } = prepared;
    return { refused: { status, reason, ...caused(cause) } };
  }
  const server = prepared.server;
  const body = server ? bodyOf(fields.body) : null;
  const unready = server ? unsendable(fields.bodyPresent, body) : null;
  if (unready) return unready;
  const scrubber = (await vault.scrubbers.get(ns)) as Scrubber;
  const same = () => vault.scrubbers.epoch(ns) === epoch;
  const guard = (work: () => void, stale: () => void) =>
    atVersion(vault.db, ns, scrubber.version, () => (same() ? work() : stale()), stale);
  const stale = {
    refused: { status: 403, reason: 'the endpoints changed meanwhile; send it again' },
  };
  if (scrubber.version !== started) return stale;
  const scrubbed = server && body ? { body: scrubber.bytes(body).bytes } : {};
  const state = await transact(vault.db, ['meta', 'records'], 'readonly', (tx) => stateIn(tx, ns));
  const again = await prepare({
    ...asked,
    records: state.live,
    policy: state.policy,
    registered: state.registered,
    key: vault.keyring.key,
    now: vault.now(),
  });
  const fresh = state.version === scrubber.version && again.ok && shape(again) === shape(prepared);
  const unchanged = (print: string) => same() && print === state.print;
  if (!fresh || !(await record(vault, ns, prepared, owner, exit, scrubber, unchanged))) {
    return stale;
  }
  const names = server
    ? prepared.injected
        .map((injection) => held.find((r) => r.kind === 'mcp' && r.name === injection.name))
        .filter((r): r is VaultRecord => !!r && tofu(registered, server, r))
        .map((r) => r.name)
    : [];
  const clean = (text: string) => scrubber.text(text).text;
  const succeeded = () => {
    if (!names.length) return;
    void pin(vault.db, ns, names, server as McpServer, vault.now(), clean).then((done) =>
      done.pinned ? vault.changed(ns, ['secrets', 'audit']) : undefined
    );
  };
  if (port) relay(port, scrubber, succeeded, fields.streamCredit === true, guard);
  await vault.changed(ns, ['audit']);
  return server
    ? { mode: 'mcp', head: prepared.head, bodyComplete: true, ...scrubbed }
    : { mode: 'secret', head: prepared.head };
}
