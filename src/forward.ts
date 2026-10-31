import type { Scrubber, Stream } from '@ai-ecoverse/slicc-scrub';
import type { ExitName } from './contract.ts';
import { all, request, transact } from './db.ts';
import { Refused } from './errors.ts';
import { type Head, type Injection, type Prepared, prepare, type Traits } from './inject.ts';
import { MAX_BODY } from './prepare.ts';
import { audit, records, removed, scrubIn, type VaultRecord } from './records.ts';
import { holds, type McpServer, mcpServer, modelRefused, refusedUrl, tofu } from './refusal.ts';
import { loadRegistered, migrate, pin, policyIn } from './rules.ts';
import { checkStamp } from './sealed.ts';
import type { Vault } from './vault.ts';

type Fields = Record<string, unknown>;

const EXIT = /^(?:page|proxy|tailscale|device:[A-Za-z0-9._:-]+)$/;

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

function moved(injected: Injection[], live: VaultRecord[]): boolean {
  return injected.some(({ record }) => {
    const found = live.find((r) => r.kind === record.kind && r.name === record.name);
    return (
      !found ||
      removed(found) ||
      found.placeholder !== record.placeholder ||
      found.updatedAt !== record.updatedAt ||
      found.unpins !== record.unpins
    );
  });
}

async function record(
  vault: Vault,
  ns: string,
  prepared: Extract<Prepared, { ok: true }>,
  uid: number,
  tag: string | null,
  exit: ExitName
) {
  const now = vault.now();
  const method = prepared.head.method.toUpperCase();
  await transact(vault.db, ['records', 'audit'], 'readwrite', async (tx) => {
    const store = tx.objectStore('records');
    for (const injection of prepared.injected) {
      const kind = prepared.server ? 'mcp' : 'secret';
      const stored = (await request(store.get([ns, kind, injection.name]))) as
        | VaultRecord
        | undefined;
      if (stored) await request(store.put({ ...stored, usedAt: now }));
      await audit(tx, ns, {
        type: prepared.server ? 'mcp' : 'forward',
        name: injection.name,
        domain: prepared.host,
        method,
        path: prepared.path,
        rule: injection.rule,
        exit,
        uid,
        tag,
        ...(prepared.server ? { server: prepared.server.server } : {}),
        at: now,
      });
    }
  });
}

export function relay(
  port: MessagePort,
  scrubber: Scrubber,
  succeeded: () => void = () => {},
  credit = false
): void {
  const stream: Stream = scrubber.stream();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const text = (value: unknown) => (typeof value === 'string' ? scrubber.text(value).text : '');
  const send = (chunk: Uint8Array) => {
    if (chunk.length) port.postMessage({ op: 'body', chunk }, [chunk.buffer]);
  };
  const finish = (message: Fields) => {
    clearTimeout(timer);
    port.postMessage(message);
    port.close();
  };
  port.onmessage = (event: MessageEvent) => {
    const data = (event.data ?? {}) as Fields;
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
      timer = setTimeout(() => send(stream.idle()), scrubber.idleMs);
    } else if (data.op === 'end') {
      send(stream.end());
      finish({ op: 'end' });
    } else if (data.op === 'error') {
      send(stream.end());
      finish({ op: 'error', message: text(data.message) });
    }
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
  const [held, registered] = await Promise.all([
    records(vault.db, ns),
    loadRegistered(vault.db, ns),
  ]);
  const prepared = await prepare({
    ns,
    head,
    owner,
    exit,
    traits,
    records: held,
    policy: await vault.loadPolicy(ns),
    registered,
    key: vault.keyring.key,
    now: vault.now(),
    holdsAnother: (found, value) => vault.scrubbers.holdsAnother(ns, found, value),
  });
  if (!prepared.ok) return { refused: { status: prepared.status, reason: prepared.reason } };
  const body = prepared.server ? bodyOf(fields.body) : null;
  const unready = prepared.server ? unsendable(fields.bodyPresent, body) : null;
  if (unready) return unready;
  const scrubber = (await vault.scrubbers.get(ns)) as Scrubber;
  const current = async () => {
    const [{ policy, registered: fresh }, live, version] = await transact(
      vault.db,
      ['meta', 'records'],
      'readonly',
      (tx) => Promise.all([policyIn(tx, ns), all<VaultRecord>(tx, 'records', ns), scrubIn(tx, ns)])
    );
    if (version !== scrubber.version || moved(prepared.injected, live)) return false;
    const url = new URL(head.url);
    const server = prepared.server;
    if (!server) return !refusedUrl(fresh, url) && !policy.paused();
    const now = mcpServer(fresh, url);
    return (
      now?.server === server.server &&
      now.url === server.url &&
      !modelRefused(fresh, url) &&
      prepared.injected.every((injection) => {
        const found = live.find((r) => r.kind === 'mcp' && r.name === injection.name);
        return !!found && holds(fresh, now, found);
      })
    );
  };
  const stale = {
    refused: { status: 403, reason: 'the endpoints changed meanwhile; send it again' },
  };
  if (!(await current())) return stale;
  await record(vault, ns, prepared, owner.uid, owner.tag, exit);
  await vault.changed(ns, ['audit']);
  const server = prepared.server;
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
  const scrubbed = server && body ? { body: scrubber.bytes(body).bytes } : {};
  if (!(await current())) return stale;
  if (port) relay(port, scrubber, succeeded, fields.streamCredit === true);
  return server
    ? { mode: 'mcp', head: prepared.head, bodyComplete: true, ...scrubbed }
    : { mode: 'secret', head: prepared.head };
}
