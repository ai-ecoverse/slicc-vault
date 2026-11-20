import type { Hit, Scrubber } from '@ai-ecoverse/slicc-scrub';
import { bytesOf } from './bytes.ts';
import { Refused } from './errors.ts';
import { Preparer } from './prepare.ts';
import { concat, Rescan, watch } from './rescan.ts';
import { register } from './rules.ts';
import type { Vault } from './vault.ts';

type Fields = Record<string, unknown>;

export const MAX_STREAMS = 64;
const SANITIZED = new Set(['model', 'mcp', 'records', 'grant', 'refresh']);
const CHANGED = "the vault's values changed; open the stream again and push from its start";
const LOCKED = 'vault is locked: unlock it in the vault window to continue';
const UNSCRUBBED = "the vault can't scrub this answer: its values are over its size limit";
const FIXED = new Set([CHANGED, LOCKED]);

export class AgentPort {
  readonly vault: Vault;
  readonly ns: string;
  readonly streams = new Map<string, { rescan: Rescan; turn: Promise<unknown> }>();
  readonly preparer: Preparer;

  constructor(vault: Vault, ns: string) {
    this.vault = vault;
    this.ns = ns;
    this.preparer = new Preparer(vault, ns);
  }

  async scrubber(): Promise<Scrubber> {
    const scrubber = await this.vault.scrubbers.get(this.ns);
    if (!scrubber) throw new Refused('EACCES', LOCKED);
    return scrubber;
  }

  async redact(fields: Fields): Promise<Fields> {
    const given = fields.texts;
    const texts = Array.isArray(given)
      ? given.map((t) => (typeof t === 'string' ? t : bytesOf(t)))
      : [null];
    if (texts.includes(null)) {
      throw new Refused('EINVAL', 'texts must be a list of strings and bytes');
    }
    const scrubber = await this.scrubber();
    const hits: Hit[] = [];
    const out = (texts as (string | Uint8Array)[]).map((item) => {
      const result = typeof item === 'string' ? scrubber.text(item) : scrubber.bytes(item);
      hits.push(...result.hits);
      return 'text' in result ? result.text : result.bytes;
    });
    return { texts: out, hits: merge(hits), version: scrubber.version };
  }

  id(fields: Fields): string {
    if (
      typeof fields.stream !== 'string' ||
      fields.stream.length === 0 ||
      fields.stream.length > 128
    ) {
      throw new Refused('EINVAL', 'stream must be an id string');
    }
    return fields.stream;
  }

  async open(fields: Fields): Promise<Fields> {
    const id = this.id(fields);
    if (this.streams.size >= MAX_STREAMS && !this.streams.has(id)) {
      throw new Refused('EAGAIN', `at most ${MAX_STREAMS} streams are open`);
    }
    const epoch = this.vault.scrubbers.epoch(this.ns);
    let scrubber: Scrubber;
    let rescan: Rescan;
    try {
      scrubber = await this.scrubber();
      rescan = new Rescan(scrubber, watch(this.vault, this.ns, epoch));
    } catch (error) {
      if (error instanceof Refused) throw error;
      throw new Refused('EAGAIN', CHANGED);
    }
    this.streams.set(id, { rescan, turn: Promise.resolve() });
    return { stream: id, idleMs: scrubber.idleMs, version: scrubber.version };
  }

  async step(fields: Fields, work: (rescan: Rescan) => Fields, last = false): Promise<Fields> {
    const id = this.id(fields);
    const found = this.streams.get(id);
    if (!found) throw new Refused('ENOENT', 'no such stream');
    const run = async () => {
      if (this.streams.get(id) !== found) throw new Refused('ENOENT', 'no such stream');
      let out: Fields = {};
      const held = await found.rescan
        .at((swapped) => {
          if (last && this.streams.get(id) === found) this.streams.delete(id);
          const reply = work(found.rescan);
          out = {
            ...reply,
            chunk: concat(swapped, reply.chunk as Uint8Array),
            version: found.rescan.current.version,
          };
        })
        .catch(() => false);
      if (held) return out;
      if (this.streams.get(id) === found) this.streams.delete(id);
      throw new Refused('EAGAIN', CHANGED);
    };
    const result = found.turn.then(run);
    found.turn = result.catch(() => undefined);
    return result;
  }

  async push(fields: Fields): Promise<Fields> {
    const chunk = bytesOf(fields.chunk);
    if (!chunk) throw new Refused('EINVAL', 'chunk must be bytes');
    return this.step(fields, (rescan) => ({ chunk: rescan.push(chunk) }));
  }

  async idle(fields: Fields): Promise<Fields> {
    return this.step(fields, (rescan) => ({ chunk: rescan.idle() }));
  }

  async end(fields: Fields): Promise<Fields> {
    return this.step(
      fields,
      (rescan) => {
        const chunk = rescan.end();
        return { chunk, hits: merge(rescan.hits()) };
      },
      true
    );
  }

  drop(fields: Fields): Fields {
    this.streams.delete(this.id(fields));
    return {};
  }

  async endpoints(fields: Fields): Promise<Fields> {
    const { added } = await register(this.vault.db, this.ns, fields.model, fields.mcp);
    if (added > 0) {
      await this.vault.loadPolicy(this.ns);
      await this.vault.changed(this.ns, ['secrets', 'exits']);
    }
    return { ok: true };
  }

  answer(fields: Fields): Promise<Fields> | Fields {
    const out = this.route(fields);
    if (!(out instanceof Promise)) return out;
    const op = fields.op as string;
    const checked = SANITIZED.has(op) ? out.then((reply) => this.sanitized(op, reply)) : out;
    return checked.catch((error) => this.cleaned(error));
  }

  async sanitized(op: string, reply: Fields): Promise<Fields> {
    const scrubber = await this.vault.scrubbers.get(this.ns);
    if (!scrubber) return reply;
    const walk = (value: unknown): unknown => {
      if (typeof value === 'string') return scrubber.text(value).text;
      if (typeof value === 'number')
        return scrubber.text(String(value)).hits.length ? undefined : value;
      if (Array.isArray(value)) return value.map(walk);
      if (value && typeof value === 'object' && !(value instanceof Uint8Array)) {
        const entries = Object.entries(value).map(([key, item]) => [key, walk(item)]);
        return Object.fromEntries(entries.filter(([, item]) => item !== undefined));
      }
      return value;
    };
    if (op === 'model' || op === 'mcp') return { ...reply, hits: walk(reply.hits) };
    return walk(reply) as Fields;
  }

  async cleaned(error: unknown): Promise<never> {
    if (!(error instanceof Refused) || FIXED.has(error.message)) throw error;
    const scrubber = await this.vault.scrubbers.get(this.ns).catch(() => {
      throw new Refused(error.code, UNSCRUBBED);
    });
    if (!scrubber) throw error;
    throw new Refused((error as Refused).code, scrubber.text((error as Refused).message).text);
  }

  route(fields: Fields): Promise<Fields> | Fields {
    switch (fields.op) {
      case 'redact':
        return this.redact(fields);
      case 'redactStream':
        return this.open(fields);
      case 'push':
        return this.push(fields);
      case 'idle':
        return this.idle(fields);
      case 'end':
        return this.end(fields);
      case 'drop':
        return this.drop(fields);
      case 'endpoints':
        return this.endpoints(fields);
      case 'model':
        return this.preparer.model(fields);
      case 'mcp':
        return this.preparer.mcp(fields);
      case 'records':
        return this.preparer.list();
      case 'grant':
        return fields.provider === undefined
          ? this.preparer.grant(fields)
          : this.preparer.signIn(fields);
      case 'refresh':
        return this.preparer.refresh(fields);
      default:
        throw new Refused('ENOTSUP', `this vault has no op ${String(fields.op)}`);
    }
  }
}

function merge(hits: Hit[]): Hit[] {
  const out = new Map<string, Hit>();
  for (const hit of hits) {
    const key = `${hit.name}\u0000${hit.form}`;
    const known = out.get(key);
    if (known) known.count += hit.count;
    else out.set(key, { ...hit });
  }
  return [...out.values()];
}
