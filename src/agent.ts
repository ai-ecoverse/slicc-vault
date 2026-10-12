import type { Hit, Scrubber, Stream } from '@ai-ecoverse/slicc-scrub';
import { Refused } from './errors.ts';
import { register } from './rules.ts';
import type { Vault } from './vault.ts';

type Fields = Record<string, unknown>;

export const MAX_STREAMS = 64;
const LOCKED = 'vault is locked: unlock it in the vault window to continue';

export class AgentPort {
  readonly vault: Vault;
  readonly ns: string;
  readonly streams = new Map<string, Stream>();

  constructor(vault: Vault, ns: string) {
    this.vault = vault;
    this.ns = ns;
  }

  async scrubber(): Promise<Scrubber> {
    const scrubber = await this.vault.scrubbers.get(this.ns);
    if (!scrubber) throw new Refused('EACCES', LOCKED);
    return scrubber;
  }

  async redact(fields: Fields): Promise<Fields> {
    const texts = fields.texts;
    if (
      !Array.isArray(texts) ||
      !texts.every((t) => typeof t === 'string' || t instanceof Uint8Array)
    ) {
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

  open(fields: Fields): Promise<Fields> {
    const id = this.id(fields);
    if (this.streams.size >= MAX_STREAMS && !this.streams.has(id)) {
      throw new Refused('EAGAIN', `at most ${MAX_STREAMS} streams are open`);
    }
    return this.scrubber().then((scrubber) => {
      this.streams.set(id, scrubber.stream());
      return { stream: id, idleMs: scrubber.idleMs, version: scrubber.version };
    });
  }

  stream(fields: Fields): Stream {
    const found = this.streams.get(this.id(fields));
    if (!found) throw new Refused('ENOENT', 'no such stream');
    return found;
  }

  push(fields: Fields): Fields {
    const chunk = fields.chunk;
    if (!(chunk instanceof Uint8Array)) throw new Refused('EINVAL', 'chunk must be bytes');
    return { chunk: this.stream(fields).push(chunk) };
  }

  end(fields: Fields): Fields {
    const stream = this.stream(fields);
    this.streams.delete(this.id(fields));
    return { chunk: stream.end(), hits: stream.hits };
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
    switch (fields.op) {
      case 'redact':
        return this.redact(fields);
      case 'redactStream':
        return this.open(fields);
      case 'push':
        return this.push(fields);
      case 'idle':
        return { chunk: this.stream(fields).idle() };
      case 'end':
        return this.end(fields);
      case 'drop':
        return this.drop(fields);
      case 'endpoints':
        return this.endpoints(fields);
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
