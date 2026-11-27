import { compile, type Options, type Scrubber, type Secret } from '@ai-ecoverse/slicc-scrub';
import { decrypt } from './keys.ts';
import { aad, MAX_VALUES, records, scrubVersion } from './records.ts';
import type { Vault } from './vault.ts';

interface Compiled {
  version: number;
  scrubber: Scrubber;
  values: { kind: string; name: string; placeholder: string; value: string }[];
  others: Map<string, Scrubber>;
}

export class Scrubbers {
  readonly vault: Pick<Vault, 'db' | 'keyring'>;
  readonly cache = new Map<string, Compiled>();
  readonly epochs = new Map<string, number>();
  readonly held = new WeakMap<Scrubber, Secret[]>();
  readonly twins = new WeakMap<Scrubber, Scrubber>();
  readonly wides = new WeakMap<Scrubber, { next: Scrubber; wide: Scrubber }>();
  readonly failed = new Map<string, number>();
  readonly limit = { values: 256, bytes: MAX_VALUES };

  constructor(vault: Pick<Vault, 'db' | 'keyring'>) {
    this.vault = vault;
  }

  touch(ns: string): void {
    this.epochs.set(ns, this.epoch(ns) + 1);
  }

  epoch(ns: string): number {
    return this.epochs.get(ns) ?? 0;
  }

  build(values: Secret[], options: Options): Scrubber {
    const encoder = new TextEncoder();
    const bytes = values.reduce((sum, secret) => sum + encoder.encode(secret.value).length, 0);
    if (bytes > this.limit.bytes) throw new RangeError('too many values to scrub');
    const scrubber = compile(values, options);
    this.held.set(scrubber, values);
    return scrubber;
  }

  ready(ns: string, needed: boolean, version: number): boolean {
    if (!needed) return true;
    if (this.failed.get(ns) === version) return false;
    return this.cache.has(ns) || !this.vault.keyring.locked;
  }

  async get(ns: string): Promise<Scrubber | null> {
    const version = await scrubVersion(this.vault.db, ns);
    const cached = this.cache.get(ns);
    if (cached && cached.version === version) return cached.scrubber;
    const key = this.vault.keyring.key;
    if (!key) return cached?.scrubber ?? null;
    const held = await records(this.vault.db, ns);
    const sealed = held.flatMap((record) =>
      [record.sealed, ...(record.replaced ? [record.replaced.sealed] : [])].map((blob) => ({
        record,
        blob,
      }))
    );
    const values = await Promise.all(
      sealed.map(async ({ record, blob }) => ({
        kind: record.kind,
        name: record.name,
        placeholder: record.placeholder,
        value: await decrypt(key, blob, aad(record.ns, record.kind, record.name)),
      }))
    );
    let scrubber: Scrubber;
    try {
      scrubber = this.build(values, { version });
    } catch (error) {
      this.failed.set(ns, version);
      throw error;
    }
    this.cache.set(ns, { version, scrubber, values, others: new Map() });
    return scrubber;
  }

  async widen(ns: string, prior: Scrubber): Promise<Scrubber | null> {
    const next = await this.get(ns);
    const had = this.held.get(prior);
    const has = next && this.held.get(next);
    if (!next || !had || !has) return null;
    const memo = this.wides.get(prior);
    if (memo?.next === next) return memo.wide;
    const key = (secret: Secret) => JSON.stringify([secret.name, secret.placeholder, secret.value]);
    const known = new Set(has.map(key));
    const kept = had.filter((secret) => !known.has(key(secret)));
    if (!kept.length) return next;
    if (kept.length > this.limit.values) return null;
    const wide = this.build([...has, ...kept], { version: next.version });
    this.wides.set(prior, { next, wide });
    return wide;
  }

  twin(scrubber: Scrubber): Scrubber {
    let twin = this.twins.get(scrubber);
    if (!twin) {
      const values = this.held.get(scrubber);
      if (!values) throw new Error('no values for this scrub');
      twin = this.build(values, { sameLength: true });
      this.twins.set(scrubber, twin);
    }
    return twin;
  }

  async holdsAnother(ns: string, own: { kind: string; name: string }, value: string) {
    await this.get(ns);
    const compiled = this.cache.get(ns) as Compiled;
    const key = `${own.kind}\u0000${own.name}`;
    let others = compiled.others.get(key);
    if (!others) {
      const rest = compiled.values.filter((o) => o.kind !== own.kind || o.name !== own.name);
      others = this.build(rest, { version: compiled.version });
      compiled.others.set(key, others);
    }
    return others.text(value).hits.some((hit) => hit.form !== 'fragment');
  }
}
