import { compile, type Scrubber } from '@ai-ecoverse/slicc-scrub';
import { decrypt } from './keys.ts';
import { aad, records, scrubVersion } from './records.ts';
import type { Vault } from './vault.ts';

interface Compiled {
  version: number;
  scrubber: Scrubber;
  values: { kind: string; name: string; placeholder: string; value: string }[];
  others: Map<string, Scrubber>;
}

export class Scrubbers {
  readonly vault: Vault;
  readonly cache = new Map<string, Compiled>();

  constructor(vault: Vault) {
    this.vault = vault;
  }

  ready(ns: string, needed: boolean): boolean {
    return !needed || this.cache.has(ns) || !this.vault.keyring.locked;
  }

  async get(ns: string): Promise<Scrubber | null> {
    const version = await scrubVersion(this.vault.db, ns);
    const cached = this.cache.get(ns);
    if (cached && cached.version === version) return cached.scrubber;
    const key = this.vault.keyring.key;
    if (!key) return cached?.scrubber ?? null;
    const held = await records(this.vault.db, ns);
    const values = await Promise.all(
      held.map(async (record) => ({
        kind: record.kind,
        name: record.name,
        placeholder: record.placeholder,
        value: await decrypt(key, record.sealed, aad(record.ns, record.kind, record.name)),
      }))
    );
    const scrubber = compile(values, { version });
    this.cache.set(ns, { version, scrubber, values, others: new Map() });
    return scrubber;
  }

  async holdsAnother(ns: string, own: { kind: string; name: string }, value: string) {
    await this.get(ns);
    const compiled = this.cache.get(ns) as Compiled;
    const key = `${own.kind}\u0000${own.name}`;
    let others = compiled.others.get(key);
    if (!others) {
      const rest = compiled.values.filter((o) => o.kind !== own.kind || o.name !== own.name);
      others = compile(rest, { version: compiled.version });
      compiled.others.set(key, others);
    }
    return others.text(value).hits.some((hit) => hit.form !== 'fragment');
  }
}
