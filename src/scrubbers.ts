import { compile, type Scrubber } from '@ai-ecoverse/slicc-scrub';
import { decrypt } from './keys.ts';
import { aad, records, scrubVersion } from './records.ts';
import type { Vault } from './vault.ts';

interface Compiled {
  version: number;
  scrubber: Scrubber;
  values: { kind: string; name: string; value: string }[];
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
    this.cache.set(ns, { version, scrubber, values });
    return scrubber;
  }

  async holdsAnother(ns: string, own: { kind: string; name: string }, value: string) {
    await this.get(ns);
    const known = (this.cache.get(ns) as Compiled).values;
    const others = known.filter((o) => o.kind !== own.kind || o.name !== own.name);
    return others.some((o) => value.includes(o.value));
  }
}
