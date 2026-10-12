import { type Channel, channel, type Message, type Part } from './channel.ts';
import { type Config, load } from './config.ts';
import type { ScrubState, VaultStatus } from './contract.ts';
import { open } from './db.ts';
import { Keyring } from './lock.ts';
import { EMPTY, type Policy } from './policy.ts';
import { backupState, records, reminder, scrubVersion } from './records.ts';
import { pending, waiting } from './requests.ts';
import { loadPolicy, loadStored } from './rules.ts';
import type { Context } from './sealed.ts';

export type Listener = (ns: string, parts: Part[]) => void | Promise<void>;

export interface Vault {
  db: IDBDatabase;
  config: Config;
  keyring: Keyring;
  bus: Channel;
  policy(ns: string): Policy;
  loadPolicy(ns: string): Promise<Policy>;
  setPolicy(ns: string, policy: Policy): void;
  now(): number;
  changed(ns: string, parts: Part[]): Promise<void>;
  onChange(listener: Listener): () => void;
  context(ns: string): Context;
  scrub(ns: string): Promise<ScrubState>;
  status(ns: string): Promise<VaultStatus>;
}

export interface Options {
  db?: IDBDatabase;
  bus?: Channel;
  config?: Config;
  now?: () => number;
}

export async function start(options: Options = {}): Promise<Vault> {
  const [db, config] = await Promise.all([options.db ?? open(), options.config ?? load()]);
  const bus = options.bus ?? channel();
  const keyring = new Keyring(db, bus);
  const now = options.now ?? Date.now;
  const listeners = new Set<Listener>();
  const policies = new Map<string, Policy>();
  const notify = async (ns: string, parts: Part[]) => {
    await Promise.all([...listeners].map((listener) => listener(ns, parts)));
  };
  const vault: Vault = {
    db,
    config,
    keyring,
    bus,
    now,
    policy: (ns) => policies.get(ns) ?? EMPTY,
    async loadPolicy(ns) {
      const loaded = await loadPolicy(db, ns);
      policies.set(ns, loaded);
      return loaded;
    },
    setPolicy(ns, policy) {
      policies.set(ns, policy);
    },
    async changed(ns, parts) {
      bus.post({ type: 'changed', ns, parts });
      await notify(ns, parts);
    },
    onChange(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    context(ns) {
      return {
        db,
        ns,
        keyring,
        policy: () => vault.policy(ns),
        now,
        changed: () => vault.changed(ns, ['secrets', 'requests', 'audit']),
      };
    },
    async scrub(ns) {
      const [held, version] = await Promise.all([records(db, ns), scrubVersion(db, ns)]);
      const needed = held.length > 0;
      return { needed, version, ready: !needed || keyring.seen };
    },
    async status(ns) {
      const [backup, held, stored] = await Promise.all([
        backupState(db, ns),
        records(db, ns),
        loadStored(db, ns),
      ]);
      const secrets = held.some((record) => record.kind === 'secret');
      return {
        version: config.version,
        protocol: 1,
        origin: ns,
        locked: keyring.locked,
        lock: keyring.mode,
        scrub: await vault.scrub(ns),
        waiting: (await waiting(db, ns, now())).map(pending),
        exportedAt: backup.exportedAt,
        backupReminder: reminder(backup, secrets),
        policy: stored.last ?? [],
      };
    },
  };
  bus.listen((message: Message) => {
    if (message.type === 'changed') void reload(message.ns, message.parts);
    else if (message.type !== 'popup') void keyring.receive(message);
  });
  const reload = async (ns: string, parts: Part[]) => {
    if (parts.includes('exits') && policies.has(ns)) await vault.loadPolicy(ns);
    await notify(ns, parts);
  };
  await keyring.load();
  return vault;
}
