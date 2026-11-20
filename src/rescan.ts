import type { Hit, Scrubber, Stream } from '@ai-ecoverse/slicc-scrub';
import { atVersion } from './records.ts';
import type { Vault } from './vault.ts';

const TRIES = 3;

export interface Watch {
  at(version: number, work: () => void, stale: () => void): void | Promise<void>;
  widen(prior: Scrubber): Promise<Scrubber | null>;
  twin(scrubber: Scrubber): Scrubber;
}

export function watch(vault: Vault, ns: string, epoch: number): Watch {
  let mark = epoch;
  return {
    at: (version, work, stale) =>
      atVersion(
        vault.db,
        ns,
        version,
        () => (vault.scrubbers.epoch(ns) === mark ? work() : stale()),
        stale
      ),
    widen: (prior) => {
      mark = vault.scrubbers.epoch(ns);
      return vault.scrubbers.widen(ns, prior);
    },
    twin: (scrubber) => vault.scrubbers.twin(scrubber),
  };
}

function joined(head: Uint8Array, tail: Uint8Array): Uint8Array {
  const out = new Uint8Array(head.length + tail.length);
  out.set(head);
  out.set(tail, head.length);
  return out;
}

export class Rescan {
  readonly watcher: Watch;
  current: Scrubber;
  stream: Stream;
  twin: Stream;
  held: Uint8Array = new Uint8Array(0);
  seen: Hit[] = [];

  constructor(scrubber: Scrubber, watcher: Watch) {
    this.watcher = watcher;
    this.current = scrubber;
    this.twin = watcher.twin(scrubber).stream();
    this.stream = scrubber.stream();
  }

  take(out: Uint8Array, passed: Uint8Array): Uint8Array {
    this.held = this.held.slice(passed.length);
    return out;
  }

  push(chunk: Uint8Array): Uint8Array {
    this.held = joined(this.held, chunk);
    return this.take(this.stream.push(chunk), this.twin.push(chunk));
  }

  idle(): Uint8Array {
    return this.take(this.stream.idle(), this.twin.idle());
  }

  end(): Uint8Array {
    return this.take(this.stream.end(), this.twin.end());
  }

  hits(): Hit[] {
    return [...this.seen, ...this.stream.hits];
  }

  swap(next: Scrubber, pair: Scrubber): Uint8Array {
    const tail = this.held;
    this.seen.push(...this.stream.hits);
    this.current = next;
    this.stream = next.stream();
    this.twin = pair.stream();
    this.held = new Uint8Array(0);
    return this.push(tail);
  }

  async at(work: (swapped: Uint8Array) => void): Promise<boolean> {
    let next = this.current;
    for (let tries = 0; ; tries++) {
      const candidate = next;
      const pair = candidate === this.current ? null : this.watcher.twin(candidate);
      let stale = false;
      await this.watcher.at(
        candidate.version,
        () => work(pair ? this.swap(candidate, pair) : new Uint8Array(0)),
        () => {
          stale = true;
        }
      );
      if (!stale) return true;
      if (tries === TRIES) return false;
      const wide = await this.watcher.widen(candidate);
      if (!wide) return false;
      next = wide;
    }
  }
}

export function concat(head: Uint8Array, tail: Uint8Array): Uint8Array {
  return head.length ? joined(head, tail) : tail;
}
