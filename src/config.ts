import { allowed } from './origin.ts';

export interface Config {
  version: string;
  embedders: string[];
}

export const FALLBACK: Config = { version: '0.0.0', embedders: ['https://seven.sliccy.ai'] };

export const PRODUCTION = 'vault.sliccy.ai';

const SOURCE = /^https?:\/\/[a-z0-9.-]+(?::(?:\d+|\*))?$/;

function sources(value: unknown): string[] | null {
  if (!Array.isArray(value)) return null;
  const valid = value.filter((entry) => typeof entry === 'string' && SOURCE.test(entry));
  return valid.length === value.length ? valid : null;
}

async function read(fetcher: typeof fetch, path: string): Promise<Record<string, unknown> | null> {
  try {
    const response = await fetcher(path, { cache: 'no-cache', credentials: 'omit' });
    return response.ok ? ((await response.json()) as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

export async function load(
  fetcher: typeof fetch = fetch,
  host: string = globalThis.location?.hostname ?? ''
): Promise<Config> {
  const [own, served] = await Promise.all([
    read(fetcher, '/config.json'),
    read(fetcher, '/embedders.json'),
  ]);
  const version = typeof own?.version === 'string' ? own.version : FALLBACK.version;
  const fallback = host === PRODUCTION ? (sources(own?.embedders) ?? FALLBACK.embedders) : [];
  const embedders = sources(served?.embedders) ?? fallback;
  return { version, embedders };
}

let shared: Promise<Config> | null = null;

export function loaded(): Promise<Config> {
  shared ??= load();
  return shared;
}

export function embedded(config: Config, origin: string): boolean {
  return allowed(config.embedders, origin);
}
