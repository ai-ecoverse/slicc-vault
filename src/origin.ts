const PORTS: Record<string, string> = { 'http:': '80', 'https:': '443' };
const SOURCE = /^(https?):\/\/([a-z0-9.-]+)(?::(\d+|\*))?$/;

export function matches(source: string, origin: string): boolean {
  const parsed = SOURCE.exec(source);
  const url = URL.parse(origin);
  if (!parsed || !url || url.origin !== origin) return false;
  const [, scheme, host, port] = parsed;
  if (url.protocol !== `${scheme}:` || url.hostname !== host) return false;
  if (port === '*') return true;
  return (url.port || PORTS[url.protocol]) === (port ?? PORTS[url.protocol]);
}

export function allowed(embedders: readonly string[], origin: string): boolean {
  return embedders.some((source) => matches(source, origin));
}
