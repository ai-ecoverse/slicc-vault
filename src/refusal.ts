import BUILT_IN from './endpoints.json' with { type: 'json' };

export interface Endpoint {
  host: string;
  path: string;
  providers?: string[];
}

export interface McpServer {
  server: string;
  url: string;
  names: string[];
  tokenUrl?: string;
}

export interface Owned {
  provider: string;
  url: string;
}

export interface PageEndpoints {
  model: string[];
  mcp: McpServer[];
  custom: Owned[];
}

export interface Registered {
  model: string[];
  mcp: McpServer[];
  owned?: Owned[];
  page?: PageEndpoints;
}

export const NO_PAGE: PageEndpoints = { model: [], mcp: [], custom: [] };

export function servers(registered: Registered): McpServer[] {
  const page = (registered.page ?? NO_PAGE).mcp;
  const owned = new Set(page.map((server) => server.server));
  return [...page, ...registered.mcp.filter((server) => !owned.has(server.server))];
}

export interface Holder {
  url?: string;
  source: string;
}

export function holds(registered: Registered, server: McpServer, record: Holder): boolean {
  if (record.url !== undefined) return new URL(server.url).href === record.url;
  if (record.source === 'oauth:mcp') return new URL(server.url).protocol === 'https:';
  return (
    new URL(server.url).protocol === 'https:' && (registered.page ?? NO_PAGE).mcp.includes(server)
  );
}

export function coveredByBuiltIn(provider: string, url: string): boolean {
  const parsed = URL.parse(url);
  if (!parsed) return false;
  const host = hostOf(parsed);
  return BUILT_IN_ENDPOINTS.filter((e) => e.providers.includes(provider)).some((pattern) =>
    covers(pattern, host, parsed.pathname)
  );
}

export const NO_ENDPOINTS: Registered = { model: [], mcp: [] };
export const BUILT_IN_ENDPOINTS: readonly (Endpoint & { providers: string[] })[] = BUILT_IN;
const KERNEL = /^(\d{1,5})\.kernel\.localhost$/;

function hostPattern(host: string): RegExp {
  const escaped = host.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^.]+');
  return new RegExp(`^${escaped}$`);
}

function segments(path: string): string[] {
  return path.split('/').filter(Boolean);
}

export function kernelPort(url: URL): number | null {
  const match = KERNEL.exec(url.hostname);
  const port = match ? Number(match[1]) : 0;
  if (
    url.protocol !== 'http:' ||
    !match ||
    url.port !== '' ||
    port < 1 ||
    port > 65535 ||
    port === 9222
  ) {
    return null;
  }
  return port;
}

export function endpoint(raw: string, mcp: boolean): Endpoint | null {
  const url = URL.parse(raw);
  if (!url || url.username || url.password) return null;
  const kernel = mcp && kernelPort(url) !== null;
  if (url.protocol !== 'https:' && !kernel) return null;
  if (url.port !== '' && url.port !== '443') return null;
  return { host: url.hostname.toLowerCase(), path: url.pathname.replace(/\/+$/, '') };
}

export function covers(pattern: Endpoint, host: string, path: string): boolean {
  if (!hostPattern(pattern.host).test(host)) return false;
  const want = segments(pattern.path);
  const have = segments(path);
  return want.every((segment, i) => i < have.length && (segment === '*' || segment === have[i]));
}

export function contains(pattern: Endpoint, domain: string, paths: string[]): boolean {
  if (!hostPattern(pattern.host).test(domain)) return false;
  const want = segments(pattern.path);
  if (want.length === 0) return true;
  if (paths.length === 0) return false;
  return paths.every((path) => {
    const have = segments(path);
    return want.every(
      (segment, i) =>
        i < have.length && !have[i].includes('*') && (segment === '*' || segment === have[i])
    );
  });
}

export function patterns(registered: Registered): Endpoint[] {
  const page = registered.page ?? NO_PAGE;
  const model = [...page.model, ...page.custom.map((entry) => entry.url)].map((url) =>
    endpoint(url, false)
  );
  const mcp = page.mcp.map((server) => endpoint(server.url, true));
  return [...BUILT_IN_ENDPOINTS, ...[...model, ...mcp].filter((e): e is Endpoint => e !== null)];
}

export function modelRefused(registered: Registered, url: URL): boolean {
  const page = registered.page ?? NO_PAGE;
  const own = [...page.model, ...page.custom.map((entry) => entry.url)]
    .map((base) => endpoint(base, false))
    .filter((e): e is Endpoint => e !== null);
  const host = hostOf(url);
  return [...BUILT_IN_ENDPOINTS, ...own].some((pattern) => covers(pattern, host, url.pathname));
}

export function hostOf(url: URL): string {
  return url.hostname.toLowerCase().replace(/\.+$/, '');
}

export function refusedUrl(registered: Registered, url: URL): boolean {
  const host = hostOf(url);
  return patterns(registered).some((pattern) => covers(pattern, host, url.pathname));
}

export function onHost(pattern: Endpoint, host: string): boolean {
  return hostPattern(pattern.host).test(host);
}

function plain(url: URL, port: string): boolean {
  return !url.username && !url.password && url.port === port;
}

export function modelFor(registered: Registered, provider: string, url: URL): boolean {
  if (url.protocol !== 'https:' || !plain(url, '')) return false;
  const host = hostOf(url);
  const built = BUILT_IN_ENDPOINTS.filter((e) => e.providers.includes(provider));
  const owned = (registered.page ?? NO_PAGE).custom
    .filter((entry) => entry.provider === provider)
    .map((entry) => endpoint(entry.url, false) as Endpoint);
  return [...built, ...owned].some((pattern) => covers(pattern, host, url.pathname));
}

export function under(base: string, url: URL): boolean {
  const own = new URL(base);
  const pattern = endpoint(base, true) as Endpoint;
  return (
    own.protocol === url.protocol &&
    plain(url, own.port) &&
    covers(pattern, hostOf(url), url.pathname)
  );
}

export function serverFor(registered: Registered, server: string, url: URL): McpServer | null {
  const host = hostOf(url);
  for (const entry of servers(registered).filter((e) => e.server === server)) {
    if (entry.tokenUrl === url.href) return entry;
    const pattern = endpoint(entry.url, true) as Endpoint;
    const own = new URL(entry.url);
    const same = own.protocol === url.protocol && plain(url, own.port);
    if (same && covers(pattern, host, url.pathname)) return entry;
  }
  return null;
}

export function mcpServer(registered: Registered, url: URL): McpServer | null {
  const host = hostOf(url);
  for (const server of servers(registered)) {
    const pattern = endpoint(server.url, true);
    const sameScheme = URL.parse(server.url)?.protocol === url.protocol;
    if (pattern && sameScheme && covers(pattern, host, url.pathname)) return server;
  }
  return null;
}
