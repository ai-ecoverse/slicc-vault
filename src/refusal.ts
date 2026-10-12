import BUILT_IN from './endpoints.json' with { type: 'json' };

export interface Endpoint {
  host: string;
  path: string;
}

export interface McpServer {
  server: string;
  url: string;
  names: string[];
}

export interface Registered {
  model: string[];
  mcp: McpServer[];
}

export const NO_ENDPOINTS: Registered = { model: [], mcp: [] };
export const BUILT_IN_ENDPOINTS: readonly Endpoint[] = BUILT_IN;
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
  const model = registered.model.map((url) => endpoint(url, false));
  const mcp = registered.mcp.map((server) => endpoint(server.url, true));
  return [...BUILT_IN_ENDPOINTS, ...[...model, ...mcp].filter((e): e is Endpoint => e !== null)];
}

export function hostOf(url: URL): string {
  return url.hostname.toLowerCase().replace(/\.+$/, '');
}

export function refusedUrl(registered: Registered, url: URL): boolean {
  const host = hostOf(url);
  return patterns(registered).some((pattern) => covers(pattern, host, url.pathname));
}

export function mcpServer(registered: Registered, url: URL): McpServer | null {
  const host = hostOf(url);
  for (const server of registered.mcp) {
    const pattern = endpoint(server.url, true);
    const sameScheme = URL.parse(server.url)?.protocol === url.protocol;
    if (pattern && sameScheme && covers(pattern, host, url.pathname)) return server;
  }
  return null;
}
