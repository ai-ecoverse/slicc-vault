import type { ExitName, Rule, Stamp } from './contract.ts';
import { decrypt } from './keys.ts';
import type { Policy } from './policy.ts';
import { aad, removed, rulesFor, type VaultRecord } from './records.ts';
import { hostOf, type McpServer, mcpServer, type Registered, refusedUrl } from './refusal.ts';

export interface Head {
  method: string;
  url: string;
  headers: [string, string][];
}

export interface Traits {
  manualRedirects: boolean;
  encodedBodies: boolean;
}

export interface Injection {
  name: string;
  rule: Rule | null;
}

export type Prepared =
  | {
      ok: true;
      head: Head;
      injected: Injection[];
      host: string;
      path: string;
      server: McpServer | null;
    }
  | { ok: false; status: number; reason: string };

export interface Inputs {
  ns: string;
  head: Head;
  owner: Stamp;
  exit: ExitName;
  traits: Traits;
  records: VaultRecord[];
  policy: Policy;
  registered: Registered;
  key: CryptoKey | null;
  now: number;
}

class Refusal extends Error {
  readonly status: number;

  constructor(reason: string, status = 403) {
    super(reason);
    this.status = status;
  }
}

const FOUND = /fnox_proxy_[0-9a-f]{24}/g;
const AMBIGUOUS = /(^|\/)\.\.?(\/|$)|\\|%2e|%2f|%5c|%25/i;

function glob(pattern: string, path: string): boolean {
  let source = '';
  for (let i = 0; i < pattern.length; i++) {
    const char = pattern[i];
    if (char === '*' && pattern[i + 1] === '*') {
      source += '.*';
      i++;
    } else if (char === '*') source += '[^/]*';
    else if (char === '?') source += '[^/]';
    else source += char.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${source}$`).test(path);
}

export function matches(rule: Rule, method: string, host: string, path: string, header: string) {
  if (rule.domain !== host || rule.header !== header) return false;
  if (rule.methods.length > 0 && !rule.methods.includes(method)) return false;
  return rule.paths.length === 0 || rule.paths.some((pattern) => glob(pattern, path));
}

function placeholders(text: string): string[] {
  return text.match(FOUND) ?? [];
}

function unbase64(text: string): string | null {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(text) || text.length % 4 !== 0) return null;
  try {
    const bytes = Uint8Array.from(atob(text), (char) => char.charCodeAt(0));
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

function loose(text: string): string {
  const clean = text.replace(/[^A-Za-z0-9+/]/g, '');
  return atob(clean.slice(0, clean.length - (clean.length % 4)));
}

function decoded(text: string): string {
  try {
    return decodeURIComponent(text);
  } catch {
    return text;
  }
}

function base64(text: string): string {
  let binary = '';
  for (const byte of new TextEncoder().encode(text)) binary += String.fromCharCode(byte);
  return btoa(binary);
}

class Injector {
  readonly input: Inputs;
  readonly url: URL;
  readonly host: string;
  readonly path: string;
  readonly method: string;
  readonly byPlaceholder: Map<string, VaultRecord>;
  readonly injected: Injection[] = [];
  readonly server: McpServer | null;

  constructor(input: Inputs) {
    this.input = input;
    const url = URL.parse(input.head.url);
    if (!url) throw new Refusal('the request has no valid URL');
    this.url = url;
    this.host = hostOf(url);
    this.path = url.pathname;
    this.method = input.head.method.toUpperCase();
    this.byPlaceholder = new Map(input.records.map((record) => [record.placeholder, record]));
    this.server = mcpServer(input.registered, url);
  }

  label(placeholder: string): string {
    return (this.byPlaceholder.get(placeholder) as VaultRecord).name;
  }

  known(text: string): string[] {
    return placeholders(text).filter((p) => this.byPlaceholder.has(p));
  }

  checkTarget(): void {
    const { url, input } = this;
    const inUrl = this.known(`${url.href} ${decoded(url.href)}`);
    if (inUrl.length) throw new Refusal(`${this.label(inUrl[0])} works only in a header`);
    for (const [name] of input.head.headers) {
      const inName = this.known(name);
      if (inName.length) throw new Refusal(`${this.label(inName[0])} can't be a header name`);
    }
    if (url.username || url.password) throw new Refusal('credentials in the URL are refused');
    const kernel = this.server !== null && url.protocol === 'http:';
    if (!kernel && (url.protocol !== 'https:' || (url.port !== '' && url.port !== '443'))) {
      throw new Refusal('credentials are sent only over https on port 443');
    }
    const rawPath = input.head.url.replace(/^[a-z][a-z0-9+.-]*:\/\/[^/?#]*/i, '').split(/[?#]/)[0];
    if (AMBIGUOUS.test(rawPath)) throw new Refusal(`ambiguous path ${rawPath}`);
    if (input.traits.encodedBodies) {
      throw new Refusal('this exit returns encoded bodies, which the vault cannot scrub', 502);
    }
  }

  record(placeholder: string, kind: 'secret' | 'mcp'): VaultRecord {
    const record = this.byPlaceholder.get(placeholder) as VaultRecord;
    const name = record.name;
    if (removed(record)) throw new Refusal(`${name} was removed`);
    if (record.kind !== kind) {
      throw new Refusal(
        kind === 'mcp'
          ? `${name} is a secret; secrets are never sent to model or MCP endpoints`
          : `${name} isn't a secret the vault injects`
      );
    }
    if (record.expiresAt !== undefined && record.expiresAt <= this.input.now) {
      throw new Refusal(`${name} expired; refreshing`);
    }
    if (!this.input.key) throw new Refusal('vault is locked: unlock it in the vault window');
    return record;
  }

  rule(record: VaultRecord, header: string): Rule {
    const { policy, exit, traits } = this.input;
    const rules = rulesFor(record, policy);
    const found = rules.find((rule) => matches(rule, this.method, this.host, this.path, header));
    if (!found) {
      const domains = [...new Set(rules.map((rule) => rule.domain))];
      if (!rules.length)
        throw new Refusal(`no rule in /etc/fnox/config.toml lets ${record.name} be used`);
      if (!domains.includes(this.host))
        throw new Refusal(`${record.name} is only for ${domains.join(', ')}`);
      throw new Refusal(
        `${record.name} isn't allowed in ${header} for ${this.method} ${this.path}`
      );
    }
    const exits = policy.exits(record.name);
    if (exits && !exits.includes(exit)) {
      throw new Refusal(`${record.name} isn't allowed on ${exit} (/etc/slicc/secrets-policy.toml)`);
    }
    if (header !== 'authorization' && !traits.manualRedirects) {
      throw new Refusal(`${record.name} in ${header} needs an exit that doesn't follow redirects`);
    }
    return found;
  }

  async substitute(text: string, header: string, kind: 'secret' | 'mcp'): Promise<string> {
    let out = text;
    for (const placeholder of new Set(this.known(text))) {
      const record = this.record(placeholder, kind);
      if (text.split(placeholder).length > 2) {
        throw new Refusal(`${record.name} appears more than once in ${header}`);
      }
      if (kind === 'mcp' && !this.server?.names.includes(record.name)) {
        throw new Refusal(
          `${record.name} isn't a credential of the MCP server ${this.server?.server}`
        );
      }
      const rule = kind === 'secret' ? this.rule(record, header) : null;
      const value = await decrypt(
        this.input.key as CryptoKey,
        record.sealed,
        aad(record.ns, record.kind, record.name)
      );
      out = out.replace(placeholder, value);
      this.injected.push({ name: record.name, rule });
    }
    return out;
  }

  async basic(value: string, header: string, kind: 'secret' | 'mcp'): Promise<string> {
    const match = /^(Basic\s+)(\S+)$/i.exec(value);
    if (header !== 'authorization' || !match) return value;
    const decoded = unbase64(match[2]);
    if (decoded === null) {
      if (this.known(`${match[2]} ${loose(match[2])}`).length) {
        throw new Refusal(
          'a Basic credential that holds a placeholder must be valid base64 of UTF-8'
        );
      }
      return value;
    }
    if (!this.known(decoded).length) return value;
    const colon = decoded.indexOf(':');
    const user = colon < 0 ? decoded : decoded.slice(0, colon);
    const pass = colon < 0 ? '' : decoded.slice(colon + 1);
    const newUser = await this.substitute(user, header, kind);
    if (newUser.includes(':')) throw new Refusal("a substituted Basic user can't contain :");
    const newPass = colon < 0 ? '' : await this.substitute(pass, header, kind);
    return `${match[1]}${base64(colon < 0 ? newUser : `${newUser}:${newPass}`)}`;
  }

  async headers(kind: 'secret' | 'mcp'): Promise<[string, string][]> {
    const out: [string, string][] = [];
    for (const [rawName, value] of this.input.head.headers) {
      const name = rawName.toLowerCase();
      let next = await this.basic(value, name, kind);
      if (next === value) next = await this.substitute(value, name, kind);
      if (/[\r\n\0]/.test(next)) throw new Refusal('a header would contain CR, LF or NUL');
      out.push([rawName, next]);
    }
    return out;
  }

  async run(): Promise<Prepared> {
    this.checkTarget();
    const all = this.input.head.headers.flatMap(([, value]) => {
      const basic = /^Basic\s+(\S+)$/i.exec(value);
      const inside = basic ? (unbase64(basic[1]) ?? loose(basic[1])) : '';
      return [...this.known(value), ...this.known(inside)];
    });
    if (!all.length) throw new Refusal('the request carries no placeholder of this vault');
    const refused = refusedUrl(this.input.registered, this.url);
    if (refused && !this.server) {
      throw new Refusal(`${this.host} is a model or MCP endpoint; the vault never injects there`);
    }
    const headers = await this.headers(this.server ? 'mcp' : 'secret');
    const head = { ...this.input.head, headers };
    return {
      ok: true,
      head,
      injected: this.injected,
      host: this.host,
      path: this.path,
      server: this.server,
    };
  }
}

export async function prepare(input: Inputs): Promise<Prepared> {
  try {
    return await new Injector(input).run();
  } catch (error) {
    if (error instanceof Refusal) return { ok: false, status: error.status, reason: error.message };
    throw error;
  }
}
