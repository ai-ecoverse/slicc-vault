import type {
  ExecMode,
  ExitName,
  ExitPolicyView,
  PolicyChange,
  PolicyFile,
  RefusedRule,
  Rule,
} from './contract.ts';
import { PLACEHOLDER } from './records.ts';
import { parseToml, type TomlTable, type TomlValue } from './toml.ts';

export const CONFIG_FILE = '/etc/fnox/config.toml';
export const POLICY_FILE = '/etc/slicc/secrets-policy.toml';
export const FILES: readonly PolicyFile[] = [CONFIG_FILE, POLICY_FILE];

export interface Policy {
  refused(): RefusedRule[];
  placeholder(name: string): string | null;
  rules(name: string): Rule[];
  exec(name: string): ExecMode;
  argv(name: string): string[][] | null;
  exits(name: string): ExitName[] | null;
  limits(): Limits;
  shells(): string[];
  view(): ExitPolicyView;
}

export interface Limits {
  materialize_per_minute: number;
  materialize_per_day: number;
  shell_per_day: number;
}

export const LIMITS: Limits = {
  materialize_per_minute: 10,
  materialize_per_day: 200,
  shell_per_day: 5000,
};

export interface ConfigPolicy {
  secrets: Record<string, string>;
  rules: { secret: string; rule: Rule }[];
}

export interface ExtraPolicy {
  exec: Record<string, { mode: Exclude<ExecMode, false>; argv?: string[][] }>;
  exits: Record<string, ExitName[]>;
  limits: Limits;
}

export interface Accepted {
  config: { sha256: string; parsed: ConfigPolicy } | null;
  extra: { sha256: string; parsed: ExtraPolicy } | null;
}

export const NONE: Accepted = { config: null, extra: null };

const DOMAIN = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/;
const TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const EXIT = /^(?:page|proxy|tailscale|device:[A-Za-z0-9._-]+)$/;

function isTable(value: TomlValue | undefined): value is TomlTable {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function strings(value: TomlValue | undefined): string[] | null {
  if (value === undefined) return [];
  if (!Array.isArray(value) || !value.every((item) => typeof item === 'string')) return null;
  return value as string[];
}

export function parseRule(entry: TomlValue, index: number, warnings: string[]) {
  const where = `proxy rule ${index + 1}`;
  if (!isTable(entry) || typeof entry.secret !== 'string' || typeof entry.domain !== 'string') {
    warnings.push(`${where}: needs secret and domain`);
    return null;
  }
  const domain = entry.domain.toLowerCase();
  if (entry.header !== undefined && typeof entry.header !== 'string') {
    warnings.push(`${where}: header must be a header name`);
    return null;
  }
  const header = typeof entry.header === 'string' ? entry.header.toLowerCase() : 'authorization';
  const methods = strings(entry.methods);
  const paths = strings(entry.paths);
  if (!DOMAIN.test(domain)) {
    warnings.push(`${where}: ${entry.domain} isn't an exact host name`);
    return null;
  }
  if (!TOKEN.test(header) || entry.header === '') {
    warnings.push(`${where}: ${String(entry.header)} isn't a header name`);
    return null;
  }
  if (!methods?.every((method) => TOKEN.test(method))) {
    warnings.push(`${where}: methods must be a list of method names`);
    return null;
  }
  if (!paths?.every((path) => path.startsWith('/'))) {
    warnings.push(`${where}: paths must be a list of paths starting with /`);
    return null;
  }
  const rule: Rule = { domain, header, methods: methods.map((m) => m.toUpperCase()), paths };
  return { secret: entry.secret, rule };
}

export function parseConfig(text: string, warnings: string[]): ConfigPolicy {
  const root = parseToml(text);
  const fallback = typeof root.default_provider === 'string' ? root.default_provider : null;
  const secrets: Record<string, string> = Object.create(null);
  const listed = isTable(root.secrets) ? root.secrets : {};
  for (const [name, entry] of Object.entries(listed)) {
    if (!isTable(entry)) continue;
    const provider = typeof entry.provider === 'string' ? entry.provider : fallback;
    if (provider !== 'seven') continue;
    if (typeof entry.value === 'string' && PLACEHOLDER.test(entry.value))
      secrets[name] = entry.value;
    else warnings.push(`${name}: its value isn't a vault placeholder`);
  }
  const proxy = isTable(root.proxy) ? root.proxy.rules : undefined;
  const entries = Array.isArray(proxy) ? proxy : [];
  const rules: ConfigPolicy['rules'] = [];
  entries.forEach((entry, index) => {
    const parsed = parseRule(entry, index, warnings);
    if (!parsed) return;
    if (!(parsed.secret in secrets)) {
      warnings.push(`proxy rule ${index + 1}: ${parsed.secret} isn't a seven secret in [secrets]`);
      return;
    }
    rules.push(parsed);
  });
  return { secrets, rules };
}

function execEntry(name: string, value: TomlValue, warnings: string[]) {
  if (value === true) return { mode: 'any' as const };
  if (value === false) return null;
  const keys = isTable(value) ? Object.keys(value) : [];
  const only = (key: string) => keys.length === 1 && keys[0] === key;
  if (isTable(value) && only('shell') && value.shell === true) return { mode: 'shell' as const };
  const argv = isTable(value) && only('argv') ? value.argv : undefined;
  const lists = Array.isArray(argv) ? argv.map((item) => strings(item)) : [];
  if (
    lists.length > 0 &&
    lists.every((list) => list && list.length > 0 && list[0].startsWith('/'))
  ) {
    return { mode: 'argv' as const, argv: lists as string[][] };
  }
  warnings.push(`[exec] ${name}: use true, { argv = [["/path", …]] } or { shell = true }`);
  return null;
}

function limits(table: TomlValue | undefined, warnings: string[]): Limits {
  const out = { ...LIMITS };
  if (!isTable(table)) return out;
  for (const field of Object.keys(LIMITS) as (keyof Limits)[]) {
    const value = table[field];
    if (value === undefined) continue;
    if (typeof value === 'number' && Number.isInteger(value) && value > 0) out[field] = value;
    else warnings.push(`[limits] ${field} must be a positive integer`);
  }
  return out;
}

export function parseExtra(text: string, warnings: string[]): ExtraPolicy {
  const root = parseToml(text);
  const exec: ExtraPolicy['exec'] = Object.create(null);
  for (const [name, value] of Object.entries(isTable(root.exec) ? root.exec : {})) {
    const entry = execEntry(name, value, warnings);
    if (entry) exec[name] = entry;
  }
  const exits: ExtraPolicy['exits'] = Object.create(null);
  for (const [name, value] of Object.entries(isTable(root.exits) ? root.exits : {})) {
    const list = strings(value) ?? [];
    const valid = list.filter((exit) => EXIT.test(exit)) as ExitName[];
    if (valid.length !== list.length || !Array.isArray(value)) {
      warnings.push(`[exits] ${name}: only page, proxy, tailscale and device:<name> are exits`);
    }
    exits[name] = valid;
  }
  return { exec, exits, limits: limits(root.limits, warnings) };
}

function ruleKey(secret: string, rule: Rule): string {
  return JSON.stringify([secret, rule.domain, rule.header, rule.methods, rule.paths]);
}

export function diffConfig(before: ConfigPolicy | null, after: ConfigPolicy): PolicyChange[] {
  const old = new Map(
    (before?.rules ?? []).map((entry) => [ruleKey(entry.secret, entry.rule), entry])
  );
  const next = new Map(after.rules.map((entry) => [ruleKey(entry.secret, entry.rule), entry]));
  const changes: PolicyChange[] = [];
  for (const [key, entry] of next) {
    if (!old.has(key))
      changes.push({ kind: 'rule', secret: entry.secret, rule: entry.rule, change: 'added' });
  }
  for (const [key, entry] of old) {
    if (!next.has(key))
      changes.push({ kind: 'rule', secret: entry.secret, rule: entry.rule, change: 'removed' });
  }
  return changes;
}

export function diffExtra(before: ExtraPolicy | null, after: ExtraPolicy): PolicyChange[] {
  const changes: PolicyChange[] = [];
  const names = new Set([...Object.keys(before?.exec ?? {}), ...Object.keys(after.exec)]);
  for (const name of names) {
    const from = before?.exec[name]?.mode ?? false;
    const to = after.exec[name]?.mode ?? false;
    const argv =
      JSON.stringify(before?.exec[name]?.argv) !== JSON.stringify(after.exec[name]?.argv);
    if (from !== to || argv) changes.push({ kind: 'exec', secret: name, from, to });
  }
  const exits = new Set([...Object.keys(before?.exits ?? {}), ...Object.keys(after.exits)]);
  for (const name of exits) {
    const from = before?.exits[name] ?? null;
    const to = after.exits[name] ?? null;
    if (JSON.stringify(from) !== JSON.stringify(to))
      changes.push({ kind: 'exits', secret: name, from, to });
  }
  const old = before?.limits ?? LIMITS;
  for (const field of Object.keys(LIMITS) as (keyof Limits)[]) {
    if (old[field] !== after.limits[field]) {
      changes.push({ kind: 'limits', field, from: old[field], to: after.limits[field] });
    }
  }
  return changes;
}

export type Refuse = (rule: Rule) => boolean;

export function build(accepted: Accepted, refuse: Refuse = () => false): Policy {
  const config = accepted.config?.parsed ?? { secrets: {}, rules: [] };
  const extra = accepted.extra?.parsed ?? { exec: {}, exits: {}, limits: LIMITS };
  const kept = config.rules.filter((entry) => !refuse(entry.rule));
  const refused = config.rules
    .filter((entry) => refuse(entry.rule))
    .map(({ secret, rule }) => ({
      secret,
      rule,
      reason: `${secret}: ${rule.domain} is a model or MCP endpoint; the vault never injects there`,
    }));
  return {
    refused: () => refused,
    placeholder: (name) => (Object.hasOwn(config.secrets, name) ? config.secrets[name] : null),
    rules: (name) => kept.filter((entry) => entry.secret === name).map((entry) => entry.rule),
    exec: (name) => (Object.hasOwn(extra.exec, name) ? extra.exec[name].mode : false),
    argv: (name) => (Object.hasOwn(extra.exec, name) ? (extra.exec[name].argv ?? null) : null),
    exits: (name) => (Object.hasOwn(extra.exits, name) ? extra.exits[name] : null),
    limits: () => extra.limits,
    shells: () =>
      Object.entries(extra.exec)
        .filter(([, entry]) => entry.mode === 'shell')
        .map(([name]) => name)
        .sort(),
    view: () => ({
      file: POLICY_FILE,
      sha256: accepted.extra?.sha256 ?? null,
      restricted: Object.entries(extra.exits)
        .map(([name, exits]) => ({ name, exits }))
        .sort((a, b) => a.name.localeCompare(b.name)),
    }),
  };
}

export const EMPTY: Policy = build(NONE);
