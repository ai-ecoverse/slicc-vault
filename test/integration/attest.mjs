import { createHash } from 'node:crypto';

export const CONFIG = '/etc/fnox/config.toml';
export const POLICY = '/etc/slicc/secrets-policy.toml';

function ancestors(path) {
  const parts = path.split('/').slice(1, -1);
  return ['/', ...parts.map((_, i) => `/${parts.slice(0, i + 1).join('/')}`)].map((dir) => ({
    path: dir,
    uid: 0,
    gid: 0,
    mode: 0o40755,
  }));
}

export function missing(path, overrides = {}) {
  return {
    path,
    absent: true,
    users: 'enforce',
    onRootFs: true,
    parents: ancestors(path),
    ...overrides,
  };
}

export function attest(path, text, overrides = {}) {
  const bytes = Buffer.from(text);
  const parents = ancestors(path);
  return {
    path,
    bytes: bytes.toString('base64'),
    uid: 0,
    gid: 0,
    mode: 0o100644,
    ino: 42,
    mtimeMs: 1760000000000,
    sha256: createHash('sha256').update(bytes).digest('hex'),
    users: 'enforce',
    onRootFs: true,
    parents,
    ...overrides,
  };
}

export function config(entries, rules) {
  const secrets = Object.entries(entries)
    .map(([name, placeholder]) => `${name} = { provider = "seven", value = "${placeholder}" }`)
    .join('\n');
  const stanzas = rules
    .map(
      (rule) =>
        `[[proxy.rules]]\nsecret = "${rule.secret}"\ndomain = "${rule.domain}"\n${
          rule.header ? `header = "${rule.header}"\n` : ''
        }${
          rule.methods ? `methods = ${JSON.stringify(rule.methods)}\n` : ''
        }${rule.paths ? `paths = ${JSON.stringify(rule.paths)}\n` : ''}`
    )
    .join('\n');
  return `default_provider = "seven"\n\n[providers.seven]\ntype = "sealed"\n\n[secrets]\n${secrets}\n\n${stanzas}`;
}
