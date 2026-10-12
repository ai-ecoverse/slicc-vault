import { createHash } from 'node:crypto';

export const CONFIG = '/etc/fnox/config.toml';
export const POLICY = '/etc/slicc/secrets-policy.toml';

export function attest(path, text, overrides = {}) {
  const sha256 = createHash('sha256').update(text).digest('hex');
  const dir = path.slice(0, path.lastIndexOf('/'));
  return {
    path,
    bytes: text,
    attestation: {
      path,
      uid: 0,
      gid: 0,
      mode: 0o100644,
      ino: 42,
      mtimeMs: 1760000000000,
      sha256,
      users: 'enforce',
      onRootFs: true,
      parents: [
        { path: dir, uid: 0, mode: 0o40755 },
        { path: '/etc', uid: 0, mode: 0o40755 },
        { path: '/', uid: 0, mode: 0o40755 },
      ],
      ...overrides,
    },
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
          rule.methods ? `methods = ${JSON.stringify(rule.methods)}\n` : ''
        }${rule.paths ? `paths = ${JSON.stringify(rule.paths)}\n` : ''}`
    )
    .join('\n');
  return `default_provider = "seven"\n\n[providers.seven]\ntype = "sealed"\n\n[secrets]\n${secrets}\n\n${stanzas}`;
}
