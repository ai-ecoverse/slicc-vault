import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';

const CONFIG = `default_provider = "seven"

[providers.seven]
type = "sealed"

[secrets]
GITHUB_TOKEN = { provider = "seven", value = "fnox_proxy_0123456789abcdef01234567" }

[[proxy.rules]]
secret = "GITHUB_TOKEN"
domain = "api.github.com"
methods = ["GET"]
`;
const POLICY = `[exec]
NPM_TOKEN = true

[exits]
NPM_TOKEN = ["page"]
`;

function attestation(path, text, change = (a) => a) {
  const bytes = Buffer.from(text);
  const parts = path.split('/').slice(1, -1);
  const parents = ['/', ...parts.map((_, i) => `/${parts.slice(0, i + 1).join('/')}`)].map(
    (dir) => ({
      path: dir,
      uid: 0,
      gid: 0,
      mode: 0o40755,
    })
  );
  return change({
    path,
    bytes: bytes.toString('base64'),
    uid: 0,
    gid: 0,
    mode: 0o100644,
    ino: 1024,
    mtimeMs: 1760300000000,
    sha256: createHash('sha256').update(bytes).digest('hex'),
    users: 'enforce',
    onRootFs: true,
    parents,
  });
}

const config = '/etc/fnox/config.toml';
const policy = '/etc/slicc/secrets-policy.toml';
const cases = {
  'good-config': ['the root-owned config.toml', true, '', attestation(config, CONFIG)],
  'good-policy': ['the root-owned secrets-policy.toml', true, '', attestation(policy, POLICY)],
  'bad-uid': [
    'owned by uid 1000',
    false,
    "isn't root-owned",
    attestation(config, CONFIG, (a) => ({ ...a, uid: 1000 })),
  ],
  'bad-group-writable': [
    'mode 0664',
    false,
    'writable by group or others',
    attestation(config, CONFIG, (a) => ({ ...a, mode: 0o100664 })),
  ],
  'bad-other-writable': [
    'mode 0646',
    false,
    'writable by group or others',
    attestation(config, CONFIG, (a) => ({ ...a, mode: 0o100646 })),
  ],
  'bad-not-regular': [
    'a symlink type in mode',
    false,
    "isn't a regular file",
    attestation(config, CONFIG, (a) => ({ ...a, mode: 0o120644 })),
  ],
  'bad-sha256': [
    'sha256 of other bytes',
    false,
    "don't match the attestation",
    attestation(config, CONFIG, (a) => ({
      ...a,
      sha256: createHash('sha256').update('other').digest('hex'),
    })),
  ],
  'bad-sha256-format': [
    'sha256 in upper case',
    false,
    "isn't in the kernel's format",
    attestation(config, CONFIG, (a) => ({ ...a, sha256: a.sha256.toUpperCase() })),
  ],
  'bad-users-report': [
    "users 'report'",
    false,
    'kernel users must be enforce',
    attestation(config, CONFIG, (a) => ({ ...a, users: 'report' })),
  ],
  'bad-users-off': [
    "users 'off'",
    false,
    'kernel users must be enforce',
    attestation(config, CONFIG, (a) => ({ ...a, users: 'off' })),
  ],
  'bad-users-unknown': [
    "users 'maybe'",
    false,
    "isn't in the kernel's format",
    attestation(config, CONFIG, (a) => ({ ...a, users: 'maybe' })),
  ],
  'bad-mount': [
    'under a mount',
    false,
    "isn't on the root file system",
    attestation(config, CONFIG, (a) => ({ ...a, onRootFs: false })),
  ],
  'bad-parent-owner': [
    '/etc/fnox owned by uid 1000',
    false,
    "a parent directory isn't root-owned",
    attestation(config, CONFIG, (a) => ({
      ...a,
      parents: a.parents.map((p) => (p.path === '/etc/fnox' ? { ...p, uid: 1000 } : p)),
    })),
  ],
  'bad-parent-writable': [
    '/etc writable by others',
    false,
    "a parent directory isn't root-owned",
    attestation(config, CONFIG, (a) => ({
      ...a,
      parents: a.parents.map((p) => (p.path === '/etc' ? { ...p, mode: 0o40777 } : p)),
    })),
  ],
  'bad-parent-type': [
    '/etc/fnox not a directory',
    false,
    "a parent directory isn't root-owned",
    attestation(config, CONFIG, (a) => ({
      ...a,
      parents: a.parents.map((p) => (p.path === '/etc/fnox' ? { ...p, mode: 0o100755 } : p)),
    })),
  ],
  'bad-parents-missing': [
    'no entry for /',
    false,
    "parents aren't exactly",
    attestation(config, CONFIG, (a) => ({ ...a, parents: a.parents.slice(1) })),
  ],
  'bad-parents-order': [
    'parents out of order',
    false,
    "parents aren't exactly",
    attestation(config, CONFIG, (a) => ({ ...a, parents: [...a.parents].reverse() })),
  ],
  'bad-path': [
    'a path that is not a policy file',
    false,
    "isn't a policy file",
    attestation('/etc/passwd', CONFIG),
  ],
  'bad-extra-field': [
    'an unknown field',
    false,
    "isn't in the kernel's format",
    attestation(config, CONFIG, (a) => ({ ...a, signature: 'x' })),
  ],
  'bad-missing-field': [
    'no ino',
    false,
    "isn't in the kernel's format",
    attestation(config, CONFIG, ({ ino, ...a }) => a),
  ],
  'bad-parent-field': [
    'a parent without gid',
    false,
    "isn't in the kernel's format",
    attestation(config, CONFIG, (a) => ({ ...a, parents: a.parents.map(({ gid, ...p }) => p) })),
  ],
  'bad-utf8': [
    'bytes that are not UTF-8',
    false,
    "isn't UTF-8",
    (() => {
      const a = attestation(config, '');
      const bytes = Buffer.from([0xff, 0xfe, 0x00]);
      return {
        ...a,
        bytes: bytes.toString('base64'),
        sha256: createHash('sha256').update(bytes).digest('hex'),
      };
    })(),
  ],
};
for (const [name, [description, trusted, reason, value]] of Object.entries(cases)) {
  const fixture = { description, trusted, ...(trusted ? {} : { reason }), attestation: value };
  writeFileSync(new URL(`${name}.json`, import.meta.url), `${JSON.stringify(fixture, null, 2)}\n`);
}
