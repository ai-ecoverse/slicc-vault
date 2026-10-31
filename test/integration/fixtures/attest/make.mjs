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

function ancestors(path) {
  const parts = path.split('/').slice(1, -1);
  return ['/', ...parts.map((_, i) => `/${parts.slice(0, i + 1).join('/')}`)].map((dir) => ({
    path: dir,
    uid: 0,
    gid: 0,
    mode: 0o40755,
  }));
}

function absence(path, change = (a) => a) {
  return change({
    path,
    absent: true,
    users: 'enforce',
    onRootFs: true,
    parents: ancestors(path),
  });
}

function attestation(path, text, change = (a) => a) {
  const bytes = Buffer.from(text);
  const parents = ancestors(path);
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
  'good-absent': ['a missing config.toml', true, '', absence(config)],
  'good-absent-policy': ['a missing secrets-policy.toml', true, '', absence(policy)],
  'bad-absent-short-prefix': [
    'parents stop above a missing directory',
    false,
    "parents aren't exactly",
    absence(config, (a) => ({ ...a, parents: a.parents.slice(0, 2) })),
  ],
  'bad-absent-gap': [
    'no entry for /etc',
    false,
    "parents aren't exactly",
    absence(config, (a) => ({ ...a, parents: a.parents.filter((p) => p.path !== '/etc') })),
  ],
  'bad-absent-foreign-parent': [
    'a directory that is not above the path',
    false,
    "parents aren't exactly",
    absence(config, (a) => ({
      ...a,
      parents: a.parents.map((p) => (p.path === '/etc/fnox' ? { ...p, path: '/tmp' } : p)),
    })),
  ],
  'bad-absent-untrusted-parent': [
    '/etc/fnox owned by uid 1000',
    false,
    "a parent directory isn't root-owned",
    absence(config, (a) => ({
      ...a,
      parents: a.parents.map((p) => (p.path === '/etc/fnox' ? { ...p, uid: 1000 } : p)),
    })),
  ],
  'bad-absent-writable-parent': [
    '/etc writable by others',
    false,
    "a parent directory isn't root-owned",
    absence(config, (a) => ({
      ...a,
      parents: a.parents.map((p) => (p.path === '/etc' ? { ...p, mode: 0o40777 } : p)),
    })),
  ],
  'bad-absent-parent-type': [
    '/etc/fnox not a directory',
    false,
    "a parent directory isn't root-owned",
    absence(config, (a) => ({
      ...a,
      parents: a.parents.map((p) => (p.path === '/etc/fnox' ? { ...p, mode: 0o100755 } : p)),
    })),
  ],
  'bad-absent-users-off': [
    "users 'off'",
    false,
    'kernel users must be enforce',
    absence(config, (a) => ({ ...a, users: 'off' })),
  ],
  'bad-absent-mount': [
    'under a mount',
    false,
    "isn't on the root file system",
    absence(config, (a) => ({ ...a, onRootFs: false })),
  ],
  'bad-absent-path': [
    'a path that is not a policy file',
    false,
    "isn't a policy file",
    absence('/etc/passwd'),
  ],
  'bad-absent-extra-fields': [
    'the stats of a file on a missing file',
    false,
    "isn't in the kernel's format",
    absence(config, (a) => ({ ...a, uid: 0, mode: 0o100644 })),
  ],
  'bad-absent-with-bytes': [
    'bytes on a missing file',
    false,
    "isn't in the kernel's format",
    { ...attestation(config, CONFIG), absent: true },
  ],
  'bad-absent-false': [
    'absent false',
    false,
    "isn't in the kernel's format",
    absence(config, (a) => ({ ...a, absent: false })),
  ],
  'bad-absent-string': [
    'absent as a string',
    false,
    "isn't in the kernel's format",
    absence(config, (a) => ({ ...a, absent: 'true' })),
  ],
  'bad-absent-no-parents': [
    'no parents',
    false,
    "isn't in the kernel's format",
    absence(config, ({ parents, ...a }) => a),
  ],
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
