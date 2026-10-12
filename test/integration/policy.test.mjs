import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { attest, CONFIG, config, POLICY } from './attest.mjs';
import { setup } from './setup.mjs';

const { embedder } = await setup();

const seal = (name, value) => window.harness.sealed({ v: 1, op: 'seal', name, value });
const upload = (files) => window.harness.policy(files);
const sealedList = () => window.harness.sealed({ v: 1, op: 'list' });

async function connected(t, name = 'seven', tab = null) {
  const page = await embedder(t, name, tab);
  await page.evaluate(() => window.harness.connect());
  return page;
}

test('an attested config.toml activates its rules', async (t) => {
  const page = await connected(t);
  const gh = await page.evaluate(seal, 'GITHUB_TOKEN', 'ghp_value_for_rules');
  const npm = await page.evaluate(seal, 'NPM_TOKEN', 'npm_value_for_rules');
  const text = config(
    { GITHUB_TOKEN: gh.placeholder, NPM_TOKEN: 'fnox_proxy_000000000000000000000000' },
    [
      {
        secret: 'GITHUB_TOKEN',
        domain: 'API.GitHub.com',
        methods: ['get', 'POST'],
        paths: ['/repos/*'],
      },
      { secret: 'GITHUB_TOKEN', domain: 'uploads.github.com' },
      { secret: 'NPM_TOKEN', domain: 'registry.npmjs.org' },
      { secret: 'OTHER', domain: 'example.com' },
      { secret: 'GITHUB_TOKEN', domain: '*.github.com' },
    ]
  );
  const reply = await page.evaluate(upload, [attest(CONFIG, text)]);
  assert.equal(reply.accepted, true);
  assert.deepEqual(
    reply.rules.map((rule) => [rule.secret, rule.domain, rule.header, rule.methods, rule.paths]),
    [
      ['GITHUB_TOKEN', 'api.github.com', 'authorization', ['GET', 'POST'], ['/repos/*']],
      ['GITHUB_TOKEN', 'uploads.github.com', 'authorization', [], []],
      ['NPM_TOKEN', 'registry.npmjs.org', 'authorization', [], []],
    ]
  );
  assert.equal(reply.files[0].warnings.length, 2);
  await page.until(() =>
    window.harness.events.some((e) => e.event === 'changed' && e.parts.includes('exits'))
  );
  const listed = await page.evaluate(sealedList);
  assert.deepEqual(
    listed.secrets.map((s) => [s.name, s.state, s.rules.length]),
    [
      ['GITHUB_TOKEN', 'active', 2],
      ['NPM_TOKEN', 'inert', 0],
    ]
  );
  const shown = (await page.evaluate(() => window.harness.call('list'))).list.secrets;
  assert.deepEqual(shown[0].domains, ['api.github.com', 'uploads.github.com']);
  assert.equal(npm.state, 'inert');
  const looked = await page.evaluate(() =>
    window.harness.sealed({ v: 1, op: 'placeholder', name: 'GITHUB_TOKEN' })
  );
  assert.equal(looked.state, 'active');
  await page.reload();
  await page.until(() => document.title === 'ready');
  await page.evaluate(() => window.harness.connect());
  const again = await page.evaluate(sealedList);
  assert.equal(again.secrets[0].state, 'active');
  const narrowed = await page.evaluate(upload, [
    attest(CONFIG, config({ GITHUB_TOKEN: gh.placeholder }, [])),
  ]);
  assert.equal(narrowed.accepted, true);
  assert.deepEqual(narrowed.rules, []);
  assert.equal((await page.evaluate(sealedList)).secrets[0].state, 'inert');
  const audit = (await page.evaluate(() => window.harness.call('audit', { limit: 2 }))).audit;
  assert.deepEqual(
    audit.map((entry) => [entry.type, entry.accepted, entry.changes.map((c) => c.change)]),
    [
      ['policy', true, ['removed', 'removed', 'removed']],
      ['policy', true, ['added', 'added', 'added']],
    ]
  );
  const preview = await connected(t, 'preview', await page.tab());
  assert.deepEqual(
    (await preview.evaluate(() => window.harness.call('list'))).list.exits.restricted,
    []
  );
});

test('files the kernel did not attest as root-owned are not trusted', async (t) => {
  const page = await connected(t);
  const gh = await page.evaluate(seal, 'GITHUB_TOKEN', 'ghp_value_for_rules');
  const text = config({ GITHUB_TOKEN: gh.placeholder }, [
    { secret: 'GITHUB_TOKEN', domain: 'api.github.com' },
  ]);
  assert.equal((await page.evaluate(upload, [attest(CONFIG, text)])).accepted, true);
  const wider = config({ GITHUB_TOKEN: gh.placeholder }, [
    { secret: 'GITHUB_TOKEN', domain: 'evil.example.com' },
  ]);
  const cases = [
    [{ uid: 1000 }, "isn't root-owned"],
    [{ mode: 0o100666 }, 'writable by group or others'],
    [
      {
        parents: [
          { path: '/', uid: 0, gid: 0, mode: 0o40755 },
          { path: '/etc', uid: 0, gid: 0, mode: 0o40755 },
          { path: '/etc/fnox', uid: 1000, gid: 0, mode: 0o40755 },
        ],
      },
      'parent directory',
    ],
    [
      {
        parents: [
          { path: '/', uid: 0, gid: 0, mode: 0o40755 },
          { path: '/etc', uid: 0, gid: 0, mode: 0o40777 },
          { path: '/etc/fnox', uid: 0, gid: 0, mode: 0o40755 },
        ],
      },
      'parent directory',
    ],
    [{ parents: [] }, "parents aren't exactly"],
    [{ onRootFs: false }, 'root file system'],
    [{ users: 'report' }, 'kernel users must be enforce'],
    [{ sha256: '0'.repeat(64) }, "don't match the attestation"],
    [{ sha256: '00' }, "isn't in the kernel's format"],
  ];
  for (const [overrides, reason] of cases) {
    const reply = await page.evaluate(upload, [attest(CONFIG, wider, overrides)]);
    assert.equal(reply.accepted, false, reason);
    assert.match(
      reply.warnings[0],
      new RegExp(`^rules not trusted: /etc/fnox/config.toml: .*${reason}`)
    );
  }
  const odd = await page.evaluate(upload, [attest('/etc/passwd', wider)]);
  assert.match(odd.warnings[0], /isn't a policy file/);
  const broken = await page.evaluate(upload, [attest(CONFIG, '[secrets\nX = 1')]);
  assert.match(broken.warnings[0], /line 1/);
  const { bytes, ...none } = attest(CONFIG, wider);
  const missing = await page.evaluate(upload, [none]);
  assert.match(missing.warnings[0], /kernel's format/);
  const status = await page.evaluate(
    async () => (await window.harness.call('status')).status.policy
  );
  assert.equal(status[0].accepted, false);
  assert.ok(bytes);
  const listed = await page.evaluate(sealedList);
  assert.deepEqual(
    listed.secrets[0].rules.map((rule) => rule.domain),
    ['api.github.com']
  );
  const audit = (await page.evaluate(() => window.harness.call('audit', { limit: 100 }))).audit;
  assert.ok(audit.filter((entry) => entry.type === 'policy' && !entry.accepted).length >= 2);
});

test('secrets-policy.toml sets exec, exits and limits', async (t) => {
  const page = await connected(t);
  const gh = await page.evaluate(seal, 'GITHUB_TOKEN', 'ghp_value_for_rules');
  await page.evaluate(seal, 'NPM_TOKEN', 'npm_value_for_rules');
  await page.evaluate(seal, 'OPENAI_API_KEY', 'sk-value-for-shell');
  const extra = `[exec]
NPM_TOKEN = true
GITHUB_TOKEN = { argv = [["/usr/bin/gh", "release", "upload"]] }
OPENAI_API_KEY = { shell = true }
BAD = "yes"

[exits]
NPM_TOKEN = ["page", "device:lars-air"]
GITHUB_TOKEN = ["page", "carrier-pigeon"]

[limits]
materialize_per_minute = 5
materialize_per_day = -1
`;
  const reply = await page.evaluate(upload, [
    attest(
      CONFIG,
      config({ GITHUB_TOKEN: gh.placeholder }, [
        { secret: 'GITHUB_TOKEN', domain: 'api.github.com' },
      ])
    ),
    attest(POLICY, extra),
  ]);
  assert.equal(reply.accepted, true);
  assert.equal(reply.files[1].warnings.length, 3);
  const listed = await page.evaluate(sealedList);
  assert.deepEqual(
    listed.secrets.map((s) => [s.name, s.exec]),
    [
      ['GITHUB_TOKEN', 'argv'],
      ['NPM_TOKEN', 'any'],
      ['OPENAI_API_KEY', 'shell'],
    ]
  );
  const list = (await page.evaluate(() => window.harness.call('list'))).list;
  const byName = Object.fromEntries(list.secrets.map((s) => [s.name, s]));
  assert.deepEqual(byName.GITHUB_TOKEN.execArgv, [['/usr/bin/gh', 'release', 'upload']]);
  assert.deepEqual(byName.NPM_TOKEN.exits, ['page', 'device:lars-air']);
  assert.deepEqual(byName.GITHUB_TOKEN.exits, ['page']);
  assert.equal(byName.OPENAI_API_KEY.exits, undefined);
  assert.equal(list.exits.file, '/etc/slicc/secrets-policy.toml');
  assert.match(list.exits.sha256, /^[0-9a-f]{64}$/);
  assert.deepEqual(
    list.exits.restricted.map((r) => r.name),
    ['GITHUB_TOKEN', 'NPM_TOKEN']
  );
  const audit = (await page.evaluate(() => window.harness.call('audit', { limit: 1 }))).audit[0];
  assert.equal(audit.file, '/etc/slicc/secrets-policy.toml');
  assert.deepEqual(audit.changes.map((c) => c.kind).sort(), [
    'exec',
    'exec',
    'exec',
    'exits',
    'exits',
    'limits',
  ]);
});

test('the KS-7 conformance fixtures', async (t) => {
  const page = await connected(t);
  const dir = new URL('./fixtures/attest/', import.meta.url);
  const names = (await readdir(dir)).filter((name) => name.endsWith('.json')).sort();
  assert.ok(names.length >= 20);
  for (const name of names) {
    const fixture = JSON.parse(await readFile(new URL(name, dir), 'utf8'));
    const reply = await page.evaluate(upload, [fixture.attestation]);
    assert.equal(reply.files[0].accepted, fixture.trusted, `${name}: ${reply.warnings.join(' ')}`);
    if (!fixture.trusted)
      assert.ok(reply.warnings[0].includes(fixture.reason), `${name}: ${reply.warnings[0]}`);
  }
});
