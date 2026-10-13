import assert from 'node:assert/strict';
import { test } from 'node:test';
import { kdbx } from './kdbx.mjs';
import { setup } from './setup.mjs';

const { embedder } = await setup();

const PASSPHRASE = 'fake backup passphrase';
const shared = {};
const bytes64 = (text) => Buffer.from(text).toString('base64');

async function connected(t, name = 'seven', tab = null) {
  const page = await embedder(t, name, tab);
  await page.evaluate(() => window.harness.connect());
  return page;
}

const importing = (page, fields) =>
  page.evaluate((f) => {
    const bytes = Uint8Array.from(atob(f.bytes), (c) => c.charCodeAt(0));
    return window.harness.call('import', { ...f, bytes });
  }, fields);

test('export a backup, which another embedder of the same vault cannot take over', async (t) => {
  const page = await connected(t);
  const a = await page.evaluate(() =>
    window.harness.call('put', { name: 'TOKEN_A', value: 'fake-backup-value-0001' })
  );
  await page.evaluate(() =>
    window.harness.call('seal', {
      name: 'ANTHROPIC',
      value: 'fake-model-key-0002',
      source: 'settings',
      kind: 'model',
    })
  );
  await page.evaluate(() =>
    window.harness.call('seal', {
      name: 'REFRESH',
      value: 'fake-grant-value-0003',
      source: 'oauth:x',
      kind: 'grant',
    })
  );
  const short = await page.evaluate(() => window.harness.call('export', { passphrase: 'short' }));
  assert.equal(short.error.code, 'EINVAL');
  const before = (await page.evaluate(() => window.harness.call('status'))).status;
  assert.equal(before.exportedAt, null);
  const exported = await page.evaluate(async (p) => {
    const reply = await window.harness.call('export', { passphrase: p });
    return { count: reply.count, bundle: btoa(String.fromCharCode(...reply.bundle)) };
  }, PASSPHRASE);
  assert.equal(exported.count, 2);
  const text = Buffer.from(exported.bundle, 'base64').toString();
  assert.ok(!text.includes('fake-backup-value'));
  assert.equal(JSON.parse(text).format, 'slicc-vault-bundle');
  const after = (await page.evaluate(() => window.harness.call('status'))).status;
  assert.ok(after.exportedAt > 0);
  assert.equal(after.backupReminder, null);
  const crossed = await connected(t, 'preview', await page.tab());
  const taken = await importing(crossed, {
    kind: 'bundle',
    bytes: exported.bundle,
    password: PASSPHRASE,
  });
  assert.ok(taken.candidates.every((c) => /another embedder/.test(c.refused)));
  shared.bundle = exported.bundle;
  shared.placeholder = a.placeholder;
});

test('the backup imports into another vault with its placeholders', async (t) => {
  const { bundle, placeholder } = shared;
  const exported = { bundle };
  const a = { placeholder };
  const fresh = await connected(t);
  const wrong = await importing(fresh, {
    kind: 'bundle',
    bytes: exported.bundle,
    password: 'not the passphrase',
  });
  assert.equal(wrong.error.code, 'EACCES');
  const pick = await importing(fresh, {
    kind: 'bundle',
    bytes: exported.bundle,
    password: PASSPHRASE,
  });

  assert.deepEqual(pick.candidates.map((c) => [c.name, c.kind, c.exists]).sort(), [
    ['ANTHROPIC', 'model', false],
    ['TOKEN_A', 'secret', false],
  ]);
  const done = await importing(fresh, {
    kind: 'bundle',
    bytes: exported.bundle,
    password: PASSPHRASE,
    pick: ['TOKEN_A', 'NOPE'],
  });
  assert.deepEqual(
    done.imported.map((r) => [r.name, r.placeholder]),
    [['TOKEN_A', a.placeholder]]
  );
  assert.deepEqual(done.skipped, ['NOPE']);
  const listed = await fresh.evaluate(() =>
    window.harness.sealed({ v: 1, op: 'placeholder', name: 'TOKEN_A' })
  );
  assert.equal(listed.placeholder, a.placeholder);
  const red = await fresh.evaluate(async () => {
    await window.harness.agent();
    return window.harness.ask('redact', { texts: ['x fake-backup-value-0001 y'] });
  });
  assert.equal(red.texts[0], `x ${a.placeholder} y`);
  const garbage = await importing(fresh, {
    kind: 'bundle',
    bytes: bytes64('not json'),
    password: PASSPHRASE,
  });
  assert.match(garbage.error.message, /isn't a vault backup/);
});

test("six's secrets.env becomes records and suggested rules", async (t) => {
  const page = await connected(t);
  const env = [
    '# six secrets',
    'GITHUB_TOKEN=fake-six-value-0001',
    'GITHUB_TOKEN_DOMAINS=api.github.com,*.github.com',
    'export NPM_TOKEN="fake-six-value-0002"',
    'TINY=abc',
    'bad line',
  ].join('\n');
  const pick = await importing(page, { kind: 'six', bytes: bytes64(env) });
  const byName = Object.fromEntries(pick.candidates.map((c) => [c.name, c]));
  assert.deepEqual(Object.keys(byName).sort(), ['GITHUB_TOKEN', 'NPM_TOKEN', 'TINY']);
  assert.match(
    byName.GITHUB_TOKEN.suggestedRules,
    /\[\[proxy.rules\]\]\nsecret = "GITHUB_TOKEN"\ndomain = "api.github.com"/
  );
  assert.match(byName.GITHUB_TOKEN.suggestedRules, /\*\.github\.com is a wildcard/);
  assert.match(byName.TINY.refused, /shorter than 8 bytes/);
  const done = await importing(page, {
    kind: 'six',
    bytes: bytes64(env),
    pick: ['GITHUB_TOKEN', 'NPM_TOKEN', 'TINY'],
  });
  assert.deepEqual(
    done.imported.map((r) => r.name),
    ['GITHUB_TOKEN', 'NPM_TOKEN']
  );
  assert.deepEqual(done.skipped, ['TINY']);
  const list = (await page.evaluate(() => window.harness.call('list'))).list.secrets;
  assert.deepEqual(
    list.map((s) => s.source),
    ['import:six', 'import:six']
  );
});

test('a KeePass file is opened with its master password, lazily', async (t) => {
  const page = await connected(t);
  const file = await kdbx('fake-master-password', [
    ['Deploy key', 'fake-keepass-value-0001'],
    ['2nd: API token', 'fake-keepass-value-0002'],
    ['tiny', 'x1'],
  ]);
  const wrong = await importing(page, { kind: 'keepass', bytes: file, password: 'wrong' });
  assert.equal(wrong.error.code, 'EACCES');
  const pick = await importing(page, {
    kind: 'keepass',
    bytes: file,
    password: 'fake-master-password',
  });
  assert.deepEqual(pick.candidates.map((c) => c.name).sort(), [
    'DEPLOY_KEY',
    'TINY',
    '_2ND_API_TOKEN',
  ]);
  const done = await importing(page, {
    kind: 'keepass',
    bytes: file,
    password: 'fake-master-password',
    pick: ['DEPLOY_KEY'],
  });
  assert.deepEqual(
    done.imported.map((r) => r.name),
    ['DEPLOY_KEY']
  );
  const missing = await importing(page, { kind: 'keepass', bytes: file });
  assert.equal(missing.error.code, 'EINVAL');
  const seen = await page.evaluate(() => JSON.stringify(window.harness.seen));
  assert.ok(!seen.includes('fake-keepass-value'));
});
