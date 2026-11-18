import assert from 'node:assert/strict';
import { test } from 'node:test';
import { attest, CONFIG, missing, POLICY } from './attest.mjs';
import { setup } from './setup.mjs';

const { embedder } = await setup();

const VALUE = 'fake-config-entry-0001';
const OTHER = 'fake-config-entry-0002';
const OWNER = { pid: 9, ppid: 1, uid: 1000, gid: 1000, tag: 'cone', users: 'enforce' };
const RULE = '[[proxy.rules]]\nsecret = "GITHUB_PAT"\ndomain = "api.github.com"\n';
const SESSION =
  '[[proxy.rules]]\nsecret = "MAIL_PASS"\ndomain = "smtp.example.com"\nprotocol = "smtp"\nposition = "auth-plain"\nport = 587\n';

function configText(entries, rules = RULE) {
  return `default_provider = "seven"\n\n[secrets]\n${entries.join('\n')}\n\n${rules}`;
}

async function sealed(page, name, value) {
  return (
    await page.evaluate(
      (n, v) => window.harness.sealed({ v: 1, op: 'seal', name: n, value: v }),
      name,
      value
    )
  ).placeholder;
}

async function ready(t) {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.connect());
  const pat = await sealed(page, 'GITHUB_PAT', VALUE);
  return { page, pat };
}

function upload(page, files) {
  return page.evaluate((list) => window.harness.policy(list), files);
}

function listed(page) {
  return page.evaluate(() => window.harness.sealed({ v: 1, op: 'list' }));
}

async function forwarded(page, placeholder) {
  const { reply } = await page.evaluate((f) => window.harness.forward(f), {
    head: {
      method: 'GET',
      url: 'https://api.github.com/user',
      headers: [['authorization', `Bearer ${placeholder}`]],
    },
    owner: OWNER,
    exit: 'page',
    bodyPresent: false,
    rawTraits: { manualRedirects: true },
  });
  return reply;
}

function verdict(page, name) {
  return page.evaluate(
    (n) => window.harness.sealed({ v: 1, op: 'test', name: n, url: 'https://api.github.com/user' }),
    name
  );
}

function needed(name, placeholder) {
  return `${name}'s [secrets] entry in /etc/fnox/config.toml needs value = "${placeholder}"`;
}

test('a [secrets] entry without a value leaves its record inert with config-entry in list and forward', async (t) => {
  const { page, pat } = await ready(t);
  const text = configText(['GITHUB_PAT = { provider = "seven", description = "GitHub" }']);
  const reply = await upload(page, [attest(CONFIG, text), attest(POLICY, '')]);
  assert.equal(reply.accepted, true);
  assert.deepEqual(reply.rules, []);
  assert.deepEqual(reply.warnings, [
    "GITHUB_PAT: its value isn't a vault placeholder",
    "proxy rule 1: GITHUB_PAT isn't a seven secret in [secrets]",
  ]);
  assert.deepEqual((await listed(page)).secrets, [
    {
      name: 'GITHUB_PAT',
      placeholder: pat,
      state: 'inert',
      exec: false,
      rules: [],
      configEntry: 'no-value',
    },
  ]);
  const refused = await forwarded(page, pat);
  assert.deepEqual(refused.refused, {
    status: 403,
    reason: needed('GITHUB_PAT', pat),
    cause: 'config-entry',
  });
  const tested = await verdict(page, 'GITHUB_PAT');
  assert.equal(tested.verdict, 'refuse');
  assert.equal(tested.cause, 'config-entry');
  const seen = JSON.stringify([refused, tested, await listed(page)]);
  assert.ok(!seen.includes(VALUE));
});

test('a correct [secrets] entry stays active and has no configEntry', async (t) => {
  const { page, pat } = await ready(t);
  const text = configText([`GITHUB_PAT = { provider = "seven", value = "${pat}" }`]);
  const reply = await upload(page, [attest(CONFIG, text), attest(POLICY, '')]);
  assert.deepEqual(reply.warnings, []);
  const [entry] = (await listed(page)).secrets;
  assert.equal(entry.state, 'active');
  assert.equal('configEntry' in entry, false);
  assert.equal((await verdict(page, 'GITHUB_PAT')).verdict, 'inject');
});

test('another record placeholder, a non-placeholder value and a missing entry each give their own reason', async (t) => {
  const { page, pat } = await ready(t);
  const other = await sealed(page, 'OTHER_PAT', OTHER);
  await sealed(page, 'PLAIN_PAT', OTHER);
  await sealed(page, 'LOOSE_PAT', OTHER);
  const text = configText(
    [
      `GITHUB_PAT = { provider = "seven", value = "${other}" }`,
      `OTHER_PAT = { provider = "seven", value = "${other}" }`,
      'PLAIN_PAT = { provider = "seven", value = "not-a-placeholder-value" }',
    ],
    `${RULE}\n[[proxy.rules]]\nsecret = "OTHER_PAT"\ndomain = "api.github.com"\n\n[[proxy.rules]]\nsecret = "LOOSE_PAT"\ndomain = "api.github.com"\n`
  );
  const reply = await upload(page, [attest(CONFIG, text), attest(POLICY, '')]);
  assert.equal(reply.accepted, true);
  const reasons = Object.fromEntries(
    (await listed(page)).secrets.map((s) => [s.name, [s.state, s.configEntry ?? null]])
  );
  assert.deepEqual(reasons, {
    GITHUB_PAT: ['inert', 'wrong-placeholder'],
    LOOSE_PAT: ['inert', 'no-entry'],
    OTHER_PAT: ['active', null],
    PLAIN_PAT: ['inert', 'not-a-placeholder'],
  });
  const refused = await forwarded(page, pat);
  assert.equal(refused.refused.cause, 'config-entry');
  assert.equal(refused.refused.reason, needed('GITHUB_PAT', pat));
});

test('a session use of a record whose entry has no value is refused with config-entry', async (t) => {
  const { page } = await ready(t);
  const mail = await sealed(page, 'MAIL_PASS', OTHER);
  const text = configText(['MAIL_PASS = { provider = "seven" }'], SESSION);
  await upload(page, [attest(CONFIG, text), attest(POLICY, '')]);
  const reply = await page.evaluate((f) => window.harness.call('sessionMaterialize', f), {
    stamp: OWNER,
    session: `config-entry-session-${process.pid}-0000`,
    host: 'smtp.example.com',
    port: 587,
    protocol: 'smtp',
    position: 'auth-plain',
    verified: true,
    handshakeAt: Date.now(),
    exit: 'page',
    placeholders: [mail],
  });
  assert.deepEqual(reply.error, {
    code: 'EACCES',
    message: `session refused: ${needed('MAIL_PASS', mail)}`,
    cause: 'config-entry',
  });
});

test('a paused policy still refuses a dropped entry with policy-paused', async (t) => {
  const { page, pat } = await ready(t);
  const text = configText(['GITHUB_PAT = { provider = "seven" }']);
  await upload(page, [attest(CONFIG, text), missing(POLICY)]);
  assert.equal((await forwarded(page, pat)).refused.cause, 'policy-paused');
  assert.equal((await verdict(page, 'GITHUB_PAT')).cause, 'policy-paused');
});

test('fixing a dropped entry is accepted as an added rule, and nothing else changes', async (t) => {
  const { page, pat } = await ready(t);
  await upload(page, [attest(CONFIG, configText(['GITHUB_PAT = { provider = "seven" }']))]);
  const fixed = configText([`GITHUB_PAT = { provider = "seven", value = "${pat}" }`]);
  const reply = await upload(page, [attest(CONFIG, fixed)]);
  assert.equal(reply.accepted, true);
  assert.deepEqual(
    reply.rules.map((rule) => [rule.secret, rule.domain]),
    [['GITHUB_PAT', 'api.github.com']]
  );
  const audit = (await page.evaluate(() => window.harness.call('audit', { limit: 2 }))).audit;
  assert.deepEqual(
    audit.map((entry) => [entry.type, entry.accepted, entry.changes.map((c) => c.change)]),
    [
      ['policy', true, ['added']],
      ['policy', true, []],
    ]
  );
  const [entry] = (await listed(page)).secrets;
  assert.equal(entry.state, 'active');
  assert.equal('configEntry' in entry, false);
});
