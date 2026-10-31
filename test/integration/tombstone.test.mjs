import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { attest, CONFIG, config, missing, POLICY } from './attest.mjs';
import { setup } from './setup.mjs';

const { embedder } = await setup();

const SECRET = 'fake-absent-secret-0701';
const MAIL = 'fake-absent-mail-0702';
const TOKEN = 'fake-absent-mcp-0703';
const OWNER = { pid: 9, ppid: 1, uid: 1000, gid: 1000, tag: 'cone', users: 'enforce' };
const CHILD = { ...OWNER, pid: 10, ppid: 9 };
const API = 'https://api.example.com/v1/items';
const PAUSED = 'policy file missing: paused';
const EXTRA = '[exec]\nTOKEN_A = true\n\n[exits]\nTOKEN_A = ["page"]\n';
const ASK = { names: ['TOKEN_A'], path: '/usr/bin/npm', argv: ['npm'], cwd: '/home/cone' };

const upload = (page, files) => page.evaluate((list) => window.harness.policy(list), files);

async function ready(t) {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.connect());
  const seal = (name, value) =>
    page.evaluate(
      (n, v) => window.harness.sealed({ v: 1, op: 'seal', name: n, value: v }),
      name,
      value
    );
  const a = (await seal('TOKEN_A', SECRET)).placeholder;
  const mail = (await seal('MAIL_PASS', MAIL)).placeholder;
  const text = `${config({ TOKEN_A: a, MAIL_PASS: mail }, [
    { secret: 'TOKEN_A', domain: 'api.example.com' },
  ])}
[[proxy.rules]]
secret = "MAIL_PASS"
domain = "smtp.example.com"
protocol = "smtp"
position = "auth-plain"
port = 587
anchors = []
pins = ["${btoa('p'.repeat(32))}"]
roots = true
`;
  const files = [attest(CONFIG, text), attest(POLICY, EXTRA)];
  const reply = await upload(page, files);
  assert.equal(reply.accepted, true, reply.warnings.join(' '));
  return { page, a, mail, files };
}

function call(placeholder) {
  return {
    head: { method: 'GET', url: API, headers: [['Authorization', `Bearer ${placeholder}`]] },
    owner: OWNER,
    exit: 'page',
    bodyPresent: false,
    rawTraits: { manualRedirects: true },
  };
}

const forward = (page, fields) => page.evaluate((f) => window.harness.forward(f), fields);
const verdict = (page) =>
  page.evaluate((url) => window.harness.sealed({ v: 1, op: 'test', name: 'TOKEN_A', url }), API);
const materialize = (page) =>
  page.evaluate((f, s) => window.harness.sealed({ v: 1, op: 'materialize', ...f }, s), ASK, OWNER);
const consume = (page, ticket) =>
  page.evaluate((f) => window.harness.call('materializeConsume', f), {
    ...ASK,
    ticket,
    stamp: CHILD,
    resolved: ASK.path,
    interpreters: [],
    trusted: true,
  });

let counter = 0;
function session(mail) {
  counter += 1;
  return {
    stamp: OWNER,
    session: `absent-session-${process.pid}-${counter}-0000`,
    host: 'smtp.example.com',
    port: 587,
    protocol: 'smtp',
    position: 'auth-plain',
    verified: true,
    handshakeAt: Date.now(),
    exit: 'page',
    placeholders: [mail],
  };
}

const target = (mail) => {
  const { stamp, session: id, host, port, protocol, exit } = session(mail);
  return { stamp, session: id, host, port, protocol, exit };
};

const op = (page, name, fields) => page.evaluate((n, f) => window.harness.call(n, f), name, fields);

async function allPaused(page, a, mail) {
  const sent = await forward(page, call(a));
  assert.deepEqual(sent.reply.refused, { status: 403, reason: PAUSED });
  assert.deepEqual((({ verdict: v, reason }) => [v, reason])(await verdict(page)), [
    'refuse',
    PAUSED,
  ]);
  assert.deepEqual((await materialize(page)).error, { code: 'EACCES', message: PAUSED });
  assert.deepEqual((await op(page, 'sessionMaterialize', session(mail))).error, {
    code: 'EACCES',
    message: PAUSED,
  });
  assert.deepEqual((await op(page, 'sessionAnchors', target(mail))).error, {
    code: 'EACCES',
    message: PAUSED,
  });
}

test('a missing config.toml clears its rules and pauses', async (t) => {
  const { page, a, mail } = await ready(t);
  const reply = await upload(page, [missing(CONFIG)]);
  assert.equal(reply.accepted, true);
  assert.deepEqual(reply.files[0], {
    path: CONFIG,
    sha256: null,
    accepted: true,
    warnings: [],
    absent: true,
    paused: true,
  });
  assert.deepEqual(reply.rules, []);
  const { status } = await op(page, 'status', {});
  assert.deepEqual(status.policy, reply.files);
  await allPaused(page, a, mail);
  const listed = await page.evaluate(() => window.harness.sealed({ v: 1, op: 'list' }));
  assert.equal(listed.secrets.find((s) => s.name === 'TOKEN_A').state, 'inert');
  const [entry] = (await op(page, 'audit', { limit: 1 })).audit;
  assert.deepEqual(
    [entry.type, entry.file, entry.sha256, entry.absent, entry.accepted],
    ['policy', CONFIG, null, true, true]
  );
  assert.ok(entry.changes.some((change) => change.change === 'removed'));
});

test('a missing secrets-policy.toml pauses though the rules stay', async (t) => {
  const { page, a, mail } = await ready(t);
  const reply = await upload(page, [missing(POLICY)]);
  assert.equal(reply.rules.length, 2);
  assert.deepEqual(reply.files[0].paused, true);
  await allPaused(page, a, mail);
});

test('a pause outlives a reload', async (t) => {
  const { page, a, mail } = await ready(t);
  await upload(page, [missing(POLICY)]);
  await page.reload();
  await page.until(() => document.title === 'ready');
  await page.evaluate(() => window.harness.connect());
  await allPaused(page, a, mail);
});

test('a ticket from before a pause is refused at consume', async (t) => {
  const { page } = await ready(t);
  const { ticket } = await materialize(page);
  assert.ok(ticket);
  await upload(page, [missing(POLICY)]);
  const reply = await consume(page, ticket);
  assert.deepEqual(reply.error, { code: 'EACCES', message: PAUSED });
  assert.equal(reply.values, undefined);
});

test('an MCP forward does not depend on the rules', async (t) => {
  const { page } = await ready(t);
  const token = await page.evaluate(
    (value) =>
      window.harness.call('put', { name: 'NOTES_MCP', value, kind: 'mcp', server: 'notes' }),
    TOKEN
  );
  await op(page, 'endpoints', {
    mcp: [{ server: 'notes', url: 'https://notes.example.com/mcp', names: ['NOTES_MCP'] }],
  });
  await upload(page, [missing(CONFIG), missing(POLICY)]);
  const fields = call(token.placeholder);
  fields.head.url = 'https://notes.example.com/mcp/call';
  const { reply } = await forward(page, fields);
  assert.equal(reply.mode, 'mcp');
});

test('a trusted attestation with bytes resumes', async (t) => {
  const { page, a, mail, files } = await ready(t);
  await upload(page, [missing(CONFIG), missing(POLICY)]);
  const half = await upload(page, [files[1]]);
  assert.deepEqual(
    half.files.map(({ path, paused }) => [path, paused]),
    [
      [POLICY, undefined],
      [CONFIG, true],
    ]
  );
  await allPaused(page, a, mail);
  const reply = await upload(page, [files[0]]);
  assert.equal(reply.rules.length, 2);
  assert.deepEqual(
    reply.files.map(({ path, absent, paused }) => [path, absent, paused]),
    [[CONFIG, undefined, undefined]]
  );
  const { reply: sent } = await forward(page, call(a));
  assert.deepEqual(sent.head.headers, [['Authorization', `Bearer ${SECRET}`]]);
  assert.ok((await materialize(page)).ticket);
  const [entry] = (await op(page, 'audit', {})).audit.filter((e) => e.type === 'policy');
  assert.deepEqual([entry.file, entry.accepted], [CONFIG, true]);
  assert.ok(entry.changes.some((change) => change.change === 'added'));
});

test('untrusted entries leave the last accepted policy and a pause as they are', async (t) => {
  const { page, a, mail } = await ready(t);
  const dir = new URL('./fixtures/attest/', import.meta.url);
  const names = (await readdir(dir)).filter((name) => name.startsWith('bad-absent'));
  assert.ok(names.length >= 6);
  const entries = [];
  for (const name of names) {
    entries.push(JSON.parse(await readFile(new URL(name, dir), 'utf8')).attestation);
  }
  for (const entry of entries) {
    const reply = await upload(page, [entry]);
    assert.equal(reply.files[0].accepted, false);
    assert.equal(reply.files[0].paused, undefined);
    assert.equal(reply.rules.length, 2);
  }
  const { reply: sent } = await forward(page, call(a));
  assert.equal(sent.mode, 'secret');
  await upload(page, [missing(CONFIG)]);
  for (const entry of entries.filter((e) => e.path === CONFIG)) {
    const reply = await upload(page, [entry]);
    assert.deepEqual(
      [reply.files[0].accepted, reply.files[0].absent, reply.files[0].paused],
      [false, true, true]
    );
  }
  await allPaused(page, a, mail);
});
