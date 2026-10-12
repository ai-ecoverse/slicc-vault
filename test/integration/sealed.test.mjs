import assert from 'node:assert/strict';
import { test } from 'node:test';
import { setup } from './setup.mjs';

const { embedder } = await setup();

const send = (req, stamp) => window.harness.sealed(req, stamp ?? window.harness.stamp);
const as = (uid) => ({ pid: 7, ppid: 1, uid, gid: uid, tag: null });

async function connected(t) {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.connect());
  return page;
}

test('seal creates an inert record, and a rotation keeps its placeholder', async (t) => {
  const page = await connected(t);
  const created = await page.evaluate(send, {
    v: 1,
    op: 'seal',
    name: 'API_KEY',
    value: 'first-value',
  });
  assert.equal(created.state, 'inert');
  const rotated = await page.evaluate(
    send,
    { v: 1, op: 'seal', name: 'API_KEY', value: 'second-value' },
    as(1001)
  );
  assert.equal(rotated.placeholder, created.placeholder);
  const listed = await page.evaluate(send, { v: 1, op: 'list' });
  assert.deepEqual(listed, {
    v: 1,
    secrets: [
      { name: 'API_KEY', placeholder: created.placeholder, state: 'inert', exec: false, rules: [] },
    ],
  });
  const verdict = await page.evaluate(send, {
    v: 1,
    op: 'test',
    name: 'API_KEY',
    url: 'https://api.example.com/',
  });
  assert.equal(verdict.verdict, 'refuse');
});

test('a value entered in Settings is replaced only by uid 0', async (t) => {
  const page = await connected(t);
  const entered = await page.evaluate(() =>
    window.harness.call('put', { name: 'HUMAN_KEY', value: 'typed-by-a-human' })
  );
  const refused = await page.evaluate(send, {
    v: 1,
    op: 'seal',
    name: 'HUMAN_KEY',
    value: 'by-the-agent',
  });
  assert.equal(refused.error.code, 'EEXIST');
  const root = await page.evaluate(
    send,
    { v: 1, op: 'seal', name: 'HUMAN_KEY', value: 'by-sudo-approved' },
    as(0)
  );
  assert.equal(root.placeholder, entered.placeholder);
});

test('human requests: one per uid, status per uid, cancel, and refusals', async (t) => {
  const page = await connected(t);
  const first = await page.evaluate(send, { v: 1, op: 'request', kind: 'value', name: 'A_TOKEN' });
  assert.equal(first.state, 'pending');
  const again = await page.evaluate(send, {
    v: 1,
    op: 'request',
    kind: 'oauth',
    provider: 'github',
    oauth: {},
  });
  assert.equal(again.error.code, 'EAGAIN');
  const other = await page.evaluate(
    send,
    { v: 1, op: 'request', kind: 'jerk-seal', provider: 'npm' },
    as(1002)
  );
  assert.equal(other.state, 'pending');
  const foreign = await page.evaluate(send, { v: 1, op: 'status', id: first.id }, as(1002));
  assert.equal(foreign.error.code, 'ENOENT');
  const status = await page.evaluate(send, { v: 1, op: 'status', id: first.id });
  assert.deepEqual(status, { v: 1, state: 'pending' });
  const waiting = await page.evaluate(
    async () => (await window.harness.call('status')).status.waiting
  );
  assert.deepEqual(
    waiting.map((entry) => [entry.kind, entry.uid]),
    [
      ['value', 1000],
      ['jerk-seal', 1002],
    ]
  );
  const cancelled = await page.evaluate(send, { v: 1, op: 'cancel', id: first.id });
  assert.equal(cancelled.state, 'cancelled');
  const after = await page.evaluate(send, { v: 1, op: 'status', id: first.id });
  assert.equal(after.state, 'cancelled');
  const next = await page.evaluate(send, {
    v: 1,
    op: 'request',
    kind: 'oauth',
    provider: 'github',
    oauth: { scopes: ['repo'] },
  });
  assert.equal(next.state, 'pending');
  const long = await page.evaluate(
    send,
    { v: 1, op: 'request', kind: 'value', name: 'B', prompt: 'x'.repeat(201) },
    as(1003)
  );
  assert.equal(long.error.code, 'EINVAL');
});

test('framing and field errors answer with errno names', async (t) => {
  const page = await connected(t);
  const replies = await page.evaluate(async (send) => {
    const run = (req, stamp) => window.harness.sealed(req, stamp ?? window.harness.stamp);
    return {
      version: await run({ v: 2, op: 'list' }),
      op: await run({ v: 1, op: 'reveal', name: 'X' }),
      proto: await run({ v: 1, op: 'toString' }),
      name: await run({ v: 1, op: 'seal', name: '1BAD', value: 'x' }),
      crlf: await run({ v: 1, op: 'seal', name: 'GOOD', value: 'aaaaaaaa\nb' }),
      short: await run({ v: 1, op: 'seal', name: 'GOOD', value: 'seven77' }),
      nested: await run({
        v: 1,
        op: 'seal',
        name: 'GOOD',
        value: 'x fnox_proxy_0123456789abcdef01234567',
      }),
      stamp: await run({ v: 1, op: 'list' }, { uid: 'root' }),
      big: await run({ v: 1, op: 'seal', name: 'BIG', value: 'x'.repeat(70000) }),
      text: await run('{"v":1,'),
      missing: await run({ v: 1, op: 'placeholder', name: 'NOPE' }),
      materialize: await run({
        v: 1,
        op: 'materialize',
        names: ['X'],
        path: '/usr/bin/npm',
        argv: ['npm'],
        cwd: '/',
      }),
    };
  });
  for (const key of [
    'version',
    'op',
    'proto',
    'name',
    'crlf',
    'short',
    'nested',
    'stamp',
    'big',
    'text',
  ]) {
    assert.equal(replies[key].error.code, 'EINVAL', key);
  }
  assert.equal(replies.missing.error.code, 'ENOENT');
  assert.equal(replies.materialize.error.code, 'ENOENT');
  const unknown = await page.evaluate(() => window.harness.call('reveal'));
  assert.equal(unknown.error.code, 'ENOTSUP');
});
