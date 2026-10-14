import assert from 'node:assert/strict';
import { test } from 'node:test';
import { attest, CONFIG, config, POLICY } from './attest.mjs';
import { setup } from './setup.mjs';

const { embedder } = await setup();

const VALUE_A = 'fake-value-0001-aaaa';
const VALUE_B = 'fake-value-0002-bbbb';
const OWNER = { pid: 9, ppid: 1, uid: 1000, gid: 1000, tag: 'cone', users: 'enforce' };

async function ready(t, extra = '') {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.connect());
  const a = await page.evaluate(
    (value) => window.harness.sealed({ v: 1, op: 'seal', name: 'TOKEN_A', value }),
    VALUE_A
  );
  const b = await page.evaluate(
    (value) => window.harness.sealed({ v: 1, op: 'seal', name: 'TOKEN_B', value }),
    VALUE_B
  );
  const text = config({ TOKEN_A: a.placeholder, TOKEN_B: b.placeholder }, [
    { secret: 'TOKEN_A', domain: 'api.example.com', methods: ['GET'], paths: ['/v1/*'] },
  ]);
  const files = [attest(CONFIG, text), attest(POLICY, extra)];
  const reply = await page.evaluate((list) => window.harness.policy(list), files);
  assert.equal(reply.accepted, true);
  return { page, a: a.placeholder, b: b.placeholder };
}

function head(url, headers, method = 'GET') {
  return { method, url, headers };
}

function send(page, fields, response = null) {
  return page.evaluate((f, r) => window.harness.forward(f, r), fields, response);
}

test('forward injects within the rule and scrubs the response', async (t) => {
  const { page, a } = await ready(t);
  const fields = {
    head: head('https://api.example.com/v1/items', [['Authorization', `Bearer ${a}`]]),
    owner: OWNER,
    exit: 'page',
    rawTraits: {},
  };
  const response = {
    head: {
      status: 200,
      statusText: 'OK',
      url: 'https://api.example.com/v1/items',
      headers: [['x-echo', VALUE_A]],
    },
    chunks: ['{"echo":"fake-value-', '0001-aaaa","b64":"', btoa(VALUE_A), '"}'],
  };
  const { reply, parts } = await send(page, fields, response);
  assert.deepEqual(reply.head.headers, [['Authorization', `Bearer ${VALUE_A}`]]);
  const answer = parts.find((part) => part.op === 'response');
  assert.deepEqual(answer.headers, [['x-echo', a]]);
  const body = parts
    .filter((part) => part.op === 'body')
    .map((part) => part.text)
    .join('');
  assert.equal(body, `{"echo":"${a}","b64":"[redacted:TOKEN_A]"}`);
  assert.equal(parts.at(-1).op, 'end');
  const audit = (await page.evaluate(() => window.harness.call('audit', { limit: 1 }))).audit[0];
  assert.deepEqual(
    [
      audit.type,
      audit.name,
      audit.domain,
      audit.method,
      audit.path,
      audit.exit,
      audit.uid,
      audit.tag,
    ],
    ['forward', 'TOKEN_A', 'api.example.com', 'GET', '/v1/items', 'page', 1000, 'cone']
  );
  const used = (await page.evaluate(() => window.harness.call('list'))).list.secrets[0];
  assert.ok(used.usedAt > 0);
});

test('forward refuses what the rule does not allow, before anything is sent', async (t) => {
  const { page, a, b } = await ready(t, '[exits]\nTOKEN_A = ["proxy"]\n');
  const bearer = (p) => [['Authorization', `Bearer ${p}`]];
  const cases = [
    [head('https://api.example.com/v1/items', bearer(a)), 'page', "isn't allowed on page"],
    [head('https://other.example.com/v1/items', bearer(a)), 'proxy', 'is only for api.example.com'],
    [
      head('https://api.example.com/v1/items', bearer(a), 'POST'),
      'proxy',
      "isn't allowed in authorization",
    ],
    [
      head('https://api.example.com/v2/items', bearer(a)),
      'proxy',
      "isn't allowed in authorization",
    ],
    [head('https://api.example.com/v1/items', [['X-Key', a]]), 'proxy', "isn't allowed in x-key"],
    [head(`https://api.example.com/v1/items?k=${a}`, []), 'proxy', 'works only in a header'],
    [head('https://api.example.com/v1/items', [[a, 'x']]), 'proxy', "can't be a header name"],
    [head('http://api.example.com/v1/items', bearer(a)), 'proxy', 'only over https'],
    [head('https://api.example.com:8443/v1/items', bearer(a)), 'proxy', 'only over https'],
    [head('https://api.example.com/v1/%2e%2e/admin', bearer(a)), 'proxy', 'ambiguous path'],
    [
      head('https://api.example.com/v1/items', [['Authorization', `Bearer ${a} ${a}`]]),
      'proxy',
      'more than once',
    ],
    [
      head('https://api.example.com/v1/items', bearer(b)),
      'proxy',
      'no rule in /etc/fnox/config.toml',
    ],
    [
      head('https://api.example.com/v1/items', [['Authorization', 'Bearer none']]),
      'proxy',
      'carries no placeholder',
    ],
    [
      head('https://api.anthropic.com/v1/messages', bearer(a)),
      'proxy',
      'is a model or MCP endpoint',
    ],
    [
      head('https://bedrock-runtime.us-west-2.amazonaws.com/model', bearer(a)),
      'proxy',
      'is a model or MCP endpoint',
    ],
  ];
  for (const [request, exit, reason] of cases) {
    const { reply, parts } = await send(page, {
      head: request,
      owner: OWNER,
      exit,
      rawTraits: { manualRedirects: true },
    });
    assert.ok(reply.refused, `${reason}: ${JSON.stringify(reply)}`);
    assert.equal(reply.refused.status, 403);
    assert.ok(reply.refused.reason.includes(reason), `${reason}: ${reply.refused.reason}`);
    assert.deepEqual(parts, []);
  }
  const encoded = await send(page, {
    head: head('https://api.example.com/v1/items', bearer(a)),
    owner: OWNER,
    exit: 'proxy',
    rawTraits: { encodedBodies: true },
  });
  assert.equal(encoded.reply.refused.status, 502);
  const bad = await page.evaluate(() =>
    window.harness.call('forward', { head: {}, owner: {}, exit: 'page' })
  );
  assert.equal(bad.error.code, 'EINVAL');
  const seen = await page.evaluate(() => JSON.stringify(window.harness.seen));
  assert.ok(!seen.includes(VALUE_A) && !seen.includes(VALUE_B));
});

test('Basic credentials are decoded, injected and re-encoded', async (t) => {
  const { page, a } = await ready(t);
  const basic = (text) => [['Authorization', `Basic ${btoa(text)}`]];
  const fields = (headers) => ({
    head: head('https://api.example.com/v1/repo', headers),
    owner: OWNER,
    exit: 'page',
    rawTraits: {},
  });
  const pass = await send(page, fields(basic(`x-access-token:${a}`)));
  assert.deepEqual(pass.reply.head.headers, basic(`x-access-token:${VALUE_A}`));
  const user = await send(page, fields(basic(`${a}:x`)));
  assert.deepEqual(user.reply.head.headers, basic(`${VALUE_A}:x`));
  const plain = await send(
    page,
    fields([
      ['Authorization', `Basic ${btoa('user:pw')}`],
      ['X-Id', a],
    ])
  );
  assert.ok(plain.reply.refused);
  const broken = await send(page, fields([['Authorization', `Basic ${btoa(`u:${a}:xyz`)}!`]]));
  assert.match(broken.reply.refused.reason, /valid base64/);
});

test('the /dev/sealed test op gives the injector verdict', async (t) => {
  const { page } = await ready(t);
  const verdict = (url, method) =>
    page.evaluate(
      (u, m) => window.harness.sealed({ v: 1, op: 'test', name: 'TOKEN_A', url: u, method: m }),
      url,
      method
    );
  const yes = await verdict('https://api.example.com/v1/items', 'GET');
  assert.deepEqual(
    [yes.verdict, yes.reason],
    ['inject', 'TOKEN_A would be sent in authorization to api.example.com']
  );
  const no = await verdict('https://api.example.com/v1/items', 'DELETE');
  assert.equal(no.verdict, 'refuse');
  const off = await page.evaluate(() =>
    window.harness.sealed(
      { v: 1, op: 'test', name: 'TOKEN_A', url: 'https://api.example.com/v1/items', method: 'GET' },
      { pid: 42, ppid: 1, uid: 1000, gid: 1000, tag: 'cone', users: 'off' }
    )
  );
  assert.deepEqual([off.verdict, off.reason], ['refuse', 'kernel users must be enforce']);
});

test('lock has no effect on an auto-unlocking vault, which keeps injecting and scrubbing', async (t) => {
  const { page, a } = await ready(t);
  await page.evaluate(() => window.harness.agent());
  const fields = {
    head: head('https://api.example.com/v1/items', [['Authorization', `Bearer ${a}`]]),
    owner: OWNER,
    exit: 'page',
    rawTraits: {},
  };
  await page.evaluate(() => window.harness.call('lock'));
  const locked = await page.evaluate(() => window.harness.call('status'));
  assert.equal(locked.status.locked, false);
  assert.ok((await send(page, fields)).reply.head);
  const red = await page.evaluate((v) => window.harness.ask('redact', { texts: [v] }), VALUE_A);
  assert.deepEqual(red.texts, [a]);
});

test('forward injects nothing while kernel users is not enforce', async (t) => {
  const { page, a } = await ready(t);
  for (const users of ['off', 'report', undefined]) {
    const { users: _users, ...bare } = OWNER;
    const { reply } = await send(page, {
      head: head('https://api.example.com/v1/items', [['Authorization', `Bearer ${a}`]]),
      owner: users ? { ...bare, users } : bare,
      exit: 'page',
      rawTraits: {},
    });
    assert.deepEqual(reply.refused, { status: 403, reason: 'kernel users must be enforce' });
    assert.ok(!JSON.stringify(reply).includes(VALUE_A));
  }
});
