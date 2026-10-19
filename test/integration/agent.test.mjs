import assert from 'node:assert/strict';
import { test } from 'node:test';
import { attest, CONFIG, config } from './attest.mjs';
import { setup } from './setup.mjs';

const { embedder } = await setup();

const VALUE_A = 'fake-value-0001-aaaa';
const VALUE_M = 'fake-mcp-cred-0003-mmmm';
const VALUE_LOOP = 'fake-loop-cred-0005-llll';
const OWNER = { pid: 9, ppid: 1, uid: 1000, gid: 1000, tag: 'cone', users: 'enforce' };
const SERVER = 'http://8080.kernel.localhost/mcp';

async function ready(t) {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.connect());
  const a = await page.evaluate(
    (value) => window.harness.sealed({ v: 1, op: 'seal', name: 'TOKEN_A', value }),
    VALUE_A
  );
  const m = await page.evaluate(
    (value) =>
      window.harness.call('seal', { name: 'DOCS_MCP', value, source: 'settings', kind: 'mcp' }),
    VALUE_M
  );
  const welcome = await page.evaluate(() => window.harness.agent());
  assert.equal(welcome.role, 'agent');
  return { page, a: a.placeholder, m: m.placeholder };
}

test('redact scrubs batches of text and bytes over every value', async (t) => {
  const { page, a, m } = await ready(t);
  const reply = await page.evaluate(
    (value, mcp) =>
      window.harness
        .ask('redact', {
          texts: [`env: TOKEN_A=${value}`, new TextEncoder().encode(btoa(mcp)), 'nothing'],
        })
        .then((r) =>
          r.texts
            ? {
                ...r,
                texts: r.texts.map((x) =>
                  typeof x === 'string' ? x : new TextDecoder().decode(x)
                ),
              }
            : r
        ),
    VALUE_A,
    VALUE_M
  );
  assert.equal(reply.texts[0], `env: TOKEN_A=${a}`);
  assert.equal(reply.texts[1], '[redacted:DOCS_MCP]');
  assert.equal(reply.texts[2], 'nothing');
  assert.deepEqual(reply.hits.map((hit) => [hit.name, hit.form]).sort(), [
    ['DOCS_MCP', 'base64'],
    ['TOKEN_A', 'raw'],
  ]);
  assert.ok(reply.version > 0);
  assert.ok(m);
  const bad = await page.evaluate(() => window.harness.ask('redact', { texts: [3] }));
  assert.equal(bad.error.code, 'EINVAL');
});

test('redactStream holds back a split value', async (t) => {
  const { page, a } = await ready(t);
  const out = await page.evaluate(async (value) => {
    const h = window.harness;
    const enc = (text) => new TextEncoder().encode(text);
    const dec = (bytes) => new TextDecoder().decode(bytes);
    const opened = await h.ask('redactStream', { stream: 's1' });
    const one = await h.ask('push', { stream: 's1', chunk: enc(`out: ${value.slice(0, 9)}`) });
    const two = await h.ask('push', { stream: 's1', chunk: enc(`${value.slice(9)} done`) });
    const end = await h.ask('end', { stream: 's1' });
    const gone = await h.ask('push', { stream: 's1', chunk: enc('x') });
    await h.ask('redactStream', { stream: 's2' });
    await h.ask('push', { stream: 's2', chunk: enc('fake') });
    const idle = await h.ask('idle', { stream: 's2' });
    const dropped = await h.ask('drop', { stream: 's2' });
    return {
      idleMs: opened.idleMs,
      text: dec(one.chunk) + dec(two.chunk) + dec(end.chunk),
      hits: end.hits,
      gone: gone.error.code,
      idle: dec(idle.chunk),
      dropped: dropped.error,
    };
  }, VALUE_A);
  assert.equal(out.idleMs, 250);
  assert.equal(out.text, `out: ${a} done`);
  assert.deepEqual(out.hits, [{ name: 'TOKEN_A', form: 'raw', count: 1 }]);
  assert.equal(out.gone, 'ENOENT');
  assert.equal(out.idle, 'fake');
  assert.equal(out.dropped, undefined);
});

test('push and redact take any byte view, as exactly its own bytes', async (t) => {
  const { page, a } = await ready(t);
  const out = await page.evaluate(async (value) => {
    const h = window.harness;
    const dec = (bytes) => new TextDecoder().decode(bytes);
    const text = `out: ${value} done`;
    const pool = new Uint8Array(8192).fill(0x41);
    pool.set(new TextEncoder().encode(text), 100);
    const at = (start) => 100 + start;
    const views = [
      ['Int8Array', new Int8Array(pool.buffer, at(0), 7)],
      ['DataView', new DataView(pool.buffer, at(7), 4)],
      ['Float32Array', new Float32Array(pool.buffer.slice(at(11), at(19)))],
      ['Uint8Array subarray', pool.subarray(at(19), at(22))],
      ['Buffer pool slice', new Uint8Array(pool.buffer, at(22), text.length - 22)],
    ];
    await h.ask('redactStream', { stream: 'views' });
    let streamed = '';
    const types = [];
    for (const [name, chunk] of views) {
      const reply = await h.ask('push', { stream: 'views', chunk });
      types.push([name, reply.chunk?.constructor.name ?? reply.error.code]);
      streamed += dec(reply.chunk);
    }
    const end = await h.ask('end', { stream: 'views' });
    streamed += dec(end.chunk);
    const batch = await h.ask('redact', { texts: views.map(([, view]) => view) });
    const whole = await h.ask('redact', {
      texts: [
        new Int8Array(pool.buffer, at(0), text.length),
        new DataView(pool.buffer, at(5), value.length),
      ],
    });
    await h.ask('redactStream', { stream: 'bad' });
    const bad = [];
    for (const chunk of [new ArrayBuffer(4), { 0: 65, length: 1 }, 7, 'text']) {
      bad.push((await h.ask('push', { stream: 'bad', chunk })).error);
    }
    bad.push((await h.ask('redact', { texts: ['ok', new ArrayBuffer(4)] })).error);
    bad.push((await h.ask('redact', { texts: [{ 0: 65, length: 1 }] })).error);
    return {
      streamed,
      types,
      hits: end.hits,
      batch: batch.texts.map((x) => `${x.constructor.name}:${x.byteLength}`),
      whole: whole.texts.map(dec),
      bad,
    };
  }, VALUE_A);
  assert.equal(out.streamed, `out: ${a} done`);
  assert.ok(!out.streamed.includes('fake-value'));
  assert.deepEqual(out.hits, [{ name: 'TOKEN_A', form: 'raw', count: 1 }]);
  assert.deepEqual(
    out.types.map(([, type]) => type),
    ['Uint8Array', 'Uint8Array', 'Uint8Array', 'Uint8Array', 'Uint8Array']
  );
  assert.deepEqual(out.batch, [
    'Uint8Array:7',
    'Uint8Array:4',
    'Uint8Array:8',
    'Uint8Array:3',
    'Uint8Array:8',
  ]);
  assert.deepEqual(out.whole, [`out: ${a} done`, a]);
  assert.deepEqual(
    out.bad.slice(0, 4).map((e) => e.message),
    new Array(4).fill('chunk must be bytes')
  );
  assert.deepEqual(
    out.bad.slice(4).map((e) => [e.code, e.message]),
    new Array(2).fill(['EINVAL', 'texts must be a list of strings and bytes'])
  );
});

test('endpoints the page registers are refused for secrets, at parse and at request time', async (t) => {
  const { page, a } = await ready(t);
  const text = config({ TOKEN_A: a }, [
    { secret: 'TOKEN_A', domain: 'llm.example.com', paths: ['/v1/*'] },
    { secret: 'TOKEN_A', domain: 'llm.example.com' },
    { secret: 'TOKEN_A', domain: 'api.anthropic.com' },
    { secret: 'TOKEN_A', domain: 'docs.example.com' },
  ]);
  await page.evaluate((files) => window.harness.policy(files), [attest(CONFIG, text)]);
  const before = (await page.evaluate(() => window.harness.call('list'))).list;
  assert.deepEqual(
    before.refused.map((r) => r.rule.domain),
    ['api.anthropic.com']
  );
  const registered = await page.evaluate(() =>
    window.harness.call('endpoints', {
      model: ['https://llm.example.com/v1'],
      mcp: [{ server: 'docs', url: 'https://docs.example.com/mcp', names: [] }],
    })
  );
  assert.equal(registered.ok, true);
  await page.until(() =>
    window.harness.events.some((e) => e.event === 'changed' && e.parts.includes('exits'))
  );
  const after = (await page.evaluate(() => window.harness.call('list'))).list;
  assert.deepEqual(after.refused.map((r) => r.rule.domain).sort(), [
    'api.anthropic.com',
    'llm.example.com',
  ]);
  assert.match(after.refused[0].reason, /never injects there/);
  assert.deepEqual(after.secrets.find((s) => s.name === 'TOKEN_A').domains, [
    'llm.example.com',
    'docs.example.com',
  ]);
  const mcpPath = await page.evaluate((fields) => window.harness.forward(fields), {
    head: {
      method: 'GET',
      url: 'https://docs.example.com/mcp/tools',
      headers: [['Authorization', `Bearer ${a}`]],
    },
    owner: OWNER,
    exit: 'page',
    rawTraits: {},
  });
  assert.match(mcpPath.reply.refused.reason, /docs.example.com is a model or MCP endpoint/);
  const elsewhere = await page.evaluate((fields) => window.harness.forward(fields), {
    head: {
      method: 'GET',
      url: 'https://docs.example.com/api',
      headers: [['Authorization', `Bearer ${a}`]],
    },
    owner: OWNER,
    exit: 'page',
    rawTraits: {},
  });
  assert.ok(elsewhere.reply.head);
  const sent = await page.evaluate((fields) => window.harness.forward(fields), {
    head: {
      method: 'GET',
      url: 'https://llm.example.com/v1/chat',
      headers: [['Authorization', `Bearer ${a}`]],
    },
    owner: OWNER,
    exit: 'page',
    rawTraits: {},
  });
  assert.match(sent.reply.refused.reason, /model or MCP endpoint/);
  for (const bad of [
    { model: ['http://llm.example.com'] },
    { mcp: [{ server: 'x' }] },
    { mcp: 'nope' },
    { model: 'x' },
  ]) {
    const reply = await page.evaluate((fields) => window.harness.ask('endpoints', fields), bad);
    assert.equal(reply.error.code, 'EINVAL', JSON.stringify(bad));
  }
  const kernel9222 = await page.evaluate(() =>
    window.harness.ask('endpoints', {
      mcp: [{ server: 'cdp', url: 'http://9222.kernel.localhost/', names: [] }],
    })
  );
  assert.equal(kernel9222.error.code, 'EINVAL');
});

test('a kernel request to a registered MCP server gets only that server credential', async (t) => {
  const { page, a } = await ready(t);
  const m = (
    await page.evaluate(
      (url, value) =>
        window.harness.sealed(
          { v: 1, op: 'seal', name: 'LOOP_MCP', value, kind: 'mcp', server: 'docs', url },
          { pid: 78, ppid: 1, uid: 1000, gid: 1000, tag: null }
        ),
      SERVER,
      VALUE_LOOP
    )
  ).placeholder;
  await page.evaluate(
    (url) =>
      window.harness.ask('endpoints', { mcp: [{ server: 'docs', url, names: ['LOOP_MCP'] }] }),
    SERVER
  );
  const fields = (headers, body) => ({
    head: { method: 'POST', url: `${SERVER}/call`, headers },
    body,
    owner: OWNER,
    exit: 'page',
    rawTraits: {},
  });
  const response = {
    head: { status: 200, statusText: 'OK', url: `${SERVER}/call`, headers: [] },
    chunks: [`{"echo":"${VALUE_LOOP}"}`],
  };
  const sent = await page.evaluate(
    (f, r) =>
      window.harness.forward(f, r).then((out) => ({
        ...out,
        body: out.reply.body ? new TextDecoder().decode(out.reply.body) : null,
      })),
    fields([['Authorization', `Bearer ${m}`]], `{"args":"${VALUE_A}"}`),
    response
  );
  assert.deepEqual(sent.reply.head.headers, [['Authorization', `Bearer ${VALUE_LOOP}`]]);
  assert.equal(sent.body, `{"args":"${a}"}`);
  const body = sent.parts
    .filter((p) => p.op === 'body')
    .map((p) => p.text)
    .join('');
  assert.equal(body, `{"echo":"${m}"}`);
  const audit = (await page.evaluate(() => window.harness.call('audit', { limit: 1 }))).audit[0];
  assert.deepEqual(
    [audit.type, audit.server, audit.name, audit.uid, audit.tag],
    ['mcp', 'docs', 'LOOP_MCP', 1000, 'cone']
  );
  const secret = await page.evaluate(
    (f) => window.harness.forward(f),
    fields([['Authorization', `Bearer ${a}`]])
  );
  assert.match(secret.reply.refused.reason, /credentials are sent only over https on port 443/);
  const other = await page.evaluate((f) => window.harness.forward(f), {
    ...fields([['Authorization', `Bearer ${m}`]]),
    head: {
      method: 'POST',
      url: 'http://8081.kernel.localhost/mcp',
      headers: [['Authorization', `Bearer ${m}`]],
    },
  });
  assert.ok(other.reply.refused);
});

test('the agent role cannot use page ops, and pages cannot use agent ops', async (t) => {
  const { page } = await ready(t);
  const fromAgent = await page.evaluate(() => window.harness.ask('list'));
  assert.equal(fromAgent.error.code, 'EACCES');
  const fromPage = await page.evaluate(() => window.harness.call('redact', { texts: [] }));
  assert.equal(fromPage.error.code, 'ENOTSUP');
  const seen = await page.evaluate(() => JSON.stringify(window.harness.seen));
  assert.ok(!seen.includes(VALUE_M));
});

test('a kernel request to a registered MCP server gets no credential while kernel users is not enforce', async (t) => {
  const { page, m } = await ready(t);
  await page.evaluate(
    (url) =>
      window.harness.ask('endpoints', { mcp: [{ server: 'docs', url, names: ['DOCS_MCP'] }] }),
    SERVER
  );
  const sent = await page.evaluate((f) => window.harness.forward(f), {
    head: { method: 'POST', url: `${SERVER}/call`, headers: [['Authorization', `Bearer ${m}`]] },
    body: '{}',
    owner: { ...OWNER, users: 'off' },
    exit: 'page',
    rawTraits: {},
  });
  assert.deepEqual(sent.reply.refused, { status: 403, reason: 'kernel users must be enforce' });
  assert.ok(!JSON.stringify(sent).includes(VALUE_M));
});
