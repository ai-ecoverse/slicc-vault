import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { attest, CONFIG, config } from './attest.mjs';
import { browser } from './browser.mjs';
import { setup } from './setup.mjs';

const { chrome, embedder, served } = await setup();
const cdp = await browser(chrome);
after(() => cdp.close());

const SECRET = 'fake-contract-secret-0601';
const TOKEN = 'fake-contract-mcp-0602';
const OWNER = { pid: 9, ppid: 1, uid: 1000, gid: 1000, tag: 'cone', users: 'enforce' };
const MANUAL = { manualRedirects: true };
const SERVER = 'https://notes.example.com/mcp';
const API = 'https://api.example.com/v1/items';

async function ready(t) {
  const page = await embedder(t);
  const welcome = await page.evaluate(() => window.harness.connect());
  const secret = await page.evaluate(
    (value) => window.harness.sealed({ v: 1, op: 'seal', name: 'TOKEN_A', value }),
    SECRET
  );
  const mcp = await page.evaluate(
    (value) =>
      window.harness.call('put', { name: 'NOTES_MCP', value, kind: 'mcp', server: 'notes' }),
    TOKEN
  );
  const text = config({ TOKEN_A: secret.placeholder }, [
    { secret: 'TOKEN_A', domain: 'api.example.com' },
    { secret: 'TOKEN_A', domain: 'api.example.com', header: 'x-api-key' },
  ]);
  const accepted = await page.evaluate(
    (list) => window.harness.policy(list),
    [attest(CONFIG, text)]
  );
  assert.equal(accepted.accepted, true);
  await page.evaluate(() => window.harness.agent());
  await page.evaluate(
    (url) => window.harness.ask('endpoints', { mcp: [{ server: 'notes', url }] }),
    SERVER
  );
  return { page, welcome, a: secret.placeholder, m: mcp.placeholder };
}

function secretCall(placeholder, fields = {}, header = 'Authorization') {
  return {
    head: { method: 'POST', url: API, headers: [[header, `Bearer ${placeholder}`]] },
    owner: OWNER,
    exit: 'page',
    bodyPresent: false,
    rawTraits: MANUAL,
    ...fields,
  };
}

function mcpCall(placeholder, fields = {}, header = 'Authorization') {
  return {
    head: { method: 'POST', url: `${SERVER}/call`, headers: [[header, `Bearer ${placeholder}`]] },
    owner: OWNER,
    exit: 'page',
    bodyPresent: false,
    rawTraits: MANUAL,
    ...fields,
  };
}

function send(page, fields, response = null) {
  return page.evaluate(
    async (f, r) => {
      const { reply, ...rest } = await window.harness.forward(f, r);
      const { body, ...shown } = reply;
      const decoded = body === undefined ? {} : { body: new TextDecoder().decode(body) };
      return {
        ...rest,
        reply: shown,
        hasBody: body !== undefined,
        bytes: body instanceof Uint8Array,
        ...decoded,
      };
    },
    fields,
    response
  );
}

const used = async (page, type) =>
  (await page.evaluate(() => window.harness.call('audit'))).audit.filter((e) => e.type === type);

const shown = async (page, name) =>
  (await page.evaluate(() => window.harness.call('list'))).list.secrets.find(
    (record) => record.name === name
  );

test('status names the forward capability', async (t) => {
  const { page, welcome } = await ready(t);
  assert.deepEqual(welcome.status.capabilities, { forward: 1 });
  const { status } = await page.evaluate(() => window.harness.call('status'));
  assert.deepEqual(status.capabilities, { forward: 1 });
  const pushed = await page.evaluate(
    () => window.harness.events.findLast((event) => event.event === 'status').status
  );
  assert.deepEqual(pushed.capabilities, { forward: 1 });
});

test('a secret needs a manual exit in any header', async (t) => {
  const { page, a } = await ready(t);
  for (const header of ['Authorization', 'X-Api-Key']) {
    for (const rawTraits of [{}, { manualRedirects: false }, { manualRedirects: 'true' }]) {
      const { reply } = await send(page, secretCall(a, { rawTraits }, header));
      assert.deepEqual(reply.refused, {
        status: 403,
        reason: "TOKEN_A needs an exit that doesn't follow redirects",
      });
    }
  }
  assert.deepEqual(await used(page, 'forward'), []);
  const sent = await send(page, secretCall(a, {}, 'X-Api-Key'));
  assert.deepEqual(sent.reply.head.headers, [['X-Api-Key', `Bearer ${SECRET}`]]);
});

test('an MCP credential needs a manual exit in any header', async (t) => {
  const { page, m } = await ready(t);
  for (const header of ['Authorization', 'X-Api-Key']) {
    const { reply } = await send(page, mcpCall(m, { rawTraits: {} }, header));
    assert.deepEqual(reply.refused, {
      status: 403,
      reason: "NOTES_MCP needs an exit that doesn't follow redirects",
    });
  }
  assert.deepEqual(await used(page, 'mcp'), []);
});

test('the test verdict assumes a manual exit', async (t) => {
  const { page } = await ready(t);
  const verdict = await page.evaluate(
    (url) => window.harness.sealed({ v: 1, op: 'test', name: 'TOKEN_A', url, header: 'X-Api-Key' }),
    API
  );
  assert.equal(verdict.verdict, 'inject');
});

test('a secret forward says its mode and never reads a body', async (t) => {
  const { page, a } = await ready(t);
  const sent = await send(page, secretCall(a, { bodyPresent: true, body: 7 }));
  assert.equal(sent.reply.mode, 'secret');
  assert.equal(sent.reply.bodyComplete, undefined);
  assert.equal(sent.reply.needsBody, undefined);
  assert.equal(sent.hasBody, false);
  const bare = secretCall(a);
  delete bare.bodyPresent;
  assert.equal((await send(page, bare)).reply.mode, 'secret');
});

test('an MCP forward must say whether it has a body', async (t) => {
  const { page, m } = await ready(t);
  const fields = mcpCall(m);
  delete fields.bodyPresent;
  const { reply } = await send(page, fields);
  assert.deepEqual(reply.refused, {
    status: 400,
    reason: 'an MCP request must say whether it has a body',
  });
  assert.equal(reply.head, undefined);
  assert.deepEqual(await used(page, 'mcp'), []);
});

test('an MCP forward with a body it has not sent gets only needsBody', async (t) => {
  const { page, m } = await ready(t);
  const { reply, parts, hasBody } = await send(page, mcpCall(m, { bodyPresent: true }));
  assert.equal(reply.needsBody, true);
  assert.equal(reply.head, undefined);
  assert.equal(reply.mode, undefined);
  assert.equal(hasBody, false);
  assert.deepEqual(parts, []);
  assert.deepEqual(await used(page, 'mcp'), []);
  const record = await shown(page, 'NOTES_MCP');
  assert.equal(record.usedAt, undefined);
  assert.equal(record.pinned, undefined);
  const seen = await page.evaluate(() => JSON.stringify(window.harness.seen));
  assert.ok(!seen.includes(TOKEN));
});

test('a complete MCP body comes back scrubbed', async (t) => {
  const { page, a, m } = await ready(t);
  const body = `{"a":"${SECRET}","b":"${TOKEN}"}`;
  const sent = await send(page, mcpCall(m, { bodyPresent: true, body }));
  assert.equal(sent.reply.mode, 'mcp');
  assert.equal(sent.reply.bodyComplete, true);
  assert.deepEqual(sent.reply.head.headers, [['Authorization', `Bearer ${TOKEN}`]]);
  assert.equal(sent.bytes, true);
  assert.equal(sent.body, `{"a":"${a}","b":"${m}"}`);
  assert.equal((await used(page, 'mcp')).length, 1);
});

test('an MCP forward without a body has no body field', async (t) => {
  const { page, m } = await ready(t);
  const sent = await send(page, mcpCall(m));
  assert.equal(sent.reply.mode, 'mcp');
  assert.equal(sent.reply.bodyComplete, true);
  assert.equal(sent.hasBody, false);
});

test('an empty MCP body comes back as empty bytes', async (t) => {
  const { page, m } = await ready(t);
  for (const body of ['', new Array(0)]) {
    const fields = mcpCall(m, { bodyPresent: true });
    const sent = await page.evaluate(
      async (f, text) => {
        const { reply } = await window.harness.forward({
          ...f,
          body: Array.isArray(text) ? new Uint8Array(0) : text,
        });
        return [
          reply.mode,
          reply.bodyComplete,
          reply.body instanceof Uint8Array,
          reply.body.length,
        ];
      },
      fields,
      body
    );
    assert.deepEqual(sent, ['mcp', true, true, 0]);
  }
});

test('an MCP body above 32 MiB is refused', async (t) => {
  const { page, m } = await ready(t);
  const { reply } = await page.evaluate(
    (f) => window.harness.forward({ ...f, body: new Uint8Array(32 * 1024 * 1024 + 1) }),
    mcpCall(m, { bodyPresent: true })
  );
  assert.equal(reply.error.code, 'EINVAL');
  assert.match(reply.error.message, /at most 32 MiB/);
  assert.deepEqual(await used(page, 'mcp'), []);
});

test('an MCP request that denies its body and carries one is refused', async (t) => {
  const { page, m } = await ready(t);
  const { reply } = await send(page, mcpCall(m, { bodyPresent: false, body: '{}' }));
  assert.equal(reply.refused.status, 400);
});

test('a value that holds another stored value is refused', async (t) => {
  const { page, a, m } = await ready(t);
  const secret = await send(page, secretCall(a));
  assert.equal(secret.reply.mode, 'secret');
  await page.evaluate(
    (value) => window.harness.call('put', { name: 'TOKEN_A', value }),
    `wrap-${TOKEN}-wrap`
  );
  const held = await send(page, secretCall(a));
  assert.deepEqual(held.reply.refused, {
    status: 403,
    reason: "TOKEN_A's value contains another stored value",
  });
  await page.evaluate(
    (value) => window.harness.call('put', { name: 'TOKEN_A', value }),
    'fake-contract-other-0603'
  );
  await page.evaluate(
    (value) =>
      window.harness.call('put', { name: 'NOTES_MCP', value, kind: 'mcp', server: 'notes' }),
    `wrap-fake-contract-other-0603-wrap`
  );
  const mcp = await send(page, mcpCall(m));
  assert.deepEqual(mcp.reply.refused, {
    status: 403,
    reason: "NOTES_MCP's value contains another stored value",
  });
});

test('a forward that returns no head closes its port', async (t) => {
  const { page, a, m } = await ready(t);
  const frame = await cdp.target(new RegExp(`^${served.vault}/$`));
  await frame.evaluate(() => {
    const close = MessagePort.prototype.close;
    window.closes = 0;
    MessagePort.prototype.close = function counted() {
      window.closes += 1;
      close.call(this);
    };
  });
  const closes = () => frame.evaluate(() => window.closes);
  await send(page, secretCall(a));
  assert.equal(await closes(), 0);
  const outcomes = [
    secretCall(a, { rawTraits: {} }),
    mcpCall(m, { bodyPresent: true }),
    { head: {} },
  ];
  for (const [index, fields] of outcomes.entries()) {
    await page.evaluate((f) => window.harness.forward(f), fields);
    assert.equal(await closes(), index + 1);
  }
});

test('a rotation while a forward prepares refuses it', async (t) => {
  const { page, a } = await ready(t);
  const fields = secretCall(a);
  fields.head.headers = new Array(40).fill(['Authorization', `Bearer ${a}`]);
  const refused = await page.evaluate(async (f) => {
    const h = window.harness;
    await h.twin(true);
    const other = h.twins[0];
    for (let round = 0; round < 1200; round++) {
      const pending = h.call('forward', f);
      if (round % 3) await new Promise((resolve) => setTimeout(resolve, round % 3));
      const value = `fake-contract-rotated-${round}`;
      const put = h.call('put', { name: 'TOKEN_A', value }, [], other);
      const [reply] = await Promise.all([pending, put]);
      if (reply.refused) return reply.refused;
    }
    return null;
  }, fields);
  assert.deepEqual(refused, {
    status: 403,
    reason: 'the endpoints changed meanwhile; send it again',
  });
});

function relayed(page, a, response, fields = {}) {
  return send(page, secretCall(a, fields), {
    head: { status: 200, statusText: 'OK', url: API, headers: [] },
    ...response,
  });
}

const credits = (parts) => parts.filter((part) => part.op === 'credit').map((part) => part.bytes);

test('streamCredit acks each chunk after its output, held tails included', async (t) => {
  const { page, a } = await ready(t);
  const long = 'x'.repeat(64);
  const { parts } = await relayed(
    page,
    a,
    { chunks: [long, SECRET.slice(0, 11), SECRET.slice(11), 'y'.repeat(32)] },
    { streamCredit: true }
  );
  assert.deepEqual(credits(parts), [64, 11, SECRET.length - 11, 32]);
  assert.deepEqual(
    parts.slice(0, 3).map((part) => part.op),
    ['response', 'body', 'credit']
  );
  const second = parts.indexOf(parts.filter((part) => part.op === 'credit')[1]);
  assert.equal(parts[second - 1].op, 'credit');
  assert.equal(parts.at(-1).op, 'end');
  const text = parts
    .filter((part) => part.op === 'body')
    .map((part) => part.text)
    .join('');
  assert.equal(text, `${long}${a}${'y'.repeat(32)}`);
});

test('streamCredit gives no credit for an idle flush, a stray chunk or a late one', async (t) => {
  const { page, a } = await ready(t);
  const { parts } = await relayed(
    page,
    a,
    { chunks: [SECRET.slice(0, 11), 'not bytes'.length], wait: 500, late: 'late' },
    { streamCredit: true }
  );
  assert.deepEqual(credits(parts), [11]);
  assert.deepEqual(
    parts.map((part) => part.op),
    ['response', 'credit', 'body', 'end']
  );
});

test('forward gives no credit unless streamCredit is exactly true', async (t) => {
  const { page, a } = await ready(t);
  const on = await relayed(page, a, { chunks: ['x'.repeat(64)] }, { streamCredit: true });
  assert.deepEqual(credits(on.parts), [64]);
  for (const fields of [{}, { streamCredit: 'true' }, { streamCredit: 1 }]) {
    const { parts } = await relayed(page, a, { chunks: ['x'.repeat(64)] }, fields);
    assert.deepEqual(credits(parts), []);
    assert.equal(parts.at(-1).op, 'end');
  }
});

const CANCEL = { op: 'error', message: "the vault's values changed; send the request again" };
const NEW = 'fake-contract-newer-0604';
const HEAD = { op: 'response', status: 200, statusText: 'OK', url: API, headers: [] };
const ROTATE = { call: 'put', fields: { name: 'TOKEN_A', value: NEW } };

const stream = (page, fields, steps) =>
  page.evaluate((f, s) => window.harness.stream(f, s), fields, steps);

function cancelled({ parts }, kept) {
  assert.deepEqual(
    parts.map((part) => part.op),
    [...kept, 'error']
  );
  assert.deepEqual(parts.at(-1), CANCEL);
  assert.ok(!JSON.stringify(parts).includes(NEW));
}

test('a rotation cancels the response at its next chunk', async (t) => {
  const { page, a } = await ready(t);
  const sent = await stream(page, secretCall(a, { streamCredit: true }), [
    HEAD,
    { text: 'x'.repeat(64) },
    ROTATE,
    { text: `echo ${NEW}` },
    { text: 'more' },
    { op: 'end' },
  ]);
  cancelled(sent, ['response', 'body', 'credit']);
});

test('a rotation cancels a response before its head', async (t) => {
  const { page, a } = await ready(t);
  const sent = await stream(page, secretCall(a), [
    ROTATE,
    { ...HEAD, statusText: NEW, headers: [['x-echo', NEW]] },
  ]);
  cancelled(sent, []);
});

test('a rotation replaces the error text of a response', async (t) => {
  const { page, a } = await ready(t);
  const sent = await stream(page, secretCall(a), [HEAD, ROTATE, { op: 'error', message: NEW }]);
  cancelled(sent, ['response']);
});

test('a rotation replaces the end of a response and drops its held tail', async (t) => {
  const { page, a } = await ready(t);
  const sent = await stream(page, secretCall(a), [
    HEAD,
    { text: SECRET.slice(0, 11) },
    ROTATE,
    { op: 'end' },
  ]);
  assert.equal(sent.parts.at(-1).message, CANCEL.message);
  assert.ok(!sent.parts.some((part) => part.op === 'end'));
  assert.ok(
    !sent.parts
      .map((part) => part.text)
      .join('')
      .includes(SECRET.slice(0, 11))
  );
});

test('a rotation stops an idle flush', async (t) => {
  const { page, a } = await ready(t);
  const sent = await stream(page, secretCall(a), [
    HEAD,
    { text: SECRET.slice(0, 11) },
    ROTATE,
    { pause: 500 },
  ]);
  assert.deepEqual(sent.parts.at(-1), CANCEL);
  assert.ok(
    !sent.parts
      .map((part) => part.text)
      .join('')
      .includes(SECRET.slice(0, 11))
  );
});

test('a value added after the head cancels the response', async (t) => {
  const { page, a } = await ready(t);
  const sent = await stream(page, secretCall(a), [
    HEAD,
    { call: 'put', fields: { name: 'ADDED', value: NEW } },
    { text: NEW },
  ]);
  cancelled(sent, ['response']);
});

test('a restored record cancels the response', async (t) => {
  const { page, a } = await ready(t);
  await page.evaluate((value) => window.harness.call('put', { name: 'BACK', value }), NEW);
  await page.evaluate(() => window.harness.call('remove', { name: 'BACK' }));
  const sent = await stream(page, secretCall(a), [
    HEAD,
    { call: 'restore', fields: { name: 'BACK' } },
    { text: NEW },
  ]);
  cancelled(sent, ['response']);
});

test('a rotation in another vault document cancels the response', async (t) => {
  const { page, a } = await ready(t);
  await page.evaluate(() => window.harness.twin());
  const sent = await stream(page, secretCall(a), [
    HEAD,
    { ...ROTATE, twin: true },
    { pause: 100 },
    { text: NEW },
  ]);
  cancelled(sent, ['response']);
});

test('a response streams on while the values stay the same', async (t) => {
  const { page, m } = await ready(t);
  const sent = await stream(page, mcpCall(m, { streamCredit: true }), [
    { ...HEAD, url: `${SERVER}/call` },
    { pause: 100 },
    { text: 'x'.repeat(64) },
    { call: 'status', fields: {} },
    { text: 'y'.repeat(64) },
    { op: 'end' },
  ]);
  assert.equal(sent.parts.at(-1).op, 'end');
  assert.deepEqual(credits(sent.parts), [64, 64]);
  assert.ok(!sent.parts.some((part) => part.op === 'error'));
  assert.equal((await shown(page, 'NOTES_MCP')).pinned, true);
});

test('a rule removed while a forward prepares refuses it, unaudited', async (t) => {
  const { page, a } = await ready(t);
  const fields = secretCall(a);
  fields.head.headers = new Array(40).fill(['Authorization', `Bearer ${a}`]);
  const narrow = attest(CONFIG, config({ TOKEN_A: a }, []));
  const wide = attest(
    CONFIG,
    config({ TOKEN_A: a }, [{ secret: 'TOKEN_A', domain: 'api.example.com' }])
  );
  const refused = await page.evaluate(
    async (f, less, more) => {
      const h = window.harness;
      await h.twin(true);
      const other = h.twins[0];
      const decoded = (file) => ({
        ...file,
        bytes: Uint8Array.from(atob(file.bytes), (char) => char.charCodeAt(0)),
      });
      for (let round = 0; round < 1200; round++) {
        const before = (await h.call('audit', { limit: 1 })).audit[0].seq;
        const pending = h.call('forward', f);
        if (round % 3) await new Promise((resolve) => setTimeout(resolve, round % 3));
        const narrowed = h.call('policy', { files: [decoded(less)] }, [], other);
        const [reply] = await Promise.all([pending, narrowed]);
        const after = (await h.call('audit', { limit: 5 })).audit;
        await h.call('policy', { files: [decoded(more)] }, [], other);
        if (reply.refused?.reason.includes('meanwhile')) {
          return {
            ...reply.refused,
            forwards: after.filter((e) => e.seq > before && e.type === 'forward').length,
          };
        }
      }
      return null;
    },
    fields,
    narrow,
    wide
  );
  assert.deepEqual(refused, {
    status: 403,
    reason: 'the endpoints changed meanwhile; send it again',
    forwards: 0,
  });
});
