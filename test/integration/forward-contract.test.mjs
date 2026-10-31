import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { attest, CONFIG, config, missing, POLICY } from './attest.mjs';
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

const CHANGES = {
  rotated: ROTATE,
  'a secret added': { call: 'put', fields: { name: 'ADDED', value: NEW } },
  'a model added': {
    call: 'put',
    fields: { name: 'ADDED', value: NEW, kind: 'model', provider: 'anthropic' },
  },
  'a grant added': {
    call: 'seal',
    fields: { name: 'ADDED', value: NEW, kind: 'grant', source: 'settings' },
  },
};

const held = SECRET.slice(0, 11);
const CHANNELS = {
  head: {
    before: [],
    after: [{ ...HEAD, statusText: NEW, url: `${API}?${NEW}`, headers: [['x-echo', NEW]] }],
    kept: [],
  },
  chunk: {
    before: [HEAD, { text: 'x'.repeat(64) }],
    after: [{ text: `echo ${NEW}` }, { text: 'more' }, { op: 'end' }],
    kept: ['response', 'credit'],
  },
  error: { before: [HEAD], after: [{ op: 'error', message: NEW }], kept: ['response'] },
  end: {
    before: [HEAD, { text: held }],
    after: [{ op: 'end' }],
    kept: ['response', 'credit'],
  },
  idle: {
    before: [HEAD, { text: held }],
    after: [{ pause: 500 }],
    kept: ['response', 'credit'],
  },
};

for (const [change, step] of Object.entries(CHANGES)) {
  for (const [channel, { before, after: rest, kept }] of Object.entries(CHANNELS)) {
    test(`${change} cancels a response at its ${channel}`, async (t) => {
      const { page, a } = await ready(t);
      const fields = secretCall(a, { streamCredit: true });
      const sent = await stream(page, fields, [...before, step, ...rest]);
      const { parts } = sent;
      assert.deepEqual(
        parts.map((part) => part.op).filter((op) => op !== 'body'),
        [...kept, 'error']
      );
      assert.deepEqual(parts.at(-1), CANCEL);
      assert.ok(!JSON.stringify(parts).includes(NEW));
      assert.ok(!JSON.stringify(parts).includes(held));
    });
  }
}

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
  const sent = await stream(page, secretCall(a), [HEAD, { ...ROTATE, twin: true }, { text: NEW }]);
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

const STALE = { status: 403, reason: 'the endpoints changed meanwhile; send it again' };

async function gated(page, nth) {
  await page.evaluate(() => window.harness.twin(true));
  const frame = await cdp.target(new RegExp(`^${served.vault}/$`));
  await frame.evaluate((turn) => {
    const decrypt = SubtleCrypto.prototype.decrypt;
    const close = MessagePort.prototype.close;
    let calls = 0;
    window.closes = 0;
    window.landed = new Promise((resolve) => {
      window.release = resolve;
    });
    SubtleCrypto.prototype.decrypt = async function gate(...args) {
      calls += 1;
      if (calls === turn) {
        window.held = true;
        await window.landed;
      }
      return decrypt.apply(this, args);
    };
    MessagePort.prototype.close = function counted() {
      window.closes += 1;
      close.call(this);
    };
  }, nth);
  return frame;
}

const upload = (page, file) =>
  page.evaluate((entry) => {
    const h = window.harness;
    const bytes = entry.bytes && Uint8Array.from(atob(entry.bytes), (c) => c.charCodeAt(0));
    const files = [bytes ? { ...entry, bytes } : entry];
    return h.call('policy', { files }, [], h.twins[0]);
  }, file);

const LANDINGS = {
  'a rule revoked': (page, a) => upload(page, attest(CONFIG, config({ TOKEN_A: a }, []))),
  'a rule narrowed by method': (page, a) =>
    upload(
      page,
      attest(
        CONFIG,
        config({ TOKEN_A: a }, [{ secret: 'TOKEN_A', domain: 'api.example.com', methods: ['GET'] }])
      )
    ),
  'an exit narrowed': (page) => upload(page, attest(POLICY, '[exits]\nTOKEN_A = ["proxy"]\n')),
  'a missing file': (page) => upload(page, missing(CONFIG)),
  'a rotation': (page) =>
    page.evaluate((value) => {
      const h = window.harness;
      return h.call('put', { name: 'TOKEN_A', value }, [], h.twins[0]);
    }, NEW),
};

for (const [name, land] of Object.entries(LANDINGS)) {
  for (const [nth, seam] of [
    [1, 'preparation'],
    [2, 'the recheck'],
  ]) {
    test(`${name} during ${seam} refuses the forward, unaudited`, async (t) => {
      const { page, a } = await ready(t);
      const frame = await gated(page, nth);
      const sending = send(page, secretCall(a));
      await frame.until(() => window.held === true);
      await land(page, a);
      await frame.evaluate(() => window.release());
      const { reply, parts } = await sending;
      assert.deepEqual(reply.refused, STALE);
      assert.equal(reply.head, undefined);
      assert.deepEqual(parts, []);
      assert.equal(await frame.evaluate(() => window.closes), 1);
      assert.deepEqual(await used(page, 'forward'), []);
      assert.equal((await shown(page, 'TOKEN_A')).usedAt, undefined);
    });
  }
}

test('a forward goes through a held decrypt when nothing lands', async (t) => {
  const { page, a } = await ready(t);
  const frame = await gated(page, 2);
  const sending = send(page, secretCall(a));
  await frame.until(() => window.held === true);
  await frame.evaluate(() => window.release());
  const { reply } = await sending;
  assert.equal(reply.mode, 'secret');
  assert.equal((await used(page, 'forward')).length, 1);
});

test('a value rotated during preparation refuses an MCP body that holds it', async (t) => {
  const { page, a, m } = await ready(t);
  const frame = await gated(page, 1);
  const sending = send(page, mcpCall(m, { bodyPresent: true, body: `x ${SECRET} y` }));
  await frame.until(() => window.held === true);
  await LANDINGS['a rotation'](page, a);
  await frame.evaluate(() => window.release());
  const { reply, hasBody } = await sending;
  assert.deepEqual(reply.refused, STALE);
  assert.equal(hasBody, false);
  assert.equal(reply.bodyComplete, undefined);
});

test('forward audits request text scrubbed', async (t) => {
  const { page, a } = await ready(t);
  const fields = secretCall(a);
  fields.head.url = `${API}/${TOKEN}`;
  assert.equal((await send(page, fields)).reply.mode, 'secret');
  const [entry] = await used(page, 'forward');
  assert.ok(!JSON.stringify(entry).includes(TOKEN));
  assert.ok(entry.path.startsWith('/v1/items/'));
});

const SEAMS = {
  head: { before: [], message: { ...HEAD, statusText: NEW } },
  chunk: { before: [HEAD], message: { text: `${'x'.repeat(64)}${NEW}` } },
  error: { before: [HEAD], message: { op: 'error', message: NEW } },
  end: { before: [HEAD, { text: held }], message: { op: 'end' } },
  idle: { before: [HEAD, { text: held }], message: null },
};

for (const [channel, { before, message }] of Object.entries(SEAMS)) {
  test(`nothing goes out at the ${channel} after a version read a write followed`, async (t) => {
    const { page, a } = await ready(t);
    const frame = await cdp.target(new RegExp(`^${served.vault}/$`));
    await page.evaluate(() => window.harness.twin());
    await frame.evaluate(() => {
      const data = Object.getOwnPropertyDescriptor(MessageEvent.prototype, 'data');
      Object.defineProperty(MessageEvent.prototype, 'data', {
        get() {
          const deaf = this.target instanceof BroadcastChannel;
          return deaf ? { type: 'popup' } : data.get.call(this);
        },
      });
      window.landed = new Promise((resolve) => {
        window.release = resolve;
      });
      const complete = Object.getOwnPropertyDescriptor(IDBTransaction.prototype, 'oncomplete');
      const add = IDBTransaction.prototype.addEventListener;
      const late = (tx, handler) => (event) => {
        const only = tx.mode === 'readonly' && [...tx.objectStoreNames].join() === 'meta';
        if (!window.armed || !only) return handler.call(tx, event);
        window.armed = false;
        window.held = true;
        window.landed.then(() => handler.call(tx, event));
      };
      Object.defineProperty(IDBTransaction.prototype, 'oncomplete', {
        set(handler) {
          complete.set.call(this, late(this, handler));
        },
        get() {
          return complete.get.call(this);
        },
      });
      IDBTransaction.prototype.addEventListener = function delayed(type, handler, options) {
        const held = type === 'complete' ? late(this, handler) : handler;
        return add.call(this, type, held, options);
      };
    });
    await page.evaluate((f) => window.harness.open(f), secretCall(a));
    for (const step of before) {
      await page.evaluate((s) => window.harness.post(s), step);
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    await frame.evaluate(() => {
      window.armed = true;
    });
    if (message) await page.evaluate((s) => window.harness.post(s), message);
    await frame.until(() => window.held === true);
    await new Promise((resolve) => setTimeout(resolve, 50));
    const count = () => page.evaluate(() => window.harness.opened.parts.length);
    const checked = await count();
    await page.evaluate((value) => {
      const h = window.harness;
      return h.call('put', { name: 'TOKEN_A', value }, [], h.twins[0]);
    }, NEW);
    await frame.evaluate(() => window.release());
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(await count(), checked);
  });
}

test('the stored audit entry holds no value in its rule, tag or exit', async (t) => {
  const { page, a } = await ready(t);
  const rule = { secret: 'TOKEN_A', domain: 'api.example.com', paths: [`/v1/${TOKEN}`] };
  await page.evaluate(
    (list) => window.harness.policy(list),
    [attest(CONFIG, config({ TOKEN_A: a }, [rule]))]
  );
  const fields = secretCall(a, { exit: `device:${TOKEN}`, owner: { ...OWNER, tag: TOKEN } });
  fields.head.url = `https://api.example.com/v1/${TOKEN}`;
  assert.equal((await send(page, fields)).reply.mode, 'secret');
  const frame = await cdp.target(new RegExp(`^${served.vault}/$`));
  const stored = await frame.evaluate(
    () =>
      new Promise((resolve, reject) => {
        const opening = indexedDB.open('slicc-vault');
        opening.onerror = reject;
        opening.onsuccess = () => {
          const read = opening.result.transaction('audit').objectStore('audit').getAll();
          read.onsuccess = () =>
            resolve(JSON.stringify(read.result.filter((entry) => entry.type === 'forward')));
        };
      })
  );
  assert.ok(stored.includes('"type":"forward"'));
  assert.ok(!stored.includes(TOKEN));
});
