import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { browser, openPopup, press, typeInto } from './browser.mjs';
import { setup } from './setup.mjs';

const { chrome, embedder } = await setup();
const cdp = await browser(chrome);
after(() => cdp.close());

const VALUE = 'fake-settings-mcp-0701';
const BRIDGE = 'fake-bridge-mcp-0702';
const ROOT = { pid: 5, ppid: 1, uid: 0, gid: 0, tag: null, users: 'enforce', groups: [0] };
const REPORT = { ...ROOT, users: 'report' };
const UNSTAMPED = { pid: 5, ppid: 1, uid: 0, gid: 0, tag: null };
const CONE = { pid: 7, ppid: 1, uid: 1000, gid: 1000, tag: 'cone', users: 'enforce' };
const SUDOER = { ...CONE, groups: [1000, 27] };
const SCOOP = { pid: 8, ppid: 1, uid: 1001, gid: 1001, tag: 'scoop', users: 'enforce' };
const LOOPBACK = 'http://8081.kernel.localhost/mcp';
const TOKEN_URL = 'https://docs.example.com/token';
const noRecord = (name) => ({
  v: 1,
  error: { code: 'ENOENT', message: `no record named ${name}` },
});
const noToken = (server) => ({
  v: 1,
  state: 'done',
  exit: 3,
  message: `no token for mcp:${server} in seven's vault: run jerk mcp:${server} create`,
});

async function connected(t) {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.connect());
  return page;
}

const sealed = (page, req, stamp) =>
  page.evaluate((r, s) => window.harness.sealed({ v: 1, ...r }, s), req, stamp);
const call = (page, op, fields) => page.evaluate((o, f) => window.harness.call(o, f), op, fields);

const settings = (page, name = 'DOCS_MCP', server = 'docs') =>
  call(page, 'put', { name, value: VALUE, kind: 'mcp', server });

const bridge = (page, name, server = 'docs') =>
  sealed(page, { op: 'seal', name, value: BRIDGE, kind: 'mcp', server, url: LOOPBACK }, SCOOP);

async function jerkStatus(page, server, stamp, reader = stamp, answer = { exit: 0 }) {
  const provider = `mcp:${server}`;
  const asked = await sealed(page, { op: 'request', kind: 'jerk', jop: 'status', provider }, stamp);
  await call(page, 'answer', { request: asked.id, state: 'done', ...answer });
  return sealed(page, { op: 'status', id: asked.id }, reader);
}

test('root gets the placeholder of a Settings mcp record by name and server', async (t) => {
  const page = await connected(t);
  const put = await settings(page);
  const got = await sealed(page, { op: 'placeholder', name: 'DOCS_MCP', server: 'docs' }, ROOT);
  assert.deepEqual(got, { v: 1, placeholder: put.placeholder, state: 'inert' });
});

test('NEGATIVE a cone in the sudo group gets the answer for no record', async (t) => {
  const page = await connected(t);
  await settings(page);
  const got = await sealed(page, { op: 'placeholder', name: 'DOCS_MCP', server: 'docs' }, SUDOER);
  assert.deepEqual(got, noRecord('DOCS_MCP'));
});

test('NEGATIVE uid 0 under another users mode gets the answer for no record', async (t) => {
  const page = await connected(t);
  await settings(page);
  for (const users of ['report', 'off', undefined, ['enforce'], 'Enforce', 'enforce ']) {
    const stamp = { ...ROOT, users };
    const got = await sealed(page, { op: 'placeholder', name: 'DOCS_MCP', server: 'docs' }, stamp);
    assert.deepEqual(got, noRecord('DOCS_MCP'));
  }
});

test('NEGATIVE stamp fields in the request body count for nothing', async (t) => {
  const page = await connected(t);
  await settings(page);
  const req = { op: 'placeholder', name: 'DOCS_MCP', server: 'docs', stamp: ROOT, caller: ROOT };
  assert.deepEqual(
    await sealed(page, { ...req, uid: 0, users: 'enforce' }, CONE),
    noRecord('DOCS_MCP')
  );
});

test('NEGATIVE a malformed stamp is EINVAL', async (t) => {
  const page = await connected(t);
  await settings(page);
  const req = { op: 'placeholder', name: 'DOCS_MCP', server: 'docs' };
  for (const uid of ['0', null, 0.5, -1]) {
    assert.deepEqual(await sealed(page, req, { ...ROOT, uid }), {
      v: 1,
      error: { code: 'EINVAL', message: 'the request carries no valid kernel stamp' },
    });
  }
});

test('NEGATIVE root naming the wrong server, or none, gets the answer for no record', async (t) => {
  const page = await connected(t);
  await settings(page);
  for (const server of ['other', undefined, 7]) {
    const got = await sealed(page, { op: 'placeholder', name: 'DOCS_MCP', server }, ROOT);
    assert.deepEqual(got, noRecord('DOCS_MCP'));
  }
});

test('NEGATIVE root gets nothing for an mcp record bound to no server', async (t) => {
  const page = await connected(t);
  await call(page, 'put', { name: 'LOOSE_MCP', value: VALUE, kind: 'mcp' });
  const got = await sealed(page, { op: 'placeholder', name: 'LOOSE_MCP' }, ROOT);
  assert.deepEqual(got, noRecord('LOOSE_MCP'));
});

test('NEGATIVE root gets nothing for a removed mcp record', async (t) => {
  const page = await connected(t);
  await settings(page);
  await call(page, 'remove', { name: 'DOCS_MCP', kind: 'mcp' });
  const got = await sealed(page, { op: 'placeholder', name: 'DOCS_MCP', server: 'docs' }, ROOT);
  assert.deepEqual(got, noRecord('DOCS_MCP'));
});

test('NEGATIVE a secret-only name keeps its answer, with a server or without', async (t) => {
  const page = await connected(t);
  const put = await call(page, 'put', { name: 'PLAIN_KEY', value: VALUE });
  const today = { v: 1, placeholder: put.placeholder, state: 'inert' };
  for (const stamp of [ROOT, SUDOER]) {
    const got = await sealed(page, { op: 'placeholder', name: 'PLAIN_KEY', server: 'docs' }, stamp);
    assert.deepEqual(got, today);
  }
});

test('a name held by a secret and an mcp record answers by the caller and the server', async (t) => {
  const page = await connected(t);
  const secret = await call(page, 'put', { name: 'SHARED_NAME', value: VALUE });
  const mcp = await settings(page, 'SHARED_NAME');
  const name = 'SHARED_NAME';
  const asRoot = await sealed(page, { op: 'placeholder', name, server: 'docs' }, ROOT);
  assert.equal(asRoot.placeholder, mcp.placeholder);
  const plain = await sealed(page, { op: 'placeholder', name }, ROOT);
  assert.equal(plain.placeholder, secret.placeholder);
  const asCone = await sealed(page, { op: 'placeholder', name, server: 'docs' }, SUDOER);
  assert.equal(asCone.placeholder, secret.placeholder);
});

test('NEGATIVE the sealed list still shows only secrets, to root too', async (t) => {
  const page = await connected(t);
  await settings(page);
  assert.deepEqual(await sealed(page, { op: 'list' }, ROOT), { v: 1, secrets: [] });
});

test('root gets the placeholder and record through a jerk status bios answered exit 0', async (t) => {
  const page = await connected(t);
  const put = await settings(page);
  assert.deepEqual(await jerkStatus(page, 'docs', ROOT), {
    v: 1,
    state: 'done',
    exit: 0,
    placeholder: put.placeholder,
    record: 'inert',
  });
});

test('NEGATIVE a non-root jerk status is byte-identical to one for a server with no record', async (t) => {
  const page = await connected(t);
  await settings(page);
  const message = (server) =>
    `no token for mcp:${server} in seven's vault: run jerk mcp:${server} create`;
  const none = await jerkStatus(page, 'none', SUDOER, SUDOER, {
    exit: 3,
    message: message('none'),
  });
  const got = await jerkStatus(page, 'docs', SUDOER);
  assert.equal(
    JSON.stringify(got),
    `{"v":1,"state":"done","exit":3,"message":${JSON.stringify(message('docs'))}}`
  );
  assert.equal(JSON.stringify(got).replaceAll('mcp:docs', 'mcp:none'), JSON.stringify(none));
});

test('NEGATIVE a done jerk status with no exit gives no placeholder', async (t) => {
  const page = await connected(t);
  await settings(page);
  assert.deepEqual(await jerkStatus(page, 'docs', ROOT, ROOT, {}), {
    v: 1,
    state: 'done',
  });
  assert.deepEqual(await jerkStatus(page, 'docs', SUDOER, SUDOER, {}), noToken('docs'));
});

test('NEGATIVE a jerk status stays exit 3 after its server is rebound', async (t) => {
  const page = await connected(t);
  await settings(page);
  const provider = 'mcp:docs';
  const asked = await sealed(
    page,
    { op: 'request', kind: 'jerk', jop: 'status', provider },
    SUDOER
  );
  await call(page, 'answer', { request: asked.id, state: 'done', exit: 0, user: 'fake-user' });
  const read = () => sealed(page, { op: 'status', id: asked.id }, SUDOER);
  assert.deepEqual(await read(), noToken('docs'));
  await call(page, 'put', { name: 'DOCS_MCP', kind: 'mcp', server: 'other' });
  assert.deepEqual(await read(), noToken('docs'));
});

test("NEGATIVE uid 0 under report gets exit 3 for a jerk status, its own or root's", async (t) => {
  const page = await connected(t);
  await settings(page);
  assert.deepEqual(await jerkStatus(page, 'docs', REPORT), noToken('docs'));
  assert.deepEqual(await jerkStatus(page, 'docs', ROOT, REPORT), noToken('docs'));
});

test("NEGATIVE root reading a cone's jerk status gets exit 3", async (t) => {
  const page = await connected(t);
  await settings(page);
  assert.deepEqual(await jerkStatus(page, 'docs', SUDOER, ROOT), noToken('docs'));
});

test('NEGATIVE a removed record gives every reader exit 3', async (t) => {
  const page = await connected(t);
  await settings(page);
  await call(page, 'remove', { name: 'DOCS_MCP', kind: 'mcp' });
  assert.deepEqual(await jerkStatus(page, 'docs', ROOT), noToken('docs'));
  assert.deepEqual(await jerkStatus(page, 'docs', SUDOER), noToken('docs'));
});

test('NEGATIVE a jerk status exit 0 with no record gives every reader exit 3', async (t) => {
  const page = await connected(t);
  await settings(page);
  assert.deepEqual(await jerkStatus(page, 'other', ROOT), noToken('other'));
  assert.deepEqual(await jerkStatus(page, 'other', SUDOER), noToken('other'));
});

test('NEGATIVE a non-root jerk status hides any bios answer', async (t) => {
  const page = await connected(t);
  const answer = { exit: 1, message: 'fake failure' };
  assert.deepEqual(await jerkStatus(page, 'docs', SUDOER, SUDOER, answer), noToken('docs'));
});

test('NEGATIVE root gets no placeholder when bios answered a nonzero exit', async (t) => {
  const page = await connected(t);
  await settings(page);
  const answer = { exit: 3, message: 'not usable' };
  assert.deepEqual(await jerkStatus(page, 'docs', ROOT, ROOT, answer), {
    v: 1,
    state: 'done',
    exit: 3,
    message: 'not usable',
  });
});

test('NEGATIVE a jerk status of a provider outside mcp is left alone', async (t) => {
  const page = await connected(t);
  await settings(page, 'GITHUB_MCP', 'github');
  const asked = await sealed(
    page,
    { op: 'request', kind: 'jerk', jop: 'status', provider: 'github' },
    SUDOER
  );
  await call(page, 'answer', { request: asked.id, state: 'done', exit: 0 });
  const got = await sealed(page, { op: 'status', id: asked.id }, SUDOER);
  assert.deepEqual(got, { v: 1, state: 'done', exit: 0 });
});

test('several live mcp records on one server are EINVAL for root and exit 3 for a cone', async (t) => {
  const page = await connected(t);
  await settings(page, 'DOCS_MCP');
  await settings(page, 'DOCS_TWO_MCP');
  assert.deepEqual(await jerkStatus(page, 'docs', ROOT), {
    v: 1,
    error: {
      code: 'EINVAL',
      message: 'several mcp records are bound to docs; ask for one by name',
    },
  });
  assert.deepEqual(await jerkStatus(page, 'docs', SUDOER), noToken('docs'));
  const byName = await sealed(page, { op: 'placeholder', name: 'DOCS_MCP', server: 'docs' }, ROOT);
  assert.ok(byName.placeholder);
});

test('an expired sibling does not count as several records', async (t) => {
  const page = await connected(t);
  const put = await settings(page);
  await call(page, 'seal', {
    name: 'STALE_MCP',
    value: 'fake-stale-mcp-0707',
    kind: 'mcp',
    server: 'docs',
    source: 'oauth:mcp',
    expiresAt: Date.now() - 1,
  });
  const got = await jerkStatus(page, 'docs', ROOT);
  assert.equal(got.placeholder, put.placeholder);
});

test("a bridge token does not count as the server's record", async (t) => {
  const page = await connected(t);
  await bridge(page, 'BRIDGE_MCP');
  const put = await settings(page);
  const got = await jerkStatus(page, 'docs', ROOT);
  assert.equal(got.placeholder, put.placeholder);
  assert.deepEqual((await call(page, 'list')).list.mcp, [
    { name: 'DOCS_MCP', server: 'docs', state: 'ready' },
  ]);
});

test('NEGATIVE a bridge token alone gives no record to root', async (t) => {
  const page = await connected(t);
  await bridge(page, 'BRIDGE_MCP');
  assert.deepEqual(await jerkStatus(page, 'docs', ROOT), noToken('docs'));
  assert.deepEqual((await call(page, 'list')).list.mcp, []);
  const got = await sealed(page, { op: 'placeholder', name: 'BRIDGE_MCP', server: 'docs' }, ROOT);
  assert.deepEqual(got, noRecord('BRIDGE_MCP'));
});

test('a page write over a process record gets a new placeholder', async (t) => {
  const page = await connected(t);
  const sealedBy = await bridge(page, 'BRIDGE_MCP');
  const put = await settings(page, 'BRIDGE_MCP');
  assert.notEqual(put.placeholder, sealedBy.placeholder);
  const model = { name: 'A_KEY', kind: 'model', provider: 'openai' };
  const first = await call(page, 'seal', { ...model, value: BRIDGE, source: 'process' });
  const second = await call(page, 'put', { ...model, value: VALUE });
  assert.notEqual(second.placeholder, first.placeholder);
  const rotated = await settings(page, 'BRIDGE_MCP');
  assert.equal(rotated.placeholder, put.placeholder);
});

test('NEGATIVE a process placeholder is not filled after a page write', async (t) => {
  const page = await connected(t);
  const { placeholder } = await bridge(page, 'DOCS_MCP');
  await settings(page);
  await call(page, 'endpoints', {
    mcp: [{ server: 'docs', url: 'https://docs.example.com/mcp', names: ['DOCS_MCP'] }],
  });
  const sent = await page.evaluate((f) => window.harness.forward(f), {
    head: {
      method: 'POST',
      url: 'https://docs.example.com/mcp/call',
      headers: [['Authorization', `Bearer ${placeholder}`]],
    },
    body: '{}',
    owner: SCOOP,
    exit: 'page',
    rawTraits: {},
  });
  assert.ok(sent.reply.refused);
  assert.ok(!JSON.stringify(sent).includes(VALUE));
});

test('a sign-in over a process record gets a new placeholder', async (t) => {
  const page = await connected(t);
  const { placeholder } = await bridge(page, 'DOCS_ACCESS_TOKEN');
  await page.evaluate(() => window.harness.agent());
  const ask = (op, fields) => page.evaluate((o, f) => window.harness.ask(o, f), op, fields);
  await ask('endpoints', {
    mcp: [{ server: 'docs', url: 'https://docs.example.com/mcp', tokenUrl: TOKEN_URL }],
  });
  const granted = await ask('grant', {
    server: 'docs',
    name: 'DOCS_ACCESS_TOKEN',
    oauth: { tokenUrl: TOKEN_URL, clientId: 'fake-client' },
    response: JSON.stringify({ token_type: 'Bearer', access_token: VALUE }),
  });
  const access = granted.records.find((r) => r.name === 'DOCS_ACCESS_TOKEN');
  assert.ok(access.placeholder);
  assert.notEqual(access.placeholder, placeholder);
});

test('a process secret keeps its placeholder under a page write', async (t) => {
  const page = await connected(t);
  const first = await sealed(page, { op: 'seal', name: 'A_SECRET', value: BRIDGE }, SCOOP);
  const put = await call(page, 'put', { name: 'A_SECRET', value: VALUE });
  assert.equal(put.placeholder, first.placeholder);
});

test("a secret record of the provider keeps today's reply for a jerk status", async (t) => {
  const page = await connected(t);
  await settings(page);
  const oauth = await call(page, 'seal', {
    name: 'DOCS_TOKEN',
    value: VALUE,
    source: 'oauth:mcp:docs',
  });
  assert.deepEqual(await jerkStatus(page, 'docs', SUDOER), {
    v: 1,
    state: 'done',
    exit: 0,
    placeholder: oauth.placeholder,
  });
});

test('list.mcp holds only usable records bound to a server, without a placeholder or source', async (t) => {
  const page = await connected(t);
  await settings(page, 'READY_MCP');
  await call(page, 'put', { name: 'LOOSE_MCP', value: 'fake-loose-mcp-0702', kind: 'mcp' });
  await settings(page, 'GONE_MCP');
  await call(page, 'remove', { name: 'GONE_MCP', kind: 'mcp' });
  const expired = { kind: 'mcp', server: 'docs', source: 'oauth:mcp', expiresAt: Date.now() - 1 };
  await call(page, 'seal', { ...expired, name: 'STALE_MCP', value: 'fake-stale-mcp-0703' });
  await call(page, 'seal', {
    name: 'DOCS_GRANT',
    value: 'fake-grant-mcp-0704',
    kind: 'grant',
    source: 'oauth:mcp',
    oauth: { tokenUrl: 'https://docs.example.com/token', clientId: 'fake-client' },
  });
  await call(page, 'seal', {
    ...expired,
    name: 'RENEWS_MCP',
    value: 'fake-renews-mcp-0705',
    refresh: 'DOCS_GRANT',
  });
  await call(page, 'put', {
    name: 'ECHOED_MCP',
    value: 'fake-echoed-mcp-0706',
    kind: 'mcp',
    server: `leak-${VALUE}`,
  });
  const { list } = await call(page, 'list');
  assert.deepEqual(list.mcp, [
    { name: 'READY_MCP', server: 'docs', state: 'ready' },
    { name: 'RENEWS_MCP', server: 'docs', state: 'refreshing' },
  ]);
});

test('list.mcp leaves out a name that holds a value', async (t) => {
  const page = await connected(t);
  await call(page, 'put', { name: 'FAKE_NAME_VALUE_0708', value: 'fake-other-value-0709' });
  await call(page, 'put', { name: 'NAMED_KEY', value: 'FAKE_NAME_VALUE_0708' });
  await settings(page, 'FAKE_NAME_VALUE_0708');
  assert.deepEqual((await call(page, 'list')).list.mcp, []);
});

test('list.mcp leaves out a server too long for a jerk provider', async (t) => {
  const page = await connected(t);
  const server = 'x'.repeat(124);
  await settings(page, 'LONGEST_MCP', server);
  await settings(page, 'TOO_LONG_MCP', `${server}x`);
  assert.deepEqual((await call(page, 'list')).list.mcp, [
    { name: 'LONGEST_MCP', server, state: 'ready' },
  ]);
});

test('list.mcp is empty while the vault is locked before its first unlock', async (t) => {
  const page = await connected(t);
  await settings(page);
  const manage = await openPopup(cdp, page, { kind: 'protect' }, 'Vault lock');
  await press(manage, 'Protect with a passphrase');
  await typeInto(manage, '#passphrase', 'correct horse battery');
  await typeInto(manage, '#confirm', 'correct horse battery');
  await press(manage, 'Protect');
  await manage.until(() => document.body.textContent.includes('Protected with a passphrase.'));
  await press(manage, 'Lock now');
  await page.until(async () => (await window.harness.call('status')).status.locked === true);
  await embedder(t, 'seven', page);
  const welcome = await page.evaluate(() => window.harness.connect());
  assert.equal(welcome.status.locked, true);
  assert.deepEqual((await call(page, 'list')).list.mcp, []);
});

const forwarded = (page, url, placeholder, status) =>
  page.evaluate(
    (f, code) =>
      window.harness.forward(
        f,
        code && {
          head: { status: code, statusText: '', url: f.head.url, headers: [] },
          chunks: ['{}'],
        }
      ),
    {
      head: { method: 'POST', url, headers: [['Authorization', `Bearer ${placeholder}`]] },
      body: '{}',
      owner: ROOT,
      exit: 'page',
      rawTraits: {},
    },
    status
  );

test("root's placeholder is filled on the page-registered URL only, and the read is not audited", async (t) => {
  const page = await connected(t);
  await settings(page);
  await call(page, 'endpoints', {
    mcp: [{ server: 'docs', url: 'https://docs.example.com/mcp', names: ['DOCS_MCP'] }],
  });
  const before = (await call(page, 'audit', {})).audit.length;
  const { placeholder } = await sealed(
    page,
    { op: 'placeholder', name: 'DOCS_MCP', server: 'docs' },
    ROOT
  );
  assert.equal((await call(page, 'audit', {})).audit.length, before);
  const sent = await forwarded(page, 'https://docs.example.com/mcp/call', placeholder);
  assert.deepEqual(sent.reply.head.headers, [['Authorization', `Bearer ${VALUE}`]]);
  const refused = await forwarded(page, 'https://other.example.com/mcp', placeholder);
  assert.ok(refused.reply.refused);
  assert.ok(!JSON.stringify(refused).includes(VALUE));
});

test("with no page server, root's placeholder pins to the agent's URL on first use", async (t) => {
  const page = await connected(t);
  const { placeholder } = await settings(page);
  await page.evaluate(() => window.harness.agent());
  const ask = (op, fields) => page.evaluate((o, f) => window.harness.ask(o, f), op, fields);
  await ask('endpoints', { mcp: [{ server: 'docs', url: 'https://agent.example.com/mcp' }] });
  const sent = await forwarded(page, 'https://agent.example.com/mcp/call', placeholder, 200);
  assert.deepEqual(sent.reply.head.headers, [['Authorization', `Bearer ${VALUE}`]]);
  const { list } = await call(page, 'list');
  const view = list.secrets.find((r) => r.name === 'DOCS_MCP');
  assert.deepEqual([view.url, view.pinned], ['https://agent.example.com/mcp', true]);
  await ask('endpoints', { mcp: [{ server: 'docs', url: 'https://later.example.com/mcp' }] });
  const moved = await forwarded(page, 'https://later.example.com/mcp/call', placeholder);
  assert.ok(moved.reply.refused);
});

test('NEGATIVE a cone cannot read a jerk status of root', async (t) => {
  const page = await connected(t);
  await settings(page);
  const asked = await sealed(
    page,
    { op: 'request', kind: 'jerk', jop: 'status', provider: 'mcp:docs' },
    ROOT
  );
  await call(page, 'answer', { request: asked.id, state: 'done', exit: 0 });
  assert.deepEqual(await sealed(page, { op: 'status', id: asked.id }, SUDOER), {
    v: 1,
    error: { code: 'ENOENT', message: 'no such request' },
  });
});

test('NEGATIVE another namespace sees neither the record nor the request', async (t) => {
  const page = await connected(t);
  await settings(page);
  const asked = await sealed(
    page,
    { op: 'request', kind: 'jerk', jop: 'status', provider: 'mcp:docs' },
    ROOT
  );
  await call(page, 'answer', { request: asked.id, state: 'done', exit: 0 });
  const other = await embedder(t, 'preview', await page.tab());
  await other.evaluate(() => window.harness.connect());
  const named = await sealed(other, { op: 'placeholder', name: 'DOCS_MCP', server: 'docs' }, ROOT);
  assert.deepEqual(named, noRecord('DOCS_MCP'));
  assert.deepEqual(await sealed(other, { op: 'status', id: asked.id }, ROOT), {
    v: 1,
    error: { code: 'ENOENT', message: 'no such request' },
  });
  assert.deepEqual((await call(other, 'list')).list.mcp, []);
});

test('NEGATIVE the agent port has neither list nor sealed', async (t) => {
  const page = await connected(t);
  await settings(page);
  await page.evaluate(() => window.harness.agent());
  const ask = (op, fields) => page.evaluate((o, f) => window.harness.ask(o, f), op, fields);
  assert.equal((await ask('list')).error.code, 'EACCES');
  const req = { v: 1, op: 'placeholder', name: 'DOCS_MCP', server: 'docs' };
  assert.equal((await ask('sealed', { req, stamp: ROOT })).error.code, 'EACCES');
});
