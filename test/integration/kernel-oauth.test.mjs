import assert from 'node:assert/strict';
import { test } from 'node:test';
import { setup } from './setup.mjs';

const { embedder } = await setup();
const ROOT = { pid: 1, ppid: 0, uid: 0, gid: 0, tag: null, users: 'enforce' };
const CONE = { ...ROOT, uid: 1000, groups: [27] };
const ID = { name: 'KERNEL_TOKEN', provider: 'example', account: 'default' };
const GRANT = {
  ...ID,
  accessToken: 'fake-kernel-access-2001',
  refreshToken: 'fake-kernel-refresh-2001',
  oauth: {
    tokenUrl: 'https://idp.example.invalid/token',
    clientId: 'fake-public-client',
    authMethod: 'none',
  },
};
const RESPONSE = {
  status: 200,
  headers: [],
  body: JSON.stringify({
    access_token: 'fake-kernel-access-2002',
    refresh_token: 'fake-kernel-refresh-2002',
    token_type: 'Bearer',
    expires_in: 3600,
  }),
};

async function connected(t) {
  const page = await embedder(t);
  const welcome = await page.evaluate(() => window.harness.connect());
  return { page, welcome };
}

async function call(page, op, fields = {}, stamp = ROOT, marker = 1, twin = false) {
  const result = await page.evaluate(
    (req, caller, outer, other) =>
      window.harness.call(
        'sealed',
        { req, stamp: caller, ...(outer ? { kernelOAuth: outer } : {}) },
        [],
        other ? window.harness.twins[0] : null
      ),
    { v: 1, op, ...(op === 'capabilities' ? {} : ID), ...fields },
    stamp,
    marker,
    twin
  );
  return result.reply;
}

const registered = (page, fields = {}, stamp = ROOT) =>
  call(page, 'oauthGrant', { ...GRANT, ...fields }, stamp);
const error = (reply, code) => assert.equal(reply.error?.code, code, JSON.stringify(reply));
const egress = (page, response = RESPONSE) =>
  page.evaluate((answer) => {
    window.harness.egress.answer = answer;
  }, response);

test('kernel OAuth capability requires the trusted outer bios assertion', async (t) => {
  const { page, welcome } = await connected(t);
  assert.equal(welcome.status.capabilities.kernelOAuth, 1);
  assert.deepEqual(await call(page, 'capabilities'), { v: 1, capabilities: { kernelOAuth: 1 } });
  assert.deepEqual(await call(page, 'capabilities', {}, ROOT, 0), { v: 1, capabilities: {} });
  error(await call(page, 'capabilities', { kernelOAuth: 1 }, ROOT, 0), 'EINVAL');
  error(await call(page, 'oauthGrant', GRANT, ROOT, 0), 'ENOTSUP');
  assert.equal((await page.evaluate(() => window.harness.call('list'))).list.secrets.length, 0);
});

test('kernel OAuth registration publishes scrub before success and exposes only access discovery', async (t) => {
  const { page } = await connected(t);
  const initial = await registered(page);
  assert.deepEqual(Object.keys(initial).sort(), [
    'expiresAt',
    'placeholder',
    'refreshable',
    'state',
    'v',
  ]);
  assert.equal(initial.state, 'ready');
  assert.equal(initial.expiresAt, null);
  const sequence = await page.evaluate(() =>
    window.harness.seen.filter((e) => e.source === 'port').map((e) => JSON.parse(e.data))
  );
  const success = sequence.findIndex((e) => e.reply?.refreshable === true);
  assert.ok(
    sequence
      .slice(0, success)
      .some((e) => e.event === 'placeholders' && e.scrub.ready && e.scrub.needed)
  );
  const lookup = await page.evaluate(
    (name) => window.harness.sealed({ v: 1, op: 'placeholder', name }),
    ID.name
  );
  assert.equal(lookup.oauthManaged, true);
  assert.equal(lookup.placeholder, initial.placeholder);
  const list = await page.evaluate(() => window.harness.sealed({ v: 1, op: 'list' }));
  assert.equal(list.secrets.length, 1);
  assert.equal(list.secrets[0].oauthManaged, true);
  const redacted = await page.evaluate(
    async (values) => {
      await window.harness.agent();
      return window.harness.ask('redact', { texts: values });
    },
    [GRANT.accessToken, GRANT.refreshToken]
  );
  assert.equal(redacted.texts[0], initial.placeholder);
  assert.ok(redacted.texts.every((s) => /^fnox_proxy_[0-9a-f]{24}$/.test(s)));
});

test('kernel forced refresh supports unknown expiry and rotates through existing egress', async (t) => {
  const { page } = await connected(t);
  const initial = await registered(page);
  await egress(page);
  const fresh = await call(page, 'oauthRefresh');
  assert.equal(fresh.placeholder, initial.placeholder);
  assert.equal(fresh.state, 'ready');
  assert.ok(fresh.expiresAt > Date.now() + 3500000);
  assert.deepEqual(await call(page, 'oauthStatus'), fresh);
  await call(page, 'oauthRefresh');
  const sent = await page.evaluate(() => window.harness.egress.requests);
  assert.equal(sent.length, 2);
  assert.equal(sent[0].url, GRANT.oauth.tokenUrl);
  assert.equal(new URLSearchParams(sent[0].body).get('refresh_token'), GRANT.refreshToken);
  assert.equal(new URLSearchParams(sent[1].body).get('refresh_token'), 'fake-kernel-refresh-2002');
});

test('simultaneously admitted kernel refresh calls share the committed refresh', async (t) => {
  const { page } = await connected(t);
  await registered(page);
  await egress(page);
  await page.evaluate(() => {
    window.harness.egress.delay = 100;
  });
  const [a, b] = await Promise.all([call(page, 'oauthRefresh'), call(page, 'oauthRefresh')]);
  assert.deepEqual(a, b);
  assert.equal((await page.evaluate(() => window.harness.egress.requests)).length, 1);
});

test('cross-frame kernel refresh calls share one provider request', async (t) => {
  const { page } = await connected(t);
  await registered(page);
  await egress(page);
  await page.evaluate(async () => {
    await window.harness.twin();
    window.harness.egress.delay = 100;
  });
  const [a, b] = await Promise.all([
    call(page, 'oauthRefresh'),
    call(page, 'oauthRefresh', {}, ROOT, 1, true),
  ]);
  assert.deepEqual(a, b);
  assert.equal((await page.evaluate(() => window.harness.egress.requests)).length, 1);
});

test('invalid_grant invalidates access use immediately and is not sent again', async (t) => {
  const { page } = await connected(t);
  await registered(page, { expiresAt: Date.now() + 3600000 });
  await egress(page, {
    status: 400,
    headers: [],
    body: JSON.stringify({ error: 'invalid_grant', error_description: GRANT.refreshToken }),
  });
  const failed = await call(page, 'oauthRefresh');
  assert.equal(failed.error.cause, 'oauth-reauth-required');
  assert.equal((await call(page, 'oauthStatus')).state, 'reauth-required');
  const verdict = await page.evaluate(
    (name) =>
      window.harness.sealed(
        { v: 1, op: 'test', name, url: 'https://api.example.invalid/' },
        { pid: 1, ppid: 0, uid: 0, gid: 0, users: 'enforce' }
      ),
    ID.name
  );
  assert.equal(verdict.cause, 'record-expired');
  error(await call(page, 'oauthRefresh'), 'EACCES');
  assert.equal((await page.evaluate(() => window.harness.egress.requests)).length, 1);
  assert.ok(!JSON.stringify(failed).includes(GRANT.refreshToken));
});

test('linked drop prevents a late kernel refresh from resurrecting credentials', async (t) => {
  const { page } = await connected(t);
  const initial = await registered(page);
  await page.evaluate(async () => {
    await window.harness.twin();
    window.harness.egress.manual = true;
  });
  const pending = call(page, 'oauthRefresh');
  await page.until(() => window.harness.egress.held.length === 1);
  assert.deepEqual(await call(page, 'oauthRemove', {}, ROOT, 1, true), { v: 1, removed: true });
  await page.evaluate((answer) => window.harness.egress.release(answer), RESPONSE);
  error(await pending, 'EAGAIN');
  assert.equal((await call(page, 'oauthStatus')).state, 'removed');
  assert.deepEqual(await call(page, 'oauthRemove'), { v: 1, removed: true });
  const list = (await page.evaluate(() => window.harness.call('list'))).list.secrets;
  assert.ok(list.every((r) => r.state === 'removed'));
  const lookup = await page.evaluate(
    (name) => window.harness.sealed({ v: 1, op: 'placeholder', name }),
    ID.name
  );
  assert.equal(lookup.oauthManaged, true);
  assert.equal((await registered(page)).placeholder, initial.placeholder);
});

test('kernel grants preserve ownership and immutable endpoint binding including tombstones', async (t) => {
  const { page } = await connected(t);
  await registered(page, {}, CONE);
  error(await registered(page, {}, { ...CONE, uid: 1001 }), 'EEXIST');
  error(await call(page, 'oauthRemove', {}, { ...CONE, uid: 1001 }), 'EEXIST');
  error(await registered(page, { account: 'other' }), 'EEXIST');
  error(
    await registered(page, {
      oauth: { ...GRANT.oauth, tokenUrl: 'https://other.example.invalid/token' },
    }),
    'EEXIST'
  );
  error(await call(page, 'oauthStatus', { provider: 'other' }), 'EEXIST');
  await call(page, 'oauthRemove');
  error(await registered(page, { oauth: { ...GRANT.oauth, clientId: 'other-client' } }), 'EEXIST');
  assert.equal((await registered(page)).state, 'ready');
});

test('unsupported client authentication and captured fields never store partial grants', async (t) => {
  const { page } = await connected(t);
  error(await registered(page, { clientSecret: 'fake-confidential-secret' }), 'ENOTSUP');
  error(await registered(page, { fields: { EXTRA: 'fake-captured-value' } }), 'ENOTSUP');
  error(
    await registered(page, { oauth: { ...GRANT.oauth, authMethod: 'client_secret_post' } }),
    'ENOTSUP'
  );
  error(await registered(page, { stamp: ROOT }), 'EINVAL');
  error(await registered(page, { oauth: { ...GRANT.oauth, scope: GRANT.refreshToken } }), 'EINVAL');
  error(await registered(page, { refreshToken: 'short' }), 'EINVAL');
  assert.equal((await page.evaluate(() => window.harness.call('list'))).list.secrets.length, 0);
});

test('reauthentication without refresh removes the linked grant without changing the placeholder', async (t) => {
  const { page } = await connected(t);
  const initial = await registered(page);
  const noRefresh = { ...GRANT, expiresAt: 0 };
  delete noRefresh.refreshToken;
  const only = await call(page, 'oauthGrant', noRefresh);
  assert.equal(only.placeholder, initial.placeholder);
  assert.equal(only.state, 'expired');
  assert.equal(only.refreshable, false);
  error(await call(page, 'oauthRefresh'), 'ENOTSUP');
  const list = (await page.evaluate(() => window.harness.call('list'))).list.secrets;
  assert.equal(list.find((r) => r.kind === 'grant').state, 'removed');
});

test('generic owner replacement atomically retires the private grant and clears discovery', async (t) => {
  const { page } = await connected(t);
  await registered(page);
  await page.evaluate(
    (name) => window.harness.call('put', { name, value: 'fake-settings-replacement' }),
    ID.name
  );
  error(await call(page, 'oauthStatus'), 'ENOENT');
  const lookup = await page.evaluate(
    (name) => window.harness.sealed({ v: 1, op: 'placeholder', name }),
    ID.name
  );
  assert.equal(lookup.oauthManaged, undefined);
  assert.equal(
    (await page.evaluate(() => window.harness.call('list'))).list.secrets.find(
      (r) => r.kind === 'grant'
    ).state,
    'removed'
  );
});

test('private refresh grants cannot be looked up, materialized or exported as grants', async (t) => {
  const { page } = await connected(t);
  await registered(page);
  const grant = (await page.evaluate(() => window.harness.call('list'))).list.secrets.find(
    (r) => r.kind === 'grant'
  );
  error(
    await page.evaluate(
      (name) => window.harness.sealed({ v: 1, op: 'placeholder', name }),
      grant.name
    ),
    'ENOENT'
  );
  error(
    await page.evaluate(
      (name, stamp) =>
        window.harness.sealed(
          {
            v: 1,
            op: 'materialize',
            names: [name],
            path: '/usr/bin/true',
            argv: ['/usr/bin/true'],
            cwd: '/',
          },
          stamp
        ),
      grant.name,
      ROOT
    ),
    'ENOENT'
  );
  const backup = await page.evaluate(() =>
    window.harness.call('export', { passphrase: 'fake-backup-passphrase' })
  );
  assert.equal(backup.count, 1);
  const listed = await page.evaluate(async () => {
    await window.harness.agent();
    return window.harness.ask('records');
  });
  assert.deepEqual(listed.records, []);
});

test('a non-root process cannot clear a managed tombstone to bypass its binding', async (t) => {
  const { page } = await connected(t);
  await registered(page, {}, CONE);
  await call(page, 'oauthRemove');
  const replaced = await page.evaluate(
    (name, stamp) =>
      window.harness.sealed({ v: 1, op: 'seal', name, value: 'fake-process-replacement' }, stamp),
    ID.name,
    CONE
  );
  error(replaced, 'EEXIST');
  error(await registered(page, { account: 'another' }), 'EEXIST');
});
