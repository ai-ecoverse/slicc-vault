import assert from 'node:assert/strict';
import { test } from 'node:test';
import { setup } from './setup.mjs';

const { embedder } = await setup();
const OWNER = { pid: 5, ppid: 1, uid: 1000, gid: 1000, tag: 'cone' };

async function connected(t) {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.connect());
  return page;
}

test('a route (b) sign-in is sealed against its request, with a grant that refreshes through egress', async (t) => {
  const page = await connected(t);
  const asked = await page.evaluate(
    (owner) =>
      window.harness.sealed(
        { v: 1, op: 'request', kind: 'oauth', provider: 'github', oauth: {} },
        owner
      ),
    OWNER
  );
  const grant = await page.evaluate(() =>
    window.harness.call('seal', {
      name: 'GITHUB_GRANT',
      value: 'fake-refresh-token-0001',
      kind: 'grant',
      source: 'oauth:github',
      oauth: { tokenUrl: 'https://auth.example.com/token', clientId: 'fake-client', scope: 'repo' },
    })
  );
  assert.equal(grant.state, 'inert');
  const token = await page.evaluate(
    (id) =>
      window.harness.call('seal', {
        name: 'GITHUB_TOKEN',
        value: 'fake-access-token-0001',
        source: 'oauth:github',
        refresh: 'GITHUB_GRANT',
        expiresAt: Date.now() + 60000,
        request: id,
        jerk: { exit: 0, user: 'octo', scopes: ['repo'] },
      }),
    asked.id
  );
  const status = await page.evaluate(
    (id, owner) => window.harness.sealed({ v: 1, op: 'status', id }, owner),
    asked.id,
    OWNER
  );
  assert.deepEqual(status, {
    v: 1,
    state: 'done',
    jerk: { exit: 0, user: 'octo', scopes: ['repo'] },
    placeholder: token.placeholder,
    record: 'inert',
  });
  await page.evaluate(() => {
    window.harness.egress.answer = {
      status: 200,
      headers: [['content-type', 'application/json']],
      body: JSON.stringify({
        access_token: 'fake-access-token-0002',
        refresh_token: 'fake-refresh-token-0002',
        expires_in: 3600,
      }),
    };
  });
  const refreshed = await page.evaluate(() =>
    window.harness.call('refresh', { name: 'GITHUB_TOKEN' })
  );
  assert.equal(refreshed.state, 'refreshed');
  assert.ok(refreshed.expiresAt > Date.now() + 3500000);
  const sent = await page.evaluate(() => window.harness.egress.requests[0]);
  assert.equal(sent.method, 'POST');
  assert.equal(sent.url, 'https://auth.example.com/token');
  assert.equal(
    sent.body,
    'grant_type=refresh_token&refresh_token=fake-refresh-token-0001&client_id=fake-client&scope=repo'
  );
  const red = await page.evaluate(async () => {
    await window.harness.agent();
    return window.harness.ask('redact', {
      texts: ['a fake-access-token-0002 b fake-refresh-token-0002'],
    });
  });
  const placeholders = (await page.evaluate(() => window.harness.call('list'))).list.secrets;
  const byName = Object.fromEntries(placeholders.map((s) => [s.name, s.placeholder]));
  assert.equal(red.texts[0], `a ${byName.GITHUB_TOKEN} b ${byName.GITHUB_GRANT}`);
  assert.equal(byName.GITHUB_TOKEN, token.placeholder);
  await page.evaluate(() => {
    window.harness.egress.answer = { status: 400, headers: [], body: '{"error":"invalid_grant"}' };
  });
  const failed = await page.evaluate(() =>
    window.harness.call('refresh', { name: 'GITHUB_TOKEN' })
  );
  assert.equal(failed.error.message, 'refresh failed: invalid_grant');
  await page.evaluate(() => {
    window.harness.egress.answer = {
      status: 200,
      headers: [],
      body: '{"access_token":"fake-access-token-0003","expires_in":-5}',
    };
  });
  const invalid = await page.evaluate(() =>
    window.harness.call('refresh', { name: 'GITHUB_TOKEN' })
  );
  assert.equal(invalid.error.code, 'EACCES');
  assert.equal(invalid.error.message, 'refresh failed: the IdP returned an invalid expires_in');
  await page.evaluate(() => {
    window.harness.egress.answer = {
      status: 200,
      headers: [],
      body: '{"access_token":"fake-access-token-0005","refresh_token":""}',
    };
  });
  const empty = await page.evaluate(() => window.harness.call('refresh', { name: 'GITHUB_TOKEN' }));
  assert.match(empty.error.message, /shorter than 8 bytes/);
  const mismatched = await page.evaluate(async () => [
    await window.harness.call('seal', {
      name: 'WRONG_LEASE',
      value: 'fake-access-token-0004',
      source: 'oauth:github',
      refresh: 'jerk-seal',
      expiresAt: Date.now() + 60000,
    }),
    await window.harness.call('seal', {
      name: 'WRONG_TOKEN',
      value: 'fake-lease-value-0004',
      source: 'jerk:npm@air',
      refresh: 'GITHUB_GRANT',
      expiresAt: Date.now() + 60000,
    }),
  ]);
  assert.deepEqual(
    mismatched.map((r) => r.error.code),
    ['EINVAL', 'EINVAL']
  );
  const audit = (await page.evaluate(() => window.harness.call('audit', { limit: 20 }))).audit;
  assert.ok(
    audit.some(
      (e) => e.type === 'refresh' && e.name === 'GITHUB_TOKEN' && e.grant === 'GITHUB_GRANT'
    )
  );
});

test('two vault frames refresh one token with one request to the IdP', async (t) => {
  const page = await connected(t);
  assert.equal((await page.evaluate(() => window.harness.twin())).op, 'welcome');
  await page.evaluate(async () => {
    await window.harness.call('seal', {
      name: 'TWIN_GRANT',
      value: 'fake-refresh-token-0101',
      kind: 'grant',
      source: 'oauth:github',
      oauth: { tokenUrl: 'https://auth.example.com/token', clientId: 'fake-client' },
    });
    await window.harness.call('seal', {
      name: 'TWIN_TOKEN',
      value: 'fake-access-token-0101',
      source: 'oauth:github',
      refresh: 'TWIN_GRANT',
      expiresAt: Date.now() + 60000,
    });
    window.harness.egress.delay = 400;
    window.harness.egress.answer = {
      status: 200,
      headers: [],
      body: JSON.stringify({ access_token: 'fake-access-token-0102', expires_in: 3600 }),
    };
  });
  const [here, there] = await page.evaluate(() =>
    Promise.all([
      window.harness.call('refresh', { name: 'TWIN_TOKEN' }),
      window.harness.call('refresh', { name: 'TWIN_TOKEN' }, [], window.harness.twins[0]),
    ])
  );
  assert.equal(here.state, 'refreshed');
  assert.equal(there.state, 'refreshed');
  assert.equal(here.expiresAt, there.expiresAt);
  const sent = await page.evaluate(() => window.harness.egress.requests);
  assert.equal(sent.length, 1);
});

test('a J1 lease due for refresh is announced to the page', async (t) => {
  const page = await connected(t);
  await page.evaluate(() =>
    window.harness.call('seal', {
      name: 'NPM_TOKEN',
      value: 'fake-lease-value-0001',
      source: 'jerk:npm@air',
      refresh: 'jerk-seal',
      expiresAt: Date.now() + 1000,
    })
  );
  const reply = await page.evaluate(() => window.harness.call('refresh', { name: 'NPM_TOKEN' }));
  assert.equal(reply.state, 'requested');
  const event = await page.until(() => window.harness.events.find((e) => e.event === 'refresh'));
  assert.deepEqual([event.name, event.source], ['NPM_TOKEN', 'jerk:npm@air']);
  const none = await page.evaluate(() => window.harness.call('refresh', { name: 'NOPE' }));
  assert.equal(none.error.code, 'ENOENT');
  const bad = await page.evaluate(() =>
    window.harness.call('seal', {
      name: 'X_TOKEN',
      value: 'fake-x-value-0001',
      source: 'settings',
      oauth: { tokenUrl: 'https://a.example.com', clientId: 'c' },
    })
  );
  assert.equal(bad.error.code, 'EINVAL');
});
