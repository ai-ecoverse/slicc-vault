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
  await page.evaluate(() => {
    window.harness.egress.answer = {
      status: 200,
      headers: [],
      body: '{"access_token":"fake-access-token-0006","refresh_token":null}',
    };
  });
  const nulled = await page.evaluate(() =>
    window.harness.call('refresh', { name: 'GITHUB_TOKEN' })
  );
  assert.equal(nulled.error.message, 'refresh failed: the IdP returned an invalid refresh_token');
  await page.evaluate(() => {
    window.harness.egress.answer = {
      status: 200,
      headers: [],
      body: '{"access_token":"fake-access-token-0007","token_type":"mac","error":"x"}',
    };
  });
  const both = await page.evaluate(() => window.harness.call('refresh', { name: 'GITHUB_TOKEN' }));
  assert.equal(both.error.message, 'refresh failed: x');
  await page.evaluate(() => {
    window.harness.egress.answer = {
      status: 200,
      headers: [],
      body: '{"access_token":"fake-access-token-0008","token_type":"mac"}',
    };
  });
  const mac = await page.evaluate(() => window.harness.call('refresh', { name: 'GITHUB_TOKEN' }));
  assert.equal(
    mac.error.message,
    'refresh failed: the IdP returned a token_type other than Bearer'
  );
  await page.evaluate(() => {
    window.harness.egress.answer = { error: 'offline' };
  });
  const offline = await page.evaluate(() =>
    window.harness.call('refresh', { name: 'GITHUB_TOKEN' })
  );
  assert.equal(offline.error.code, 'ENOTCONN');
  assert.equal(offline.error.message, 'egress failed: offline');
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

test('a page port that stopped answering egress gets no more, and the next refresh goes to a live one', {
  timeout: 90000,
}, async (t) => {
  const page = await connected(t);
  assert.equal((await page.evaluate(() => window.harness.twin(true, true))).op, 'welcome');
  await page.evaluate(async () => {
    await window.harness.call('seal', {
      name: 'CLOSED_GRANT',
      value: 'fake-refresh-token-0201',
      kind: 'grant',
      source: 'oauth:github',
      oauth: { tokenUrl: 'https://auth.example.com/token', clientId: 'fake-client' },
    });
    await window.harness.call('seal', {
      name: 'CLOSED_TOKEN',
      value: 'fake-access-token-0201',
      source: 'oauth:github',
      refresh: 'CLOSED_GRANT',
      expiresAt: Date.now() + 60000,
    });
    window.harness.egress.answer = {
      status: 200,
      headers: [],
      body: JSON.stringify({ access_token: 'fake-access-token-0202', expires_in: 3600 }),
    };
    window.harness.call('refresh', { name: 'CLOSED_TOKEN' }).then((reply) => {
      window.first = reply;
    });
  });
  let first = null;
  while (!first) {
    await new Promise((resolve) => setTimeout(resolve, 1000));
    first = await page.evaluate(() => window.first ?? null);
  }
  assert.equal(first.error.code, 'ETIMEDOUT');
  const refreshed = await page.evaluate(() =>
    window.harness.call('refresh', { name: 'CLOSED_TOKEN' })
  );
  assert.equal(refreshed.state, 'refreshed');
  const kept = await page.evaluate(async () => {
    const before = window.harness.twinEvents.length;
    const list = await window.harness.call('list', {}, [], window.harness.twins[0]);
    await window.harness.call('seal', {
      name: 'AFTER',
      value: 'fake-after-value-0001',
      source: 'settings',
    });
    await new Promise((resolve) => setTimeout(resolve, 300));
    return { list: Boolean(list.list), events: window.harness.twinEvents.length - before };
  });
  assert.equal(kept.list, true);
  assert.ok(kept.events > 0);
});

test('a grant removed and restored while its refresh is in flight refuses the stale response', async (t) => {
  const page = await connected(t);
  assert.equal((await page.evaluate(() => window.harness.twin(true))).op, 'welcome');
  const result = await page.evaluate(async () => {
    const h = window.harness;
    await h.call('seal', {
      name: 'RACE_GRANT',
      value: 'fake-refresh-token-0401',
      kind: 'grant',
      source: 'oauth:github',
      oauth: { tokenUrl: 'https://auth.example.com/token', clientId: 'fake-client' },
    });
    await h.call('seal', {
      name: 'RACE_TOKEN',
      value: 'fake-access-token-0401',
      source: 'oauth:github',
      refresh: 'RACE_GRANT',
      expiresAt: Date.now() + 60000,
    });
    h.egress.delay = 1500;
    h.egress.answer = {
      status: 200,
      headers: [],
      body: JSON.stringify({ access_token: 'fake-access-token-0402', expires_in: 3600 }),
    };
    const pending = h.call('refresh', { name: 'RACE_TOKEN' });
    while (h.egress.requests.length === 0) await new Promise((resolve) => setTimeout(resolve, 20));
    const other = h.twins[0];
    const removed = await h.call('remove', { name: 'RACE_GRANT', kind: 'grant' }, [], other);
    const restored = await h.call('restore', { name: 'RACE_GRANT', kind: 'grant' }, [], other);
    const reply = await pending;
    h.egress.delay = 0;
    return { removed: !removed.error, restored: !restored.error, reply };
  });
  assert.equal(result.removed, true);
  assert.equal(result.restored, true);
  assert.equal(result.reply.error.code, 'EAGAIN');
  assert.match(result.reply.error.message, /RACE_GRANT changed meanwhile/);
});

test('the minute sweep refreshes a due token without being asked', {
  timeout: 120000,
}, async (t) => {
  const page = await connected(t);
  await page.evaluate(async () => {
    await window.harness.call('seal', {
      name: 'SWEPT_GRANT',
      value: 'fake-refresh-token-0301',
      kind: 'grant',
      source: 'oauth:github',
      oauth: { tokenUrl: 'https://auth.example.com/token', clientId: 'fake-client' },
    });
    await window.harness.call('seal', {
      name: 'SWEPT_TOKEN',
      value: 'fake-access-token-0301',
      source: 'oauth:github',
      refresh: 'SWEPT_GRANT',
      expiresAt: Date.now() + 60000,
    });
    window.harness.egress.answer = {
      status: 200,
      headers: [],
      body: JSON.stringify({ access_token: 'fake-access-token-0302', expires_in: 3600 }),
    };
  });
  let sent = 0;
  for (let i = 0; i < 80 && sent === 0; i++) {
    await new Promise((resolve) => setTimeout(resolve, 1000));
    sent = await page.evaluate(() => window.harness.egress.requests.length);
  }
  assert.equal(sent, 1);
  let audit = [];
  for (let i = 0; i < 10 && !audit.some((e) => e.type === 'refresh'); i++) {
    await new Promise((resolve) => setTimeout(resolve, 200));
    audit = (await page.evaluate(() => window.harness.call('audit', { limit: 5 }))).audit;
  }
  assert.ok(audit.some((e) => e.type === 'refresh' && e.name === 'SWEPT_TOKEN'));
});

test('a page that says hello gets its due tokens refreshed at once', async (t) => {
  const page = await connected(t);
  await page.evaluate(async () => {
    await window.harness.call('seal', {
      name: 'HELLO_GRANT',
      value: 'fake-refresh-token-0401',
      kind: 'grant',
      source: 'oauth:github',
      oauth: { tokenUrl: 'https://auth.example.com/token', clientId: 'fake-client' },
    });
    await window.harness.call('seal', {
      name: 'HELLO_TOKEN',
      value: 'fake-access-token-0401',
      source: 'oauth:github',
      refresh: 'HELLO_GRANT',
      expiresAt: Date.now() + 60000,
    });
    window.harness.egress.answer = {
      status: 200,
      headers: [],
      body: JSON.stringify({ access_token: 'fake-access-token-0402', expires_in: 3600 }),
    };
  });
  assert.equal(await page.evaluate(() => window.harness.egress.requests.length), 0);
  assert.equal((await page.evaluate(() => window.harness.twin(true))).op, 'welcome');
  await page.until(() => window.harness.egress.requests.length === 1);
  let audit = [];
  for (let i = 0; i < 20 && !audit.some((e) => e.type === 'refresh'); i++) {
    await new Promise((resolve) => setTimeout(resolve, 100));
    audit = (await page.evaluate(() => window.harness.call('audit', { limit: 5 }))).audit;
  }
  assert.ok(audit.some((e) => e.type === 'refresh' && e.name === 'HELLO_TOKEN'));
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
