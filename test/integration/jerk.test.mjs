import assert from 'node:assert/strict';
import { test } from 'node:test';
import { setup } from './setup.mjs';

const { embedder } = await setup();
const CONE = {
  pid: 7,
  ppid: 1,
  uid: 1000,
  gid: 1000,
  tag: JSON.stringify({ kind: 'user', where: 'terminal:1' }),
  users: 'enforce',
  groups: [1000, 27],
};
const SCOOP = {
  pid: 8,
  ppid: 1,
  uid: 1001,
  gid: 1000,
  tag: JSON.stringify({ kind: 'agent', agentId: 'cone:cone' }),
  users: 'enforce',
  groups: [1001, 1000],
};

async function connected(t) {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.connect());
  return page;
}

const sealed = (page, req, stamp) =>
  page.evaluate((r, s) => window.harness.sealed({ v: 1, ...r }, s), req, stamp);

test('jerk list and status are answered by the page through the vault', async (t) => {
  const page = await connected(t);
  const asked = await sealed(page, { op: 'request', kind: 'jerk', jop: 'list' }, SCOOP);
  assert.equal(asked.state, 'pending');
  const second = await sealed(
    page,
    { op: 'request', kind: 'jerk', jop: 'status', provider: 'github' },
    SCOOP
  );
  assert.equal(second.state, 'pending');
  const waiting = (await page.evaluate(() => window.harness.call('status'))).status.waiting;
  assert.deepEqual(waiting, []);
  const rows = [
    {
      provider: 'github',
      name: 'GitHub',
      env: ['GH_TOKEN', 'GITHUB_TOKEN'],
      device: 'air',
      user: 'octo',
      scopes: ['repo'],
      token: 'fake-should-drop',
    },
  ];
  const answered = await page.evaluate(
    (id, r) => window.harness.call('answer', { request: id, state: 'done', exit: 0, rows: r }),
    asked.id,
    rows
  );
  assert.equal(answered.state, 'done');
  const status = await sealed(page, { op: 'status', id: asked.id }, SCOOP);
  assert.deepEqual(status, {
    v: 1,
    state: 'done',
    exit: 0,
    rows: [
      {
        provider: 'github',
        env: ['GH_TOKEN', 'GITHUB_TOKEN'],
        name: 'GitHub',
        device: 'air',
        user: 'octo',
        scopes: ['repo'],
      },
    ],
  });
  const late = await page.evaluate(
    (id) => window.harness.call('answer', { request: id, state: 'done' }),
    asked.id
  );
  assert.equal(late.error.code, 'EINVAL');
  const lease = await page.evaluate(() =>
    window.harness.call('seal', {
      name: 'GH_TOKEN',
      value: 'fake-lease-value-0001',
      source: 'jerk:github@air',
      refresh: 'jerk-seal',
      expiresAt: Date.now() + 3600000,
    })
  );
  await page.evaluate(
    (id) => window.harness.call('answer', { request: id, state: 'done', exit: 0 }),
    second.id
  );
  const sealedStatus = await sealed(page, { op: 'status', id: second.id }, SCOOP);
  assert.deepEqual(sealedStatus, { v: 1, state: 'done', exit: 0, placeholder: lease.placeholder });
  const forged = await sealed(
    page,
    { op: 'request', kind: 'jerk', jop: 'status', provider: 'npm' },
    SCOOP
  );
  const refusedPlaceholder = await page.evaluate(
    (id) =>
      window.harness.call('answer', {
        request: id,
        state: 'done',
        exit: 0,
        placeholder: 'fnox_proxy_000000000000000000000000',
      }),
    forged.id
  );
  assert.equal(refusedPlaceholder.error.code, 'EINVAL');
  await page.evaluate(
    (id) =>
      window.harness.call('answer', {
        request: id,
        state: 'done',
        exit: 3,
        message: 'npm is not signed in',
      }),
    forged.id
  );
  const notSealed = await sealed(page, { op: 'status', id: forged.id }, SCOOP);
  assert.deepEqual(notSealed, { v: 1, state: 'done', exit: 3, message: 'npm is not signed in' });
});

test('create and drop are for root and cones, with progress, exit and cancel', async (t) => {
  const page = await connected(t);
  const refused = await sealed(
    page,
    { op: 'request', kind: 'jerk', jop: 'create', provider: 'github' },
    SCOOP
  );
  assert.equal(refused.state, 'done');
  assert.equal(refused.exit, 2);
  const status = await sealed(page, { op: 'status', id: refused.id }, SCOOP);
  assert.equal(status.exit, 2);
  const drop = await sealed(page, { op: 'request', kind: 'unseal', provider: 'github' }, SCOOP);
  assert.equal(drop.exit, 2);
  const create = await sealed(
    page,
    {
      op: 'request',
      kind: 'jerk',
      jop: 'create',
      provider: 'github',
      scope: 'repo',
      params: { device: 'air' },
    },
    CONE
  );
  assert.equal(create.state, 'pending');
  const busy = await sealed(page, { op: 'request', kind: 'value', name: 'X' }, CONE);
  assert.equal(busy.error.code, 'EAGAIN');
  await page.evaluate(
    (id) =>
      window.harness.call('answer', {
        request: id,
        state: 'progress',
        progress: 'waiting for the sign-in',
      }),
    create.id
  );
  const pending = await sealed(page, { op: 'status', id: create.id }, CONE);
  assert.deepEqual(pending, { v: 1, state: 'pending', progress: 'waiting for the sign-in' });
  const cancel = await sealed(page, { op: 'cancel', id: create.id }, CONE);
  assert.equal(cancel.state, 'cancelled');
  const event = await page.until(() => window.harness.events.find((e) => e.event === 'cancelled'));
  assert.deepEqual([event.request, event.kind], [create.id, 'jerk']);
  const report = await sealed(
    page,
    { op: 'request', kind: 'unseal', provider: 'github' },
    { ...CONE, users: 'report' }
  );
  assert.equal(report.exit, 2);
  const noGroups = await sealed(
    page,
    { op: 'request', kind: 'unseal', provider: 'github' },
    { ...CONE, groups: undefined }
  );
  assert.equal(noGroups.exit, 2);
  const root = await sealed(
    page,
    { op: 'request', kind: 'unseal', provider: 'github' },
    { ...SCOOP, uid: 0, tag: null }
  );
  assert.equal(root.state, 'pending');
  await page.evaluate(
    (id) =>
      window.harness.call('answer', { request: id, state: 'done', exit: 0, message: 'dropped' }),
    root.id
  );
  const dropped = await sealed(
    page,
    { op: 'status', id: root.id },
    { ...SCOOP, uid: 0, tag: null }
  );
  assert.deepEqual([dropped.state, dropped.exit, dropped.message], ['done', 0, 'dropped']);
  assert.equal((await page.evaluate(() => window.harness.twin(true, false, {}))).op, 'welcome');
  const stale = await sealed(page, { op: 'request', kind: 'unseal', provider: 'github' }, CONE);
  assert.equal(stale.exit, 2);
  const bad = await sealed(page, { op: 'request', kind: 'jerk', jop: 'drop' }, CONE);
  assert.equal(bad.error.code, 'EINVAL');
});
