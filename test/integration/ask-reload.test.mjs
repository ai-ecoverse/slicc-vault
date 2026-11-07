import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { browser } from './browser.mjs';
import { setup } from './setup.mjs';

const { chrome, embedder } = await setup();
const cdp = await browser(chrome);
after(() => cdp.close());

const as = (uid) => ({ pid: 80, ppid: 1, uid, gid: uid, tag: 'cone', users: 'enforce' });
const requester = {
  kind: 'user',
  name: 'lars',
  exe: '/usr/bin/fnox',
  argv: ['fnox', 'set', 'X'],
  cwd: '/',
  tty: null,
  stdin: 'tty',
};
const ask = (name, fields = {}) => ({ v: 1, op: 'ask', name, requester, ...fields });

async function held(page, req, stamp) {
  const id = await page.evaluate((r, s) => window.harness.hold(r, s), req, stamp);
  const asked = await page.until(
    (call) => window.harness.events.find((e) => e.event === 'asked' && e.call === call),
    id
  );
  return { id, request: asked.request };
}

async function shown(page, request) {
  await page.evaluate((id) => window.harness.value(id), request);
  return cdp.target(/\/value\.html$/);
}

async function dropCore(page, frame) {
  await page.evaluate(() => document.querySelector('iframe[hidden]').remove());
  await frame.until(async () =>
    (await navigator.locks.query()).held.every((l) => !l.name.startsWith('slicc-vault/ask/'))
  );
}

async function armed(frame, label) {
  await frame.until(
    (text) =>
      [...document.querySelectorAll('button')].some((b) => b.textContent === text && !b.disabled),
    label
  );
}

async function reloaded(t, fields, setupRecord) {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.connect());
  if (setupRecord)
    await page.evaluate((r, s) => window.harness.sealed(r, s), setupRecord, as(3000));
  const { id, request } = await held(page, ask('RELOADED', fields), as(3000));
  const frame = await shown(page, request);
  const mode = fields.reveal ? 'Allow' : 'Save';
  await frame.until(
    (label) => [...document.querySelectorAll('button')].some((b) => b.textContent === label),
    mode
  );
  await dropCore(page, frame);
  await page.evaluate(() => window.harness.connect());
  const gone = await page.until(() => window.harness.valueEvents.find((e) => e.event === 'gone'));
  assert.deepEqual(gone, { type: 'slicc-vault', v: 1, event: 'gone', request, state: 'withdrawn' });
  const cancelled = await page.until(
    (r) => window.harness.events.find((e) => e.event === 'cancelled' && e.request === r),
    request
  );
  assert.equal(cancelled.state, 'withdrawn');
  const waiting = (await page.evaluate(() => window.harness.call('status'))).status.waiting;
  assert.deepEqual(waiting, []);
  assert.equal(await frame.evaluate(() => document.querySelector('button')), null);
  const next = await held(page, ask('AFTER_RELOAD'), as(3000));
  assert.match(next.request, /^req_/);
  await page.evaluate((r) => window.harness.call('cancel', { request: r }), next.request);
  assert.equal(await page.evaluate((call) => window.harness.replies[call], id), undefined);
  return page;
}

test('a core frame reload withdraws a pending enter ask and frees its uid', async (t) => {
  await reloaded(t, {});
});

test('a core frame reload withdraws a pending reveal ask before Allow', async (t) => {
  const page = await reloaded(
    t,
    { reveal: true },
    { v: 1, op: 'seal', name: 'RELOADED', value: 'never-revealed-06' }
  );
  const seen = await page.evaluate(() => JSON.stringify(window.harness.seen));
  assert.ok(!seen.includes('never-revealed-06'));
});

test('Save after the core frame went away is refused and seals nothing', async (t) => {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.connect());
  const { id, request } = await held(page, ask('LATE_SAVE'), as(3001));
  const frame = await shown(page, request);
  await frame.until(() => document.querySelector('input') !== null);
  await frame.evaluate(() => {
    const input = document.querySelector('input');
    input.value = 'typed-too-late-07';
    input.dispatchEvent(new Event('input'));
  });
  await armed(frame, 'Save');
  await dropCore(page, frame);
  await frame.evaluate(() => document.querySelector('button').click());
  const gone = await page.until(() => window.harness.valueEvents.find((e) => e.event === 'gone'));
  assert.equal(gone.state, 'withdrawn');
  assert.equal(
    await page.evaluate(() => window.harness.valueEvents.some((e) => e.event === 'done')),
    false
  );
  await page.evaluate(() => window.harness.connect());
  const looked = await page.evaluate(
    (s) => window.harness.sealed({ v: 1, op: 'placeholder', name: 'LATE_SAVE' }, s),
    as(3001)
  );
  assert.equal(looked.error.code, 'ENOENT');
  const status = await page.evaluate(
    (s, r) => window.harness.sealed({ v: 1, op: 'status', id: r }, s),
    as(3001),
    request
  );
  assert.equal(status.state, 'withdrawn');
  assert.equal(await page.evaluate((call) => window.harness.replies[call], id), undefined);
  const seen = await page.evaluate(() => JSON.stringify(window.harness.seen));
  assert.ok(!seen.includes('typed-too-late-07'));
});
