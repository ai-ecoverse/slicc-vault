import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { browser, openPopup, press } from './browser.mjs';
import { setup } from './setup.mjs';

const { chrome, embedder, served } = await setup();
const cdp = await browser(chrome);
after(() => cdp.close());

const VALUE = 'npm_TYPEDinSETTINGS0123456789';

test('a value request is answered with put from the page', async (t) => {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.connect());
  const pending = await page.evaluate(() =>
    window.harness.sealed({
      v: 1,
      op: 'request',
      kind: 'value',
      name: 'NPM_TOKEN',
      prompt: 'publish @acme/pkg',
    })
  );
  assert.equal(pending.state, 'pending');
  const status = await page.evaluate(async () => (await window.harness.call('status')).status);
  assert.deepEqual(
    status.waiting.map((entry) => [entry.id, entry.kind, entry.name, entry.prompt, entry.uid]),
    [[pending.id, 'value', 'NPM_TOKEN', 'publish @acme/pkg', 1000]]
  );
  assert.deepEqual(status.scrub, { needed: false, version: 0, ready: true });
  assert.deepEqual([status.exportedAt, status.backupReminder], [null, null]);
  const short = await page.evaluate(() =>
    window.harness.call('put', { name: 'NPM_TOKEN', value: 'short' })
  );
  assert.equal(short.error.code, 'EINVAL');
  assert.match(short.error.message, /shorter than 8 bytes/);
  const wrong = await page.evaluate(
    (id, value) => window.harness.call('put', { name: 'OTHER', value, request: id }),
    pending.id,
    VALUE
  );
  assert.equal(wrong.error.code, 'EINVAL');
  const before = await page.evaluate(() => window.harness.seen.length);
  const put = await page.evaluate(
    (id, value) => window.harness.call('put', { name: 'NPM_TOKEN', value, request: id }),
    pending.id,
    VALUE
  );
  assert.match(put.placeholder, /^fnox_proxy_[0-9a-f]{24}$/);
  assert.equal(put.state, 'inert');
  const order = await page.evaluate(
    (from) => window.harness.seen.slice(from).map((s) => JSON.parse(s.data)),
    before
  );
  const pushed = order.findIndex((m) => m.event === 'placeholders');
  const replied = order.findIndex((m) => m.op === 'put');
  assert.ok(pushed >= 0 && pushed < replied, 'the scrub pair is pushed before the put reply');
  assert.deepEqual(order[pushed].scrub, { needed: true, version: 1, ready: true });
  const done = await page.evaluate(
    (id) => window.harness.sealed({ v: 1, op: 'status', id }),
    pending.id
  );
  assert.deepEqual(done, { v: 1, state: 'done', placeholder: put.placeholder, record: 'inert' });
  const reminded = await page.evaluate(async () => (await window.harness.call('status')).status);
  assert.deepEqual([reminded.exportedAt, reminded.backupReminder], [null, 'due']);
  const dismissed = await page.evaluate(() => window.harness.call('dismissBackupReminder'));
  assert.equal(dismissed.backupReminder, 'dismissed');
  await page.until(() =>
    window.harness.events.some(
      (e) => e.event === 'status' && e.status.backupReminder === 'dismissed'
    )
  );
  const rotated = await page.evaluate(
    (value) => window.harness.call('put', { name: 'NPM_TOKEN', value: `${value}x` }),
    VALUE
  );
  assert.equal(rotated.placeholder, put.placeholder);
  const seen = await page.evaluate(() => JSON.stringify(window.harness.seen));
  assert.ok(!seen.includes(VALUE));
});

test('a value request is cancelled from the page', async (t) => {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.connect());
  const pending = await page.evaluate(() =>
    window.harness.sealed({ v: 1, op: 'request', kind: 'value', name: 'NOPE_TOKEN' })
  );
  const cancelled = await page.evaluate(
    (id) => window.harness.call('cancel', { request: id }),
    pending.id
  );
  assert.equal(cancelled.state, 'cancelled');
  const status = await page.evaluate(
    (id) => window.harness.sealed({ v: 1, op: 'status', id }),
    pending.id
  );
  assert.equal(status.state, 'cancelled');
  const stale = await page.evaluate(
    (id) =>
      window.harness.call('put', { name: 'NOPE_TOKEN', value: 'value-after-cancel', request: id }),
    pending.id
  );
  assert.equal(stale.error.code, 'EINVAL');
  const none = await page.evaluate(() =>
    window.harness.sealed({ v: 1, op: 'placeholder', name: 'NOPE_TOKEN' })
  );
  assert.equal(none.error.code, 'ENOENT');
  const missing = await page.evaluate(() => window.harness.call('cancel', { request: 'req_nope' }));
  assert.equal(missing.error.code, 'ENOENT');
});

test('the page seals leases and tokens, and removes and restores secrets', async (t) => {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.connect());
  const lease = await page.evaluate(() =>
    window.harness.call('seal', {
      name: 'GH_TOKEN',
      value: 'gho_leasefromjerk01',
      source: 'jerk:github@lars-air',
      expiresAt: Date.now() + 3600000,
    })
  );
  assert.match(lease.placeholder, /^fnox_proxy_/);
  const grant = await page.evaluate(() =>
    window.harness.call('seal', {
      name: 'ADOBE_REFRESH',
      value: 'refresh-token-value',
      source: 'oauth:adobe',
      kind: 'grant',
    })
  );
  assert.equal(grant.state, 'inert');
  const bad = await page.evaluate(() =>
    window.harness.call('seal', { name: 'X_TOKEN', value: 'value-long-enough', source: 'nowhere' })
  );
  assert.equal(bad.error.code, 'EINVAL');
  const agentOverwrite = await page.evaluate(() =>
    window.harness.sealed({ v: 1, op: 'seal', name: 'GH_TOKEN', value: 'agent-overwrite-1' })
  );
  assert.equal(agentOverwrite.error.code, 'EEXIST');
  const removed = await page.evaluate(() => window.harness.call('remove', { name: 'GH_TOKEN' }));
  assert.deepEqual([removed.placeholder, removed.state], [lease.placeholder, 'removed']);
  await page.until(() =>
    window.harness.events.some((e) => e.event === 'changed' && e.parts.includes('secrets'))
  );
  const listed = await page.evaluate(() => window.harness.sealed({ v: 1, op: 'list' }));
  assert.deepEqual(listed.secrets, []);
  const restored = await page.evaluate(() => window.harness.call('restore', { name: 'GH_TOKEN' }));
  assert.equal(restored.state, 'inert');
  const list = await page.evaluate(async () => (await window.harness.call('list')).list);
  assert.deepEqual(
    list.secrets.map((s) => [s.name, s.kind, s.source, s.sourceDevice]),
    [
      ['ADOBE_REFRESH', 'grant', 'oauth:adobe', null],
      ['GH_TOKEN', 'secret', 'jerk:github@lars-air', 'lars-air'],
    ]
  );
  assert.deepEqual(list.refused, []);
  const noKind = await page.evaluate(() =>
    window.harness.call('remove', { name: 'ADOBE_REFRESH' })
  );
  assert.equal(noKind.error.code, 'ENOENT');
  const grantGone = await page.evaluate(() =>
    window.harness.call('remove', { name: 'ADOBE_REFRESH', kind: 'grant' })
  );
  assert.equal(grantGone.state, 'removed');
  assert.equal(list.secrets[1].exits, undefined);
  const audit = await page.evaluate(async () => window.harness.call('audit', { limit: 2 }));
  assert.deepEqual(
    audit.audit.map((entry) => entry.type),
    ['remove', 'restore']
  );
  assert.equal(audit.more, true);
  const older = await page.evaluate(
    async (before) => window.harness.call('audit', { before }),
    audit.next
  );
  assert.deepEqual(
    older.audit.map((entry) => entry.type),
    ['remove', 'seal', 'seal']
  );
  const scrub = await page.evaluate(async () => (await window.harness.call('placeholders')).scrub);
  assert.deepEqual(scrub, { needed: true, version: 5, ready: true });
});

test('a popup without a hand-off from a vault button does nothing', async (t) => {
  const page = await embedder(t);
  await page.goto(`${served.vault}/popup.html#00000000000000000000000000000000`);
  await page.until(() => document.querySelector('main h1')?.textContent === 'Nothing to do here');
  await page.goto(`${served.vault}/popup.html`);
  await page.until(() => document.querySelector('main h1')?.textContent === 'Nothing to do here');
});

test('the agent port gets only agent ops', async (t) => {
  const page = await embedder(t);
  const replies = await page.evaluate(async () => {
    const iframe = await window.harness.frame('/', true);
    const channel = new MessageChannel();
    const got = [];
    channel.port1.onmessage = (event) => got.push(event.data);
    iframe.contentWindow.postMessage(
      { type: 'slicc-vault', v: 1, op: 'hello', role: 'agent' },
      window.harness.vault,
      [channel.port2]
    );
    await new Promise((resolve) => setTimeout(resolve, 300));
    for (const [id, op] of [
      [1, 'put'],
      [2, 'list'],
      [3, 'redact'],
    ])
      channel.port1.postMessage({ v: 1, id, op, name: 'A', value: 'value-value' });
    await new Promise((resolve) => setTimeout(resolve, 300));
    const odd = new MessageChannel();
    odd.port1.onmessage = (event) => got.push(event.data);
    iframe.contentWindow.postMessage(
      { type: 'slicc-vault', v: 1, op: 'hello', role: 'root' },
      window.harness.vault,
      [odd.port2]
    );
    await new Promise((resolve) => setTimeout(resolve, 300));
    return got;
  });
  assert.equal(replies[0].op, 'welcome');
  assert.equal(replies[0].role, 'agent');
  assert.deepEqual(
    replies.slice(1, 4).map((r) => [r.id, r.error.code]),
    [
      [1, 'EACCES'],
      [2, 'EACCES'],
      [3, 'ENOTSUP'],
    ]
  );
  assert.equal(replies[4].op, 'refused');
});

test('the vault lock button opens the passkey popup', async (t) => {
  const page = await embedder(t);
  const popup = await openPopup(cdp, page, { kind: 'protect' }, 'Vault lock');
  assert.equal(
    await popup.evaluate(() => document.querySelector('main h1').textContent),
    'Vault lock'
  );
  await press(popup, 'Done');
  const event = await page.until(() =>
    window.harness.buttonEvents.find((e) => e.event === 'popup' && e.state === 'done')
  );
  assert.deepEqual(event.intent, { kind: 'protect' });
});
