import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { browser } from './browser.mjs';
import { setup } from './setup.mjs';

const { chrome, embedder } = await setup();
const cdp = await browser(chrome);
after(() => cdp.close());

async function connected(t) {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.connect());
  return page;
}

async function typed(page, request, text) {
  await page.evaluate((id) => window.harness.value(id), request);
  const frame = await cdp.target(/\/value\.html$/);
  await frame.until(() => document.querySelector('input') !== null);
  await frame.evaluate((value) => {
    const input = document.querySelector('input');
    input.value = value;
    input.dispatchEvent(new Event('input'));
  }, text);
  await frame.until(() => {
    const save = [...document.querySelectorAll('button')].find((b) => b.textContent === 'Save');
    return save && !save.disabled;
  });
  await frame.evaluate(() => document.querySelector('button').click());
  return frame;
}

test('a page enter seals the value typed in the frame, with its kind and binding', async (t) => {
  const page = await connected(t);
  const opened = await page.evaluate(() =>
    window.harness.call('enter', {
      name: 'TYPED_KEY',
      kind: 'model',
      provider: 'anthropic',
      settings: { REGION: 'eu' },
    })
  );
  assert.match(opened.request, /^req_[0-9a-f]{24}$/);
  const status = await page.evaluate(() => window.harness.call('status'));
  assert.deepEqual(status.status.waiting, []);
  await typed(page, opened.request, 'sk-ant-typed-in-frame-01');
  const done = await page.until(() => window.harness.valueEvents.find((e) => e.event === 'done'));
  const { list } = await page.evaluate(() => window.harness.call('list'));
  const record = list.secrets.find((s) => s.name === 'TYPED_KEY');
  assert.deepEqual(
    [record.kind, record.source, record.provider, record.settings],
    ['model', 'settings', 'anthropic', { REGION: 'eu' }]
  );
  assert.deepEqual(done, {
    type: 'slicc-vault',
    v: 1,
    event: 'done',
    request: opened.request,
    state: 'sealed',
    name: 'TYPED_KEY',
    placeholder: record.placeholder,
    record: 'inert',
  });
  const seen = await page.evaluate(() => JSON.stringify(window.harness.seen));
  assert.ok(!seen.includes('sk-ant-typed-in-frame-01'));
});

test('enter over a live record needs replace, and keeps its placeholder', async (t) => {
  const page = await connected(t);
  const first = await page.evaluate(() =>
    window.harness.call('put', { name: 'KEEP_ME', value: 'first-page-value' })
  );
  const refused = await page.evaluate(() => window.harness.call('enter', { name: 'KEEP_ME' }));
  assert.equal(refused.error.code, 'EEXIST');
  const opened = await page.evaluate(() =>
    window.harness.call('enter', { name: 'KEEP_ME', replace: true })
  );
  const frame = await typed(page, opened.request, 'second-frame-value');
  await page.until(() => window.harness.valueEvents.some((e) => e.event === 'done'));
  assert.equal(await frame.evaluate(() => document.querySelector('input')), null);
  const looked = await page.evaluate(() =>
    window.harness.sealed({ v: 1, op: 'placeholder', name: 'KEEP_ME' })
  );
  assert.equal(looked.placeholder, first.placeholder);
});

test('a cancelled enter ends the frame', async (t) => {
  const page = await connected(t);
  const opened = await page.evaluate(() => window.harness.call('enter', { name: 'NEVER_TYPED' }));
  await page.evaluate((id) => window.harness.value(id), opened.request);
  const frame = await cdp.target(/\/value\.html$/);
  await frame.until(() => document.querySelector('input') !== null);
  const cancelled = await page.evaluate(
    (request) => window.harness.call('cancel', { request }),
    opened.request
  );
  assert.equal(cancelled.state, 'cancelled');
  const gone = await page.until(() => window.harness.valueEvents.find((e) => e.event === 'gone'));
  assert.deepEqual(gone, {
    type: 'slicc-vault',
    v: 1,
    event: 'gone',
    request: opened.request,
    state: 'cancelled',
  });
});
