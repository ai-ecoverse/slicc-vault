import assert from 'node:assert/strict';
import { test } from 'node:test';
import { setup } from './setup.mjs';

const { chrome, embedder, served } = await setup();

const VALUE = 'crest-value-kept-across-launches';
const KEY = 'crest-store';

function fakeCrest() {
  if (self === top || localStorage.getItem('crest-offered') !== '1') return;
  const read = () => JSON.parse(localStorage.getItem('crest-store') ?? '{}');
  const write = (entries) => localStorage.setItem('crest-store', JSON.stringify(entries));
  const answers = {
    get: ({ key }) => read()[key] ?? null,
    list: () => Object.keys(read()).sort(),
    put: ({ key, value }) => {
      write({ ...read(), [key]: value });
      return true;
    },
    delete: ({ key }) => {
      const { [key]: _, ...kept } = read();
      write(kept);
      return true;
    },
  };
  window.webkit = {
    messageHandlers: { crestVaultStore: { postMessage: async (call) => answers[call.op](call) } },
  };
}

served.state.prelude = `(${fakeCrest})();`;

async function launch(t, crest) {
  const page = await chrome.page(t);
  await page.goto(`${served.vault}/config.json`);
  if (crest) await page.evaluate(() => localStorage.setItem('crest-offered', '1'));
  await embedder(t, 'seven', page);
  await page.evaluate(() => window.harness.connect());
  return page;
}

async function atVault(page, work, ...args) {
  await page.goto(`${served.vault}/config.json`);
  return page.evaluate(work, ...args);
}

const quit = () =>
  new Promise((resolve, reject) => {
    const deleting = indexedDB.deleteDatabase('slicc-vault');
    deleting.onsuccess = resolve;
    deleting.onerror = () => reject(deleting.error);
    deleting.onblocked = resolve;
  });

const store = (key) => JSON.parse(localStorage.getItem(key) ?? '{}');

test('a sealed value and its namespace come back after Crest quits', async (t) => {
  const page = await launch(t, true);
  const put = await page.evaluate(
    (value) => window.harness.call('put', { name: 'KEPT_TOKEN', value }),
    VALUE
  );
  assert.match(put.placeholder, /^fnox_proxy_/);
  const entries = await atVault(page, store, KEY);
  assert.ok(Object.keys(entries).some((name) => name.startsWith('dek:')));
  assert.ok(Object.keys(entries).some((name) => name.includes('KEPT_TOKEN')));
  assert.equal(JSON.stringify(entries).includes(VALUE), false);
  await page.evaluate(quit);
  await embedder(t, 'seven', page);
  await page.evaluate(() => window.harness.connect());
  const looked = await page.evaluate(() =>
    window.harness.sealed({ v: 1, op: 'placeholder', name: 'KEPT_TOKEN' })
  );
  assert.equal(looked.placeholder, put.placeholder);
  const status = await page.evaluate(async () => (await window.harness.call('status')).status);
  assert.deepEqual(status.scrub.version, 1);
  assert.equal(status.lock, 'auto');
});

test('NEGATIVE the data key and the entries never reach the embedding page', async (t) => {
  const page = await launch(t, true);
  await page.evaluate((value) => window.harness.call('put', { name: 'QUIET_TOKEN', value }), VALUE);
  const seen = await page.evaluate(() => JSON.stringify(window.harness.seen));
  assert.equal(await page.evaluate(() => typeof window.webkit), 'undefined');
  const entries = await atVault(page, store, KEY);
  const [name] = Object.keys(entries).filter((entry) => entry.startsWith('dek:'));
  assert.equal(seen.includes(entries[name]), false);
  assert.equal(seen.includes(name.slice(4)), false);
});

test('NEGATIVE a browser without the handler keeps everything in IndexedDB', async (t) => {
  const page = await launch(t, false);
  await page.evaluate((value) => window.harness.call('put', { name: 'PLAIN_TOKEN', value }), VALUE);
  assert.deepEqual(await atVault(page, store, KEY), {});
  await page.evaluate(quit);
  await embedder(t, 'seven', page);
  await page.evaluate(() => window.harness.connect());
  const looked = await page.evaluate(() =>
    window.harness.sealed({ v: 1, op: 'placeholder', name: 'PLAIN_TOKEN' })
  );
  assert.equal(looked.placeholder, undefined);
});
