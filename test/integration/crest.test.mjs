import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { browser, openPopup, press, typeInto } from './browser.mjs';
import { setup } from './setup.mjs';

const { chrome, embedder, served } = await setup();
const cdp = await browser(chrome);
after(() => cdp.close());

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
    messageHandlers: {
      crestVaultStore: {
        postMessage: async (call) => {
          if (localStorage.getItem('crest-fail-once') === call.op) {
            localStorage.removeItem('crest-fail-once');
            throw new Error('EIO');
          }
          return answers[call.op](call);
        },
      },
    },
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

const placeholder = (name) => window.harness.sealed({ v: 1, op: 'placeholder', name });
const failOnce = (op) => localStorage.setItem('crest-fail-once', op);

async function reopen(t, page) {
  await embedder(t, 'seven', page);
  await page.evaluate(() => window.harness.connect());
}

test('NEGATIVE records made after a failed read survive a later read that succeeds', async (t) => {
  const page = await launch(t, true);
  await page.evaluate((value) => window.harness.call('put', { name: 'DURABLE', value }), VALUE);
  const before = await atVault(page, store, KEY);
  await page.evaluate(quit);
  await page.evaluate(failOnce, 'list');
  await reopen(t, page);
  const made = await page.evaluate(
    (value) => window.harness.call('put', { name: 'MEANWHILE', value }),
    VALUE
  );
  assert.match(made.placeholder, /^fnox_proxy_/);
  await reopen(t, page);
  const kept = await page.evaluate(placeholder, 'MEANWHILE');
  assert.equal(kept.placeholder, made.placeholder);
  assert.deepEqual(await atVault(page, store, KEY), before);
});

test('records in IndexedDB outlive a data key Crest refused once', async (t) => {
  const page = await launch(t, false);
  const made = await page.evaluate(
    (value) => window.harness.call('put', { name: 'WAITING', value }),
    VALUE
  );
  await atVault(page, () => localStorage.setItem('crest-offered', '1'));
  await page.evaluate(failOnce, 'put');
  await reopen(t, page);
  assert.deepEqual(await atVault(page, store, KEY), {});
  await reopen(t, page);
  const entries = await atVault(page, store, KEY);
  assert.ok(Object.keys(entries).some((name) => name.startsWith('dek:')));
  assert.ok(Object.keys(entries).some((name) => name.includes('WAITING')));
  await page.evaluate(quit);
  await reopen(t, page);
  const kept = await page.evaluate(placeholder, 'WAITING');
  assert.equal(kept.placeholder, made.placeholder);
});

test('NEGATIVE a protected vault stays protected when the store holds another key', async (t) => {
  const page = await launch(t, false);
  const made = await page.evaluate(
    (value) => window.harness.call('put', { name: 'LOCKED', value }),
    VALUE
  );
  const manage = await openPopup(cdp, page, { kind: 'protect' }, 'Vault lock');
  await press(manage, 'Protect with a passphrase');
  await typeInto(manage, '#passphrase', 'correct horse battery');
  await typeInto(manage, '#confirm', 'correct horse battery');
  await press(manage, 'Protect');
  await manage.until(() => document.body.textContent.includes('Protected with a passphrase.'));
  await page.until(async () => (await window.harness.call('status')).status.lock === 'passphrase');
  const planted = { 'dek:other': 'A'.repeat(43) };
  await atVault(
    page,
    (key, entries) => {
      localStorage.setItem('crest-offered', '1');
      localStorage.setItem(key, JSON.stringify(entries));
    },
    KEY,
    planted
  );
  await reopen(t, page);
  const { status } = await page.evaluate(() => window.harness.call('status'));
  assert.equal(status.lock, 'passphrase');
  const kept = await page.evaluate(placeholder, 'LOCKED');
  assert.equal(kept.placeholder, made.placeholder);
  assert.deepEqual(await atVault(page, store, KEY), planted);
});

test('NEGATIVE settings made after a failed read survive a later read that succeeds', async (t) => {
  const page = await launch(t, true);
  await page.evaluate((value) => window.harness.call('put', { name: 'DURABLE', value }), VALUE);
  await atVault(page, quit);
  await page.evaluate(failOnce, 'list');
  await reopen(t, page);
  await page.evaluate(() => window.harness.call('dismissBackupReminder'));
  await reopen(t, page);
  const { status } = await page.evaluate(() => window.harness.call('status'));
  assert.equal(status.backupReminder, 'dismissed');
  const looked = await page.evaluate(placeholder, 'DURABLE');
  assert.match(looked.placeholder, /^fnox_proxy_/);
  const entries = await atVault(page, store, KEY);
  assert.ok(Object.keys(entries).some((name) => name.startsWith('meta:backup:')));
});
