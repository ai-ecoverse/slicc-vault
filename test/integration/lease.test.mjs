import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { after, test } from 'node:test';
import { browser, openPopup, press, typeInto } from './browser.mjs';
import { setup } from './setup.mjs';

const { chrome, embedder, served } = await setup();
const cdp = await browser(chrome);
after(() => cdp.close());

const ID = 'lease-0b7e5c1d-fake';
const NODE = 'node-4f1a9e22-fake';
const OTHER_NODE = 'node-77aa31c0-fake';
const VALUE = 'fake-jerk-lease-0901';
const PASSPHRASE = 'fake lease backup passphrase';
const PASS = 'correct horse battery';

async function connected(t, tab = null) {
  const page = await embedder(t, 'seven', tab);
  await page.evaluate(() => window.harness.connect());
  return page;
}

const call = (page, op, fields = {}) =>
  page.evaluate((o, f) => window.harness.call(o, f), op, fields);

const lease = (fields) => ({
  name: 'GH_TOKEN',
  value: VALUE,
  source: 'jerk:github@air',
  expiresAt: Date.now() + 3600000,
  refresh: 'jerk-seal',
  ...fields,
});

const shown = async (page) => {
  const { placeholders, scrub } = await call(page, 'placeholders');
  return { placeholders, scrub };
};

const forget = (page, fields = {}) =>
  call(page, 'forgetLease', { provider: 'github', lease: ID, node: NODE, ...fields });

async function revocations(page, age) {
  await page.goto(`${served.vault}/config.json`);
  const ns = served.origin('seven');
  return page.evaluate(
    (key, by) =>
      new Promise((resolve, reject) => {
        const open = indexedDB.open('slicc-vault', 1);
        open.onerror = () => reject(open.error);
        open.onsuccess = () => {
          const tx = open.result.transaction(['meta'], 'readwrite');
          const meta = tx.objectStore('meta');
          const got = meta.get(key);
          let list = [];
          got.onsuccess = () => {
            list = (got.result ?? []).map((e) => ({ ...e, at: e.at - by }));
            meta.put(list, key);
          };
          tx.oncomplete = () => resolve(list);
          tx.onerror = () => reject(tx.error);
        };
      }),
    `revoked:${ns}`,
    age
  );
}

async function raw(page) {
  await page.goto(`${served.vault}/config.json`);
  return page.evaluate(
    () =>
      new Promise((resolve, reject) => {
        const open = indexedDB.open('slicc-vault', 1);
        open.onerror = () => reject(open.error);
        open.onsuccess = () => {
          const got = open.result
            .transaction(['records'], 'readonly')
            .objectStore('records')
            .getAll();
          got.onsuccess = () =>
            resolve(
              got.result.map((r) => ({
                ...r,
                sealed: {
                  iv: btoa(String.fromCharCode(...new Uint8Array(r.sealed.iv))),
                  data: btoa(String.fromCharCode(...new Uint8Array(r.sealed.data))),
                },
              }))
            );
          got.onerror = () => reject(got.error);
        };
      })
  );
}

const unbase64url = (text) => Buffer.from(text.replaceAll('-', '+').replaceAll('_', '/'), 'base64');

async function opened(bundle) {
  const parsed = JSON.parse(Buffer.from(bundle, 'base64').toString());
  const base = await webcrypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(PASSPHRASE),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  const key = await webcrypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt: unbase64url(parsed.kdf.salt),
      iterations: parsed.kdf.iterations,
    },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  const plain = await webcrypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: unbase64url(parsed.cipher.iv),
      additionalData: new TextEncoder().encode(parsed.format),
    },
    key,
    unbase64url(parsed.data)
  );
  return new TextDecoder().decode(plain);
}

test('forgetLease from the lease node purges the record, its ciphertext and its placeholder', async (t) => {
  let page = await connected(t);
  const sealed = await call(page, 'seal', lease({ lease: { id: ID, node: NODE } }));
  const before = await call(page, 'placeholders');
  assert.ok(before.placeholders.includes(sealed.placeholder));
  const stored = (await raw(page)).find((r) => r.name === 'GH_TOKEN');
  assert.deepEqual(stored.lease, { id: ID, node: NODE });
  page = await connected(t, page);
  const { id: _id, ...forgotten } = await forget(page);
  assert.deepEqual(forgotten, { v: 1, op: 'forgetLease', forgotten: true });
  const now = await call(page, 'placeholders');
  assert.ok(!now.placeholders.includes(sealed.placeholder));
  assert.ok(now.scrub.version > before.scrub.version);
  assert.equal((await call(page, 'list')).list.secrets.length, 0);
  assert.equal((await call(page, 'restore', { name: 'GH_TOKEN' })).error.code, 'ENOENT');
  const audit = (await call(page, 'audit')).audit;
  assert.deepEqual(
    audit.filter((e) => e.type === 'remove').map(({ name, uid, tag }) => ({ name, uid, tag })),
    [{ name: 'GH_TOKEN', uid: null, tag: null }]
  );
  assert.ok(!JSON.stringify(audit).includes(ID) && !JSON.stringify(audit).includes(NODE));
  const events = await page.evaluate(() => window.harness.events);
  assert.ok(events.some((e) => e.event === 'changed' && e.parts.includes('secrets')));
  const left = await raw(page);
  assert.equal(
    left.find((r) => r.name === 'GH_TOKEN'),
    undefined
  );
  assert.ok(!JSON.stringify(left).includes(stored.sealed.data));
  page = await connected(t, page);
  assert.equal((await forget(page)).forgotten, false);
});

test('NEGATIVE forgetLease with another node, id or provider, or for an unbound lease, forgets nothing', async (t) => {
  const page = await connected(t);
  await call(page, 'seal', lease({ lease: { id: ID, node: NODE } }));
  await call(
    page,
    'seal',
    lease({ name: 'NPM_TOKEN', value: 'fake-jerk-npm-0902', source: 'jerk:npm@air' })
  );
  const before = await shown(page);
  const audited = (await call(page, 'audit')).audit.length;
  const tries = [
    { node: OTHER_NODE },
    { lease: `${ID}x` },
    { lease: ID.slice(0, -1) },
    { provider: 'npm' },
    { provider: 'git' },
    { provider: 'github@air' },
    { lease: NODE, node: ID },
  ];
  const replies = [];
  for (const fields of tries) replies.push(await forget(page, fields));
  assert.deepEqual(
    replies.map(({ id: _id, ...reply }) => reply),
    tries.map(() => ({ v: 1, op: 'forgetLease', forgotten: false }))
  );
  assert.deepEqual(await shown(page), before);
  assert.equal((await call(page, 'audit')).audit.length, audited);
  const malformed = await forget(page, { node: 7 });
  assert.equal(malformed.error.code, 'EINVAL');
  assert.equal((await forget(page)).forgotten, true);
});

test('NEGATIVE forgetLease never touches oauth, settings, process or import records of the name', async (t) => {
  const page = await connected(t);
  await call(page, 'seal', {
    name: 'GH_TOKEN',
    value: 'fake-oauth-token-0904',
    source: 'oauth:github',
  });
  await call(page, 'seal', {
    name: 'GH_TOKEN',
    value: 'fake-oauth-model-0905',
    source: 'oauth:github',
    kind: 'model',
    provider: 'github-copilot',
  });
  await call(page, 'put', { name: 'GITHUB', value: 'fake-settings-0906' });
  await call(page, 'seal', { name: 'GH_PROC', value: 'fake-process-0907', source: 'process' });
  await call(page, 'seal', { name: 'GH_IMP', value: 'fake-import-0908', source: 'import:six' });
  const before = await shown(page);
  for (const fields of [{}, { lease: 'GH_TOKEN' }, { lease: '', node: '' }]) {
    assert.equal((await forget(page, fields)).forgotten, false);
  }
  assert.deepEqual(await shown(page), before);
  assert.equal((await call(page, 'list')).list.secrets.length, 5);
});

test('a lease refresh re-seal replaces the binding, and one without lease clears it', async (t) => {
  const page = await connected(t);
  const first = await call(page, 'seal', lease({ lease: { id: ID, node: NODE } }));
  const second = await call(
    page,
    'seal',
    lease({ value: 'fake-jerk-lease-0910', lease: { id: 'lease-2', node: OTHER_NODE } })
  );
  assert.equal(second.placeholder, first.placeholder);
  assert.equal((await forget(page)).forgotten, false);
  await call(page, 'seal', lease({ value: 'fake-jerk-lease-0911' }));
  assert.equal((await forget(page, { lease: 'lease-2', node: OTHER_NODE })).forgotten, false);
  await call(
    page,
    'seal',
    lease({ value: 'fake-jerk-lease-0912', lease: { id: 'lease-3', node: NODE } })
  );
  assert.equal((await forget(page, { lease: 'lease-3' })).forgotten, true);
  assert.ok(!(await call(page, 'placeholders')).placeholders.includes(first.placeholder));
});

test('NEGATIVE seal refuses a lease that holds a value, sits on a non-jerk record or is malformed', async (t) => {
  const page = await connected(t);
  await call(page, 'put', { name: 'STORED', value: 'fake-stored-0913' });
  const bad = [
    lease({ lease: { id: 'x-fake-stored-0913-x', node: NODE } }),
    lease({ lease: { id: ID, node: 'fake-stored-0913' } }),
    lease({ lease: { id: `own-${VALUE}`, node: NODE } }),
    lease({ source: 'oauth:github', refresh: undefined, lease: { id: ID, node: NODE } }),
    { name: 'SET', value: 'fake-set-0914', source: 'settings', lease: { id: ID, node: NODE } },
    lease({ kind: 'grant', refresh: undefined, lease: { id: ID, node: NODE } }),
    lease({ lease: { id: '', node: NODE } }),
    lease({ lease: { id: 'x'.repeat(129), node: NODE } }),
    lease({ lease: { id: 'a\nb', node: NODE } }),
    lease({ lease: { id: ID } }),
    lease({ lease: { id: ID, node: NODE, extra: 'x' } }),
    lease({ lease: [ID, NODE] }),
    lease({ lease: ID }),
  ];
  for (const fields of bad) {
    const reply = await call(page, 'seal', fields);
    assert.equal(reply.error?.code, 'EINVAL', JSON.stringify(fields.lease));
    assert.ok(!reply.error.message.includes('fake-') && !reply.error.message.includes(ID));
  }
  assert.deepEqual(
    (await call(page, 'list')).list.secrets.map((r) => r.name),
    ['STORED']
  );
  const longest = await call(page, 'seal', lease({ lease: { id: 'x'.repeat(128), node: 'é' } }));
  assert.equal(longest.state, 'inert');
});

test('no reply, event, audit entry or export carries the lease', async (t) => {
  const page = await connected(t);
  await call(page, 'seal', lease({ lease: { id: ID, node: NODE } }));
  await page.evaluate(() => window.harness.agent());
  await page.evaluate(() => window.harness.ask('records'));
  await call(page, 'list');
  await call(page, 'audit');
  await call(page, 'status');
  await page.evaluate(() => window.harness.sealed({ v: 1, op: 'list' }));
  await page.evaluate(() => window.harness.sealed({ v: 1, op: 'placeholder', name: 'GH_TOKEN' }));
  const exported = await page.evaluate(async (p) => {
    const reply = await window.harness.call('export', { passphrase: p });
    return btoa(String.fromCharCode(...reply.bundle));
  }, PASSPHRASE);
  const bundle = await opened(exported);
  assert.ok(bundle.includes('GH_TOKEN'));
  assert.ok(!bundle.includes(ID) && !bundle.includes(NODE) && !bundle.includes('"lease"'));
  const seen = (await page.evaluate(() => window.harness.seen)).map((s) => s.data);
  assert.ok(seen.some((data) => data.includes('GH_TOKEN')));
  assert.ok(!seen.some((d) => d.includes(ID) || d.includes(NODE) || d.includes('"lease"')));
  assert.equal((await forget(page)).forgotten, true);
});

test('a seal without lease is unchanged and is never forgotten', async (t) => {
  const page = await connected(t);
  const reply = await call(page, 'seal', lease({}));
  assert.deepEqual(Object.keys(reply).sort(), ['id', 'name', 'op', 'placeholder', 'state', 'v']);
  const stored = (await raw(page)).find((r) => r.name === 'GH_TOKEN');
  assert.equal('lease' in stored, false);
  const again = await connected(t, page);
  assert.equal((await forget(again)).forgotten, false);
  assert.ok((await call(again, 'placeholders')).placeholders.includes(reply.placeholder));
});

test('forgetLease purges while the vault is locked', async (t) => {
  const page = await connected(t);
  const sealed = await call(page, 'seal', lease({ lease: { id: ID, node: NODE } }));
  const manage = await openPopup(cdp, page, { kind: 'protect' }, 'Vault lock');
  await press(manage, 'Protect with a passphrase');
  await typeInto(manage, '#passphrase', PASS);
  await typeInto(manage, '#confirm', PASS);
  await press(manage, 'Protect');
  await manage.until(() => document.body.textContent.includes('Protected with a passphrase.'));
  await press(manage, 'Lock now');
  await page.until(async () => (await window.harness.call('status')).status.locked === true);
  assert.equal((await forget(page, { node: OTHER_NODE })).forgotten, false);
  assert.equal((await forget(page)).forgotten, true);
  assert.ok(!(await call(page, 'placeholders')).placeholders.includes(sealed.placeholder));
  assert.equal((await call(page, 'status')).status.locked, true);
});

test('forgetLease purges a removed lease too', async (t) => {
  const page = await connected(t);
  await call(page, 'seal', lease({ lease: { id: ID, node: NODE } }));
  await call(page, 'remove', { name: 'GH_TOKEN' });
  assert.equal((await forget(page)).forgotten, true);
  assert.equal((await call(page, 'restore', { name: 'GH_TOKEN' })).error.code, 'ENOENT');
  assert.equal((await call(page, 'list')).list.secrets.length, 0);
});

test('NEGATIVE a seal of a revoked lease is refused, also when it lands before or after the purge', async (t) => {
  const page = await connected(t);
  await call(page, 'seal', lease({ lease: { id: ID, node: NODE } }));
  assert.equal((await forget(page)).forgotten, true);
  const late = await call(page, 'seal', lease({ lease: { id: ID, node: NODE } }));
  assert.deepEqual(late.error, { code: 'EACCES', message: 'this lease was revoked' });
  assert.equal((await forget(page, { lease: 'early' })).forgotten, false);
  const early = await call(page, 'seal', lease({ lease: { id: 'early', node: NODE } }));
  assert.equal(early.error.code, 'EACCES');
  assert.equal((await call(page, 'list')).list.secrets.length, 0);
  const fresh = await call(page, 'seal', lease({ lease: { id: `${ID}-2`, node: NODE } }));
  assert.equal(fresh.state, 'inert');
  const other = await call(
    page,
    'seal',
    lease({
      name: 'NPM',
      source: 'jerk:npm@air',
      value: 'fake-jerk-npm-0920',
      lease: { id: ID, node: NODE },
    })
  );
  assert.equal(other.state, 'inert');
  const plain = await call(page, 'seal', lease({ name: 'PLAIN', value: 'fake-jerk-plain-0921' }));
  assert.equal(plain.state, 'inert');
  const list = await revocations(page, 0);
  assert.equal(list.length, 2);
  assert.ok(!JSON.stringify(list).includes(ID) && !JSON.stringify(list).includes(NODE));
});

test('a revocation lapses after 7 days', async (t) => {
  let page = await connected(t);
  await forget(page);
  await revocations(page, 7 * 24 * 60 * 60 * 1000 - 60000);
  page = await connected(t, page);
  assert.equal(
    (await call(page, 'seal', lease({ lease: { id: ID, node: NODE } }))).error.code,
    'EACCES'
  );
  await revocations(page, 60000);
  page = await connected(t, page);
  const sealed = await call(page, 'seal', lease({ lease: { id: ID, node: NODE } }));
  assert.equal(sealed.state, 'inert');
});

test('at most 256 revocations are kept, the oldest dropped', async (t) => {
  const page = await connected(t);
  await page.evaluate(async (node) => {
    for (let i = 0; i <= 256; i++) {
      await window.harness.call('forgetLease', { provider: 'github', lease: `l-${i}`, node });
    }
  }, NODE);
  const oldest = await call(page, 'seal', lease({ lease: { id: 'l-0', node: NODE } }));
  assert.equal(oldest.state, 'inert');
  const kept = await call(
    page,
    'seal',
    lease({ name: 'NEXT', value: 'fake-jerk-next-0922', lease: { id: 'l-1', node: NODE } })
  );
  assert.equal(kept.error.code, 'EACCES');
  assert.equal((await revocations(page, 0)).length, 256);
});
