import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  frameOf,
  metaKeys,
  mount,
  openPilot,
  runCheck,
  SECRET,
  scrubCounter,
  scrubSetup,
  sealSeven,
} from './scrub-harness.mjs';

const { served, chrome, embedder, cdp, pilot, seven } = await scrubSetup();

test('the input canary never appears in IndexedDB, on the bus or in page-port traffic', async (t) => {
  const { page: sevenPage } = await sealSeven(embedder, t);
  const before = await sevenPage.evaluate(async () => {
    const events = window.harness.events.length;
    const version = (await window.harness.call('placeholders')).scrub.version;
    return { events, version };
  });
  const canary = `residue-canary-${SECRET}-${Date.now()}`;
  const page = await openPilot(chrome, served, t);
  await mount(page);
  const frame = await frameOf(cdp, served);
  await runCheck(page, frame, canary, 1);
  const keys = await metaKeys(frame);
  assert.ok(keys.includes(`scrub-budget:${pilot}`));
  assert.equal(
    keys.some((key) => typeof key === 'string' && key.includes('canary')),
    false
  );
  const stored = await frame.evaluate(async () => {
    const db = await new Promise((resolve, reject) => {
      const opening = indexedDB.open('slicc-vault', 1);
      opening.onsuccess = () => resolve(opening.result);
      opening.onerror = () => reject(opening.error);
    });
    const dump = {};
    for (const name of [...db.objectStoreNames]) {
      dump[name] = await new Promise((resolve, reject) => {
        const req = db.transaction([name], 'readonly').objectStore(name).getAll();
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
    }
    db.close();
    return JSON.stringify(dump);
  });
  assert.equal(stored.includes(canary), false);
  assert.equal(stored.includes(SECRET), false);
  const local = await frame.evaluate(() => ({
    localStorage: [...Array(localStorage.length)].map((_, i) => localStorage.key(i)),
    caches: typeof caches,
  }));
  assert.deepEqual(local.localStorage, []);
  const after = await sevenPage.evaluate(async () => {
    const events = window.harness.events.map((e) => e.event);
    const version = (await window.harness.call('placeholders')).scrub.version;
    return { events, version };
  });
  assert.equal(after.version, before.version);
  assert.equal(after.events.includes('changed'), false);
  assert.equal(await scrubCounter(frame, seven), before.version);
  assert.equal(
    await page.evaluate(
      (text) => window.harness.bus.some((row) => JSON.stringify(row).includes(text)),
      canary
    ),
    false
  );
});
