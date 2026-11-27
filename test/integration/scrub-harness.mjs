import { createHash } from 'node:crypto';
import { after } from 'node:test';
import { browser, click } from './browser.mjs';
import { setup } from './setup.mjs';

export const SECRET = 'scrub-secret-value-01';
export const NAME = 'SCRUB_TOKEN';
export const MARKER = '[redacted]';

export async function scrubSetup() {
  const ctx = await setup();
  const cdp = await browser(ctx.chrome);
  after(() => cdp.close());
  const pilot = ctx.served.origin('pilot');
  const seven = ctx.served.origin('seven');
  ctx.served.state.config = {
    version: '0.0.0-test',
    embedders: ctx.served.state.embedders,
    scrub: { [pilot]: seven },
  };
  return { ...ctx, cdp, pilot, seven };
}

export async function sealSeven(embedder, t, value = SECRET, name = NAME) {
  const page = await embedder(t, 'seven');
  await page.evaluate(() => window.harness.connect());
  const sealed = await page.evaluate(
    (n, v) => window.harness.sealed({ v: 1, op: 'seal', name: n, value: v }),
    name,
    value
  );
  return { page, sealed };
}

export async function openPilot(chrome, served, t) {
  const page = await chrome.page(t);
  await page.goto(`${served.origin('pilot')}/pilot.html?vault=${encodeURIComponent(served.vault)}`);
  await page.until(() => document.title === 'ready');
  return page;
}

export async function mount(page, options = {}) {
  return page.evaluate((opts) => window.harness.mount(opts), options);
}

export function scrubPattern(served, tag) {
  const base = served.vault.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  if (tag === undefined) return new RegExp(`^${base}/scrub\\.html`);
  return new RegExp(`^${base}/scrub\\.html\\?f=${encodeURIComponent(tag)}(?:$|&)`);
}

export async function frameOf(cdp, served, tag) {
  return cdp.target(scrubPattern(served, tag));
}

export async function armed(frame) {
  return frame.until(
    () =>
      document.querySelector('button') &&
      !document.querySelector('button').disabled && {
        label: document.querySelector('button').textContent,
      }
  );
}

export async function press(frame) {
  await armed(frame);
  await click(frame, 'button');
}

export async function postCheck(page, text, id = 1, index = 0) {
  await page.evaluate(
    (i, t, callId) => {
      window.harness.post(window.harness.frames[i], { id: callId, op: 'check', text: t });
    },
    index,
    text,
    id
  );
}

export async function awaitReply(page, id, index = 0) {
  return page.evaluate(
    (i, callId) => window.harness.awaitId(window.harness.frames[i], callId),
    index,
    id
  );
}

export async function runCheck(page, frame, text, id = 1, index = 0) {
  await postCheck(page, text, id, index);
  const reply = awaitReply(page, id, index);
  await press(frame);
  return reply;
}

export async function recheck(page, id = 2, index = 0) {
  return page.evaluate(
    (i, callId) => window.harness.call(window.harness.frames[i], { op: 'recheck', id: callId }),
    index,
    id
  );
}

export function digest(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

export async function budget(frame, origin) {
  return frame.evaluate(async (key) => {
    const db = await new Promise((resolve, reject) => {
      const opening = indexedDB.open('slicc-vault', 1);
      opening.onsuccess = () => resolve(opening.result);
      opening.onerror = () => reject(opening.error);
      opening.onupgradeneeded = () => opening.transaction.abort();
    });
    const value = await new Promise((resolve, reject) => {
      const req = db.transaction(['meta'], 'readonly').objectStore('meta').get(key);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    db.close();
    return value ?? null;
  }, `scrub-budget:${origin}`);
}

export async function seedBudget(frame, origin, stamps) {
  return frame.evaluate(
    async (key, list) => {
      const db = await new Promise((resolve, reject) => {
        const opening = indexedDB.open('slicc-vault', 1);
        opening.onsuccess = () => resolve(opening.result);
        opening.onerror = () => reject(opening.error);
        opening.onupgradeneeded = () => opening.transaction.abort();
      });
      await new Promise((resolve, reject) => {
        const tx = db.transaction(['meta'], 'readwrite');
        tx.objectStore('meta').put(list, key);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
      db.close();
    },
    `scrub-budget:${origin}`,
    stamps
  );
}

export async function corruptRecord(frame, ns) {
  return frame.evaluate(async (namespace) => {
    const db = await new Promise((resolve, reject) => {
      const opening = indexedDB.open('slicc-vault', 1);
      opening.onsuccess = () => resolve(opening.result);
      opening.onerror = () => reject(opening.error);
    });
    const held = await new Promise((resolve, reject) => {
      const req = db
        .transaction(['records'], 'readonly')
        .objectStore('records')
        .index('ns')
        .getAll(namespace);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    const record = held[0];
    if (!record) throw new Error('no record to corrupt');
    record.sealed = {
      alg: record.sealed?.alg ?? 'AES-GCM',
      data: new Uint8Array(48),
      iv: new Uint8Array(12),
    };
    await new Promise((resolve, reject) => {
      const tx = db.transaction(['records'], 'readwrite');
      tx.objectStore('records').put(record);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
    db.close();
  }, ns);
}

export async function metaKeys(frame) {
  return frame.evaluate(async () => {
    const db = await new Promise((resolve, reject) => {
      const opening = indexedDB.open('slicc-vault', 1);
      opening.onsuccess = () => resolve(opening.result);
      opening.onerror = () => reject(opening.error);
    });
    const keys = await new Promise((resolve, reject) => {
      const req = db.transaction(['meta'], 'readonly').objectStore('meta').getAllKeys();
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    db.close();
    return keys;
  });
}

export async function scrubCounter(frame, ns) {
  return frame.evaluate(async (namespace) => {
    const db = await new Promise((resolve, reject) => {
      const opening = indexedDB.open('slicc-vault', 1);
      opening.onsuccess = () => resolve(opening.result);
      opening.onerror = () => reject(opening.error);
    });
    const value = await new Promise((resolve, reject) => {
      const req = db
        .transaction(['meta'], 'readonly')
        .objectStore('meta')
        .get(`scrub:${namespace}`);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    db.close();
    return value ?? 0;
  }, ns);
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function pollWhile(ms, fn) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (!(await fn())) return false;
    await sleep(50);
  }
  return true;
}
