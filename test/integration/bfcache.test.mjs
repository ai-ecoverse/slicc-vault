import assert from 'node:assert/strict';
import { test } from 'node:test';
import { setup } from './setup.mjs';

const { served, chrome, embedder } = await setup();

async function back(page) {
  const { currentIndex, entries } = await page.send('Page.getNavigationHistory');
  await page.send('Page.navigateToHistoryEntry', { entryId: entries[currentIndex - 1].id });
}

test('history.back() to the vault document never restores it from the back/forward cache', async (t) => {
  const page = await chrome.page(t);
  await page.send('Page.enable');
  await page.goto(`${served.vault}/`);
  const { frameTree } = await page.send('Page.getFrameTree');
  const frame = frameTree.frame.id;
  await page.goto(`${served.origin('seven')}/`);
  const seen = [];
  const stop = chrome.cdp.on((message) => {
    const { method, params } = message;
    if (method === 'Page.backForwardCacheNotUsed' && params.frameId === frame) seen.push(message);
    if (method === 'Page.frameNavigated' && params.frame.id === frame && !params.frame.parentId) {
      seen.push(message);
    }
  });
  t.after(stop);
  await back(page);
  await page.until(
    (url) => location.href === url && document.readyState === 'complete',
    `${served.vault}/`
  );
  await new Promise((resolve) => setTimeout(resolve, 1000));
  const navigations = seen.filter(({ method }) => method === 'Page.frameNavigated');
  const missed = seen.filter(({ method }) => method === 'Page.backForwardCacheNotUsed');
  const entry = await page.evaluate(() => performance.getEntriesByType('navigation')[0]?.type);
  assert.ok(
    navigations.length === 1 &&
      navigations[0].params.type !== 'BackForwardCacheRestore' &&
      navigations[0].params.frame.url === `${served.vault}/` &&
      missed.length === 1 &&
      entry === 'back_forward',
    `BFCache exclusion lost: only the guard protects seven now ${JSON.stringify({
      navigations: navigations.map(({ params }) => params.type),
      reasons: missed.flatMap(({ params }) =>
        params.notRestoredExplanations.map(({ reason }) => reason)
      ),
      entry,
    })}`
  );
});

test('a vault frame is never shown from the back/forward cache with its embedder: it reloads', async (t) => {
  const page = await embedder(t);
  await page.send('Page.enable');
  await page.evaluate(() => window.harness.connect());
  const host = new URL(served.vault).host.split(':')[0];
  const loads = () => served.state.requests.filter((entry) => entry === `${host}/`).length;
  await page.goto(`${served.origin('bios')}/`);
  const before = loads();
  const seen = [];
  const stop = chrome.cdp.on(({ method, params }) => {
    if (method === 'Page.frameNavigated' && !params.frame.parentId) seen.push(params.type);
  });
  t.after(stop);
  await back(page);
  const deadline = Date.now() + 20000;
  const until = async (done) => {
    while (!done() && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
  };
  await until(() => seen.length > 0);
  const restored = seen[0] === 'BackForwardCacheRestore';
  if (restored) await until(() => loads() > before);
  assert.equal(seen.length, 1);
  assert.equal(loads(), restored ? before + 1 : before);
});
