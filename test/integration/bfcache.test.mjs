import assert from 'node:assert/strict';
import { test } from 'node:test';
import { setup } from './setup.mjs';

const { served, chrome } = await setup();

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
  await page.evaluate(() => {
    history.back();
  });
  await page
    .until((url) => location.href === url && document.readyState === 'complete', `${served.vault}/`)
    .catch(() => null);
  const navigated = await new Promise((resolve) => {
    const deadline = Date.now() + 10000;
    const check = () => {
      const found = seen.find(({ method }) => method === 'Page.frameNavigated');
      if (found) return resolve(found);
      if (Date.now() > deadline) return resolve(null);
      setTimeout(check, 25);
    };
    check();
  });
  const missed = seen.filter(({ method }) => method === 'Page.backForwardCacheNotUsed');
  const reasons = missed.flatMap(({ params }) => params.notRestoredExplanations);
  assert.ok(
    navigated?.params.type !== 'BackForwardCacheRestore' &&
      navigated?.params.frame.url === `${served.vault}/` &&
      missed.length === 1 &&
      reasons.some(({ reason }) => reason === 'UnloadHandlerExistsInMainFrame'),
    'BFCache exclusion lost: only the guard protects seven now'
  );
});
