import assert from 'node:assert/strict';
import { test } from 'node:test';
import { browser } from './browser.mjs';
import { setup } from './setup.mjs';

const { served, chrome, embedder } = await setup({
  persistent: true,
  args: ['--auto-select-desktop-capture-source=SLICC vault'],
});
served.state.embedders = [served.origin('seven'), 'http://preview.sliccy.localhost:*'];

async function capture(tab, ms) {
  const { result, exceptionDetails } = await tab.send('Runtime.evaluate', {
    expression: `(async () => {
      const stream = await navigator.mediaDevices.getDisplayMedia({ video: true });
      const [track] = stream.getVideoTracks();
      const deadline = Date.now() + ${ms};
      while (!track.getCaptureHandle() && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      const handle = track.getCaptureHandle();
      track.stop();
      return handle;
    })()`,
    awaitPromise: true,
    returnByValue: true,
    userGesture: true,
  });
  if (exceptionDetails) throw new Error(exceptionDetails.exception?.description);
  return result.value;
}

test('a top-level vault tab shows its capture handle to its embedders only', async (t) => {
  const vault = await chrome.page(t);
  await vault.goto(`${served.vault}/`);
  const seen = {};
  for (const [name, ms] of [
    ['seven', 10000],
    ['evil', 500],
    ['preview', 500],
  ]) {
    const capturer = await vault.tab();
    await capturer.goto(`${served.origin(name)}/`);
    seen[name] = await capture(capturer, ms);
  }
  assert.deepEqual(seen, {
    seven: { handle: 'slicc-vault', origin: served.vault },
    evil: null,
    preview: null,
  });
});

test('framed vault documents throw nothing at start', async (t) => {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.connect());
  await page.evaluate(() => window.harness.button({ intent: { kind: 'protect' } }));
  await page.until(() => window.harness.buttonEvents.some((event) => event.event === 'label'));
  const cdp = await browser(chrome);
  t.after(() => cdp.close());
  const thrown = [];
  cdp.cdp.on(({ method, params }) => {
    if (method === 'Runtime.exceptionThrown')
      thrown.push(params.exceptionDetails.exception?.description);
  });
  await cdp.target(new RegExp(`^${served.vault}/$`));
  await cdp.target(new RegExp(`^${served.vault}/button\\.html$`));
  await new Promise((resolve) => setTimeout(resolve, 500));
  assert.deepEqual(thrown, []);
});
