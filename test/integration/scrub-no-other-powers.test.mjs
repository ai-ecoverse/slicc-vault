import assert from 'node:assert/strict';
import { test } from 'node:test';
import { scrubSetup } from './scrub-harness.mjs';

const { served, chrome, embedder } = await scrubSetup();

test('the pilot core-frame hello is ignored, and check is ENOTSUP on page and agent ports', async (t) => {
  const seven = await embedder(t, 'seven');
  await seven.evaluate(() => window.harness.connect());
  const pageHello = await seven.evaluate(() => window.harness.call('check', { text: 'no' }));
  assert.equal(pageHello.error.code, 'ENOTSUP');
  await seven.evaluate(() => window.harness.agent());
  const agent = await seven.evaluate(() => window.harness.ask('check', { text: 'no' }));
  assert.equal(agent.error.code, 'ENOTSUP');
  const page = await chrome.page(t);
  await page.goto(`${served.origin('pilot')}/?vault=${encodeURIComponent(served.vault)}`);
  await page.until(() => document.title === 'ready');
  const refused = await page.evaluate(() => window.harness.connect());
  assert.equal(refused, null);
});
