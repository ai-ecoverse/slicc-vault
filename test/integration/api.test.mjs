import assert from 'node:assert/strict';
import { test } from 'node:test';
import { setup } from './setup.mjs';

const { embedder } = await setup();

test('an allowed embedder connects and gets the status', async (t) => {
  const page = await embedder(t);
  const welcome = await page.evaluate(() => window.harness.connect());
  assert.equal(welcome.op, 'welcome');
  assert.equal(welcome.status.locked, false);
  assert.equal(welcome.status.lock, 'auto');
  assert.match(welcome.status.origin, /^http:\/\/seven\.sliccy\.localhost:\d+$/);
  const sealedReply = await page.evaluate(() =>
    window.harness.sealed({ v: 1, op: 'seal', name: 'GITHUB_TOKEN', value: 'ghp_secretvalue123' })
  );
  assert.match(sealedReply.placeholder, /^fnox_proxy_[0-9a-f]{24}$/);
  assert.equal(sealedReply.state, 'inert');
});
