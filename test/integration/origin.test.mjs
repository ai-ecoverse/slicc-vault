import assert from 'node:assert/strict';
import { test } from 'node:test';
import { setup } from './setup.mjs';

const { served, embedder } = await setup();

const seal = (name, value) => window.harness.sealed({ v: 1, op: 'seal', name, value });

test('frame-ancestors keeps the vault out of an origin it does not serve', async (t) => {
  const page = await embedder(t, 'evil');
  assert.equal(await page.evaluate(() => window.harness.connect()), null);
});

test('the vault itself refuses an origin it does not serve, even when framed', async (t) => {
  served.state.frameAncestors = false;
  t.after(() => {
    served.state.frameAncestors = true;
  });
  const page = await embedder(t, 'evil');
  assert.equal(await page.evaluate(() => window.harness.connect()), null);
  await page.evaluate(() => window.harness.button({ intent: 'auto' }));
  await new Promise((resolve) => setTimeout(resolve, 1500));
  assert.deepEqual(await page.evaluate(() => window.harness.buttonEvents), []);
});

test('only the embedding window may say hello, and only in protocol 1', async (t) => {
  const page = await embedder(t);
  const answers = await page.evaluate(async () => {
    const iframe = await window.harness.frame('/', true);
    const ask = (message, from) =>
      new Promise((resolve) => {
        const channel = new MessageChannel();
        channel.port1.onmessage = (event) => resolve(event.data);
        setTimeout(() => resolve(null), 1500);
        from.postMessage(message, window.harness.vault, [channel.port2]);
      });
    const v2 = await ask({ type: 'slicc-vault', v: 2, op: 'hello' }, iframe.contentWindow);
    const wrongType = await ask({ type: 'other', v: 1, op: 'hello' }, iframe.contentWindow);
    const v1 = await ask({ type: 'slicc-vault', v: 1, op: 'hello' }, iframe.contentWindow);
    return { v2, wrongType, v1 };
  });
  assert.equal(answers.v2.op, 'refused');
  assert.equal(answers.v2.error.code, 'EINVAL');
  assert.equal(answers.wrongType, null);
  assert.equal(answers.v1.op, 'welcome');
});

test('records are namespaced by the embedding origin', async (t) => {
  const seven = await embedder(t, 'seven');
  await seven.evaluate(() => window.harness.connect());
  const ours = await seven.evaluate(seal, 'SHARED_NAME', 'seven-value');
  const preview = await embedder(t, 'preview', await seven.tab());
  const welcome = await preview.evaluate(() => window.harness.connect());
  assert.match(welcome.status.origin, /^http:\/\/preview\.sliccy\.localhost:/);
  const missing = await preview.evaluate(() =>
    window.harness.sealed({ v: 1, op: 'placeholder', name: 'SHARED_NAME' })
  );
  assert.equal(missing.error.code, 'ENOENT');
  const listed = await preview.evaluate(() => window.harness.sealed({ v: 1, op: 'list' }));
  assert.deepEqual(listed.secrets, []);
  const theirs = await preview.evaluate(seal, 'SHARED_NAME', 'preview-value');
  assert.notEqual(theirs.placeholder, ours.placeholder);
  const still = await seven.evaluate(() =>
    window.harness.sealed({ v: 1, op: 'placeholder', name: 'SHARED_NAME' })
  );
  assert.equal(still.placeholder, ours.placeholder);
  const placeholders = await preview.evaluate(
    async () => (await window.harness.call('placeholders')).placeholders
  );
  assert.deepEqual(placeholders, [theirs.placeholder]);
});
