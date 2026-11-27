import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  frameOf,
  mount,
  openPilot,
  recheck,
  runCheck,
  SECRET,
  scrubSetup,
  sealSeven,
} from './scrub-harness.mjs';

const { served, chrome, embedder, cdp } = await scrubSetup();

test('recheck takes no text, stays on the same port and load, and is EINVAL with nothing held', async (t) => {
  await sealSeven(embedder, t);
  const page = await openPilot(chrome, served, t);
  await mount(page);
  const bare = await recheck(page, 1);
  assert.equal(bare.error.code, 'EINVAL');
  const frame = await frameOf(cdp, served);
  await runCheck(page, frame, SECRET, 2);
  const withText = await page.evaluate(() =>
    window.harness.call(window.harness.frames[0], {
      id: 3,
      op: 'recheck',
      text: 'no',
    })
  );
  assert.equal(withText.error.code, 'EINVAL');
  const ok = await recheck(page, 4);
  assert.equal(typeof ok.sha256, 'string');
  const page2 = await openPilot(chrome, served, t);
  await mount(page2);
  const other = await recheck(page2, 5);
  assert.equal(other.error.code, 'EINVAL');
});
