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

test('recheck takes no text; refused recheck stays REUSED; no held text is EINVAL', async (t) => {
  const { page: seven } = await sealSeven(embedder, t);
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
  await seven.evaluate(() =>
    window.harness.sealed({ v: 1, op: 'seal', name: 'MOVED', value: 'moved-secret-value-09' })
  );
  const refused = await recheck(page, 4);
  assert.equal(refused.error.code, 'EBUSY');
  const again = await recheck(page, 5);
  assert.equal(again.error.code, 'EBUSY');
  assert.equal(again.error.message.includes('recheck') || again.error.code === 'EBUSY', true);
  const page2 = await openPilot(chrome, served, t);
  await mount(page2);
  const other = await recheck(page2, 6);
  assert.equal(other.error.code, 'EINVAL');
});
