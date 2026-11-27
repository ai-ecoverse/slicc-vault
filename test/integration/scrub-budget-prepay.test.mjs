import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  budget,
  frameOf,
  mount,
  openPilot,
  recheck,
  runCheck,
  SECRET,
  scrubSetup,
  sealSeven,
} from './scrub-harness.mjs';

const { served, chrome, embedder, cdp, pilot } = await scrubSetup();

test('a check appends exactly two timestamps; a recheck and a refused check append none', async (t) => {
  await sealSeven(embedder, t);
  const page = await openPilot(chrome, served, t);
  await mount(page);
  const frame = await frameOf(cdp, served);
  assert.equal(await budget(frame, pilot), null);
  const refused = await page.evaluate(() =>
    window.harness.call(window.harness.frames[0], {
      id: 1,
      op: 'check',
      text: 'x'.repeat(2049),
    })
  );
  assert.equal(refused.error.code, 'EINVAL');
  assert.equal(await budget(frame, pilot), null);
  await runCheck(page, frame, SECRET, 2);
  const stamps = await budget(frame, pilot);
  assert.equal(stamps.length, 2);
  assert.equal(stamps[0], stamps[1]);
  await recheck(page, 3);
  assert.deepEqual(await budget(frame, pilot), stamps);
});
