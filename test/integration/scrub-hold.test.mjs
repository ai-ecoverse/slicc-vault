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

test('a recheck after the 10-minute hold is EINVAL, and the hold is within the prepaid hour', async (t) => {
  await sealSeven(embedder, t);
  const page = await openPilot(chrome, served, t);
  await mount(page);
  const frame = await frameOf(cdp, served);
  await runCheck(page, frame, SECRET, 1);
  const stamps = await budget(frame, pilot);
  assert.equal(stamps.length, 2);
  await frame.evaluate(() => {
    const real = Performance.prototype.now;
    Performance.prototype.now = function now() {
      return real.call(this) + 11 * 60 * 1000;
    };
  });
  const expired = await recheck(page, 2);
  assert.equal(expired.error.code, 'EINVAL');
  assert.deepEqual(await budget(frame, pilot), stamps);
  assert.equal(10 * 60 * 1000 < 60 * 60 * 1000, true);
});
