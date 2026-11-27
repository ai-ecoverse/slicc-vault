import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  frameOf,
  mount,
  openPilot,
  postCheck,
  recheck,
  runCheck,
  SECRET,
  scrubSetup,
  sealSeven,
} from './scrub-harness.mjs';

const { served, chrome, embedder, cdp } = await scrubSetup();

test('a fourth check, a second recheck, and a check within 10 s are EBUSY; 2049 bytes is EINVAL', async (t) => {
  await sealSeven(embedder, t);
  const page = await openPilot(chrome, served, t);
  await mount(page);
  const frame = await frameOf(cdp, served);
  const oversized = await page.evaluate(() =>
    window.harness.call(window.harness.frames[0], {
      id: 99,
      op: 'check',
      text: 'x'.repeat(2049),
    })
  );
  assert.equal(oversized.error.code, 'EINVAL');
  assert.equal(await runCheck(page, frame, SECRET, 1).then((r) => r.scrubVersion), 1);
  const soon = await page.evaluate(() =>
    window.harness.call(window.harness.frames[0], { id: 2, op: 'check', text: 'y' })
  );
  assert.equal(soon.error.code, 'EBUSY');
  await new Promise((resolve) => setTimeout(resolve, 10000));
  assert.equal((await runCheck(page, frame, SECRET, 3)).id, 3);
  await new Promise((resolve) => setTimeout(resolve, 10000));
  assert.equal((await runCheck(page, frame, SECRET, 4)).id, 4);
  await new Promise((resolve) => setTimeout(resolve, 10000));
  const fourth = await page.evaluate(() =>
    window.harness.call(window.harness.frames[0], { id: 5, op: 'check', text: 'z' })
  );
  assert.equal(fourth.error.code, 'EBUSY');
  assert.equal(typeof (await recheck(page, 6)).sha256, 'string');
  const reused = await recheck(page, 7);
  assert.equal(reused.error.code, 'EBUSY');
  const page2 = await openPilot(chrome, served, t);
  await mount(page2);
  const frame2 = await frameOf(cdp, served);
  await postCheck(page2, SECRET, 8);
  await frame2.until(() => document.querySelector('button') !== null);
  assert.equal(await frame2.evaluate(() => document.querySelector('button') !== null), true);
});
