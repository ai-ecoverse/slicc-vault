import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  budget,
  frameOf,
  mount,
  openPilot,
  runCheck,
  SECRET,
  scrubSetup,
  sealSeven,
  seedBudget,
} from './scrub-harness.mjs';

const { served, chrome, embedder, cdp, pilot } = await scrubSetup();

test('the fifth check in a rolling hour is EBUSY, and the count survives a reload', async (t) => {
  await sealSeven(embedder, t);
  const page = await openPilot(chrome, served, t);
  await mount(page);
  const frame = await frameOf(cdp, served);
  const now = Date.now();
  await seedBudget(frame, pilot, [now, now, now, now, now, now]);
  assert.equal((await runCheck(page, frame, SECRET, 1)).scrubVersion, 1);
  assert.equal((await budget(frame, pilot)).length, 8);
  await new Promise((resolve) => setTimeout(resolve, 10000));
  const fifth = await page.evaluate(() =>
    window.harness.call(window.harness.frames[0], { id: 2, op: 'check', text: 'x' })
  );
  assert.equal(fifth.error.code, 'EBUSY');
  const page2 = await openPilot(chrome, served, t);
  await mount(page2);
  const frame2 = await frameOf(cdp, served);
  assert.equal((await budget(frame2, pilot)).length, 8);
  const again = await page2.evaluate(() =>
    window.harness.call(window.harness.frames[0], { id: 3, op: 'check', text: 'x' })
  );
  assert.equal(again.error.code, 'EBUSY');
});
