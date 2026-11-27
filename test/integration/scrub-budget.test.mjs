import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  budget,
  corruptRecord,
  frameOf,
  mount,
  openPilot,
  runCheck,
  SECRET,
  scrubSetup,
  sealSeven,
  seedBudget,
} from './scrub-harness.mjs';

const { served, chrome, embedder, cdp, pilot, seven } = await scrubSetup();

test('the fifth clicked check in a rolling hour is EBUSY, and a failed compile uses two slots', async (t) => {
  await sealSeven(embedder, t);
  const page = await openPilot(chrome, served, t);
  await mount(page);
  const frame = await frameOf(cdp, served);
  const now = Date.now();
  await seedBudget(frame, pilot, [now, now, now, now, now, now]);
  assert.equal((await runCheck(page, frame, SECRET, 1)).scrubVersion, 1);
  assert.equal((await budget(frame, pilot)).length, 8);
  await new Promise((resolve) => setTimeout(resolve, 10000));
  const fifth = await runCheck(page, frame, SECRET, 2);
  assert.equal(fifth.error.code, 'EBUSY');
  const page2 = await openPilot(chrome, served, t);
  await mount(page2);
  const frame2 = await frameOf(cdp, served);
  assert.equal((await budget(frame2, pilot)).length, 8);
  const again = await runCheck(page2, frame2, SECRET, 3);
  assert.equal(again.error.code, 'EBUSY');
  await seedBudget(frame2, pilot, []);
  await corruptRecord(frame2, seven);
  const failed = await runCheck(page2, frame2, SECRET, 4);
  assert.equal(failed.error.code, 'EINVAL');
  assert.equal((await budget(frame2, pilot)).length, 2);
});
