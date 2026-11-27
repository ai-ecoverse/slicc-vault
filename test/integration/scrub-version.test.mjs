import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  budget,
  corruptRecord,
  frameOf,
  mount,
  openPilot,
  recheck,
  runCheck,
  SECRET,
  scrubSetup,
  sealSeven,
  seedBudget,
} from './scrub-harness.mjs';

const { served, chrome, embedder, cdp, pilot, seven } = await scrubSetup();

test('a seal between check and recheck changes scrubVersion; compile failure is EINVAL with two slots', async (t) => {
  const { page: sevenPage } = await sealSeven(embedder, t);
  const page = await openPilot(chrome, served, t);
  await mount(page);
  const frame = await frameOf(cdp, served);
  const first = await runCheck(page, frame, SECRET, 1);
  assert.equal(first.scrubVersion, 1);
  await sevenPage.evaluate(() =>
    window.harness.sealed({ v: 1, op: 'seal', name: 'LATER', value: 'later-secret-value-02' })
  );
  const moved = await recheck(page, 2);
  assert.equal(moved.error.code, 'EBUSY');
  const page2 = await openPilot(chrome, served, t);
  await mount(page2, { tag: 'cap' });
  const frame2 = await frameOf(cdp, served, 'cap');
  await seedBudget(frame2, pilot, []);
  await corruptRecord(frame2, seven);
  assert.ok((await budget(frame2, pilot)) === null || (await budget(frame2, pilot)).length === 0);
  const failed = await runCheck(page2, frame2, SECRET, 3);
  assert.equal(failed.error.code, 'EINVAL');
  assert.equal((await budget(frame2, pilot)).length, 2);
});
