import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  awaitReply,
  budget,
  frameOf,
  mount,
  openPilot,
  postCheck,
  press,
  recheck,
  runCheck,
  SECRET,
  scrubSetup,
  sealSeven,
  seedBudget,
} from './scrub-harness.mjs';

const { served, chrome, embedder, cdp, pilot } = await scrubSetup();

test('exactly one check takes the last pair of free slots; one free slot is enough for neither', async (t) => {
  await sealSeven(embedder, t);
  const page = await openPilot(chrome, served, t);
  await page.evaluate(() => window.harness.mounts(2));
  const a = await frameOf(cdp, served, 'scrub-0');
  const b = await frameOf(cdp, served, 'scrub-1');
  const now = Date.now();
  await seedBudget(a, pilot, Array(6).fill(now));
  await postCheck(page, SECRET, 1, 0);
  await postCheck(page, SECRET, 2, 1);
  const ra = awaitReply(page, 1, 0);
  const rb = awaitReply(page, 2, 1);
  await Promise.all([press(a), press(b)]);
  const results = await Promise.all([ra, rb]);
  const ok = results.filter((row) => row.text);
  const busy = results.filter((row) => row.error?.code === 'EBUSY');
  assert.equal(ok.length, 1);
  assert.equal(busy.length, 1);
  assert.equal((await budget(a, pilot)).length, 8);
  const winner = results[0].text ? 0 : 1;
  await seedBudget(a, pilot, Array(8).fill(Date.now()));
  assert.equal(typeof (await recheck(page, 10, winner)).sha256, 'string');
  await seedBudget(a, pilot, Array(7).fill(Date.now()));
  const page2 = await openPilot(chrome, served, t);
  await page2.evaluate(() => window.harness.mounts(2));
  const c = await frameOf(cdp, served, 'scrub-0');
  const d = await frameOf(cdp, served, 'scrub-1');
  await postCheck(page2, SECRET, 3, 0);
  await postCheck(page2, SECRET, 4, 1);
  const rc = awaitReply(page2, 3, 0);
  const rd = awaitReply(page2, 4, 1);
  await Promise.all([press(c), press(d)]);
  const none = await Promise.all([rc, rd]);
  assert.ok(none.every((row) => row.error?.code === 'EBUSY'));
  const page3 = await openPilot(chrome, served, t);
  await mount(page3);
  const e = await frameOf(cdp, served);
  await seedBudget(e, pilot, Array(8).fill(Date.now()));
  const full = await runCheck(page3, e, SECRET, 5);
  assert.equal(full.error.code, 'EBUSY');
});
