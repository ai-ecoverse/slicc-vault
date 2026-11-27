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

test('the meta key holds at most 8 timestamps and nothing else; malformed meta is EBUSY', async (t) => {
  await sealSeven(embedder, t);
  const page = await openPilot(chrome, served, t);
  await mount(page);
  const frame = await frameOf(cdp, served);
  const now = Date.now();
  await seedBudget(frame, pilot, Array(6).fill(now));
  await runCheck(page, frame, `canary-${SECRET}`, 1);
  const stamps = await budget(frame, pilot);
  assert.equal(stamps.length, 8);
  assert.ok(stamps.every((at) => typeof at === 'number' && Number.isFinite(at)));
  assert.equal(JSON.stringify(stamps).includes(SECRET), false);
  assert.equal(JSON.stringify(stamps).includes('canary'), false);
  assert.equal(JSON.stringify(stamps).includes('hit'), false);
  await seedBudget(frame, pilot, 'not-an-array');
  await new Promise((resolve) => setTimeout(resolve, 10000));
  const bad = await runCheck(page, frame, SECRET, 2);
  assert.equal(bad.error.code, 'EBUSY');
  assert.equal(await budget(frame, pilot), 'not-an-array');
  await seedBudget(frame, pilot, [now, Number.NaN]);
  const nan = await runCheck(page, frame, SECRET, 3);
  assert.equal(nan.error.code, 'EBUSY');
  assert.deepEqual(await budget(frame, pilot), [now, Number.NaN]);
});
