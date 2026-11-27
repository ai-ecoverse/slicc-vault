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
} from './scrub-harness.mjs';

const { served, chrome, embedder, cdp, pilot } = await scrubSetup();

test('the meta key holds at most 8 timestamps and nothing else', async (t) => {
  await sealSeven(embedder, t);
  const page = await openPilot(chrome, served, t);
  await mount(page);
  const frame = await frameOf(cdp, served);
  await runCheck(page, frame, `canary-${SECRET}`, 1);
  const stamps = await budget(frame, pilot);
  assert.ok(Array.isArray(stamps));
  assert.equal(stamps.length, 2);
  assert.ok(stamps.every((at) => typeof at === 'number' && Number.isFinite(at)));
  assert.equal(JSON.stringify(stamps).includes(SECRET), false);
  assert.equal(JSON.stringify(stamps).includes('canary'), false);
  assert.equal(JSON.stringify(stamps).includes('hit'), false);
});
