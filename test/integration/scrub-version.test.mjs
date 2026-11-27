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

test('a seal between check and recheck changes scrubVersion; locked is EACCES', async (t) => {
  const { page: seven } = await sealSeven(embedder, t);
  const page = await openPilot(chrome, served, t);
  await mount(page);
  const frame = await frameOf(cdp, served);
  const first = await runCheck(page, frame, SECRET, 1);
  assert.equal(first.scrubVersion, 1);
  await seven.evaluate(() =>
    window.harness.sealed({ v: 1, op: 'seal', name: 'LATER', value: 'later-secret-value-02' })
  );
  const moved = await recheck(page, 2);
  assert.equal(moved.error.code, 'EBUSY');
  await seven.evaluate(() => window.harness.call('lock'));
  const page2 = await openPilot(chrome, served, t);
  await mount(page2);
  const frame2 = await frameOf(cdp, served);
  const locked = await runCheck(page2, frame2, SECRET, 3);
  assert.equal(locked.error.code, 'EACCES');
});
