import assert from 'node:assert/strict';
import { test } from 'node:test';
import { frameOf, mount, openPilot, runCheck, SECRET, scrubSetup } from './scrub-harness.mjs';

const { served, chrome, cdp } = await scrubSetup();

test('an empty mapped namespace gives ENOENT, never a clean result', async (t) => {
  const page = await openPilot(chrome, served, t);
  await mount(page);
  const frame = await frameOf(cdp, served);
  const reply = await runCheck(page, frame, SECRET, 1);
  assert.deepEqual(reply.error.code, 'ENOENT');
  assert.equal(reply.text, undefined);
});
