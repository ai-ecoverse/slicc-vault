import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  frameOf,
  MARKER,
  mount,
  openPilot,
  runCheck,
  SECRET,
  scrubSetup,
  sealSeven,
} from './scrub-harness.mjs';

const { served, chrome, embedder, cdp, pilot, seven } = await scrubSetup();

test('the namespace comes from the mapping, never the caller origin', async (t) => {
  await sealSeven(embedder, t);
  served.state.config = {
    version: '0.0.0-test',
    embedders: served.state.embedders,
    scrub: { [pilot]: seven },
  };
  const page = await openPilot(chrome, served, t);
  await mount(page);
  const frame = await frameOf(cdp, served);
  const reply = await runCheck(page, frame, SECRET, 1);
  assert.equal(reply.text, MARKER);
  served.state.config = {
    version: '0.0.0-test',
    embedders: served.state.embedders,
    scrub: { [pilot]: pilot },
  };
  const page2 = await openPilot(chrome, served, t);
  await mount(page2);
  const frame2 = await frameOf(cdp, served);
  const empty = await runCheck(page2, frame2, SECRET, 2);
  assert.equal(empty.error.code, 'ENOENT');
});
