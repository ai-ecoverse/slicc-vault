import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  digest,
  frameOf,
  MARKER,
  mount,
  openPilot,
  recheck,
  runCheck,
  SECRET,
  scrubSetup,
  sealSeven,
} from './scrub-harness.mjs';

const { served, chrome, embedder, cdp } = await scrubSetup();

test('a sealed value becomes [redacted] after a trusted click, and recheck digests the same bytes', async (t) => {
  await sealSeven(embedder, t);
  const page = await openPilot(chrome, served, t);
  const welcome = await mount(page);
  assert.deepEqual(welcome.welcome, {
    v: 1,
    op: 'welcome',
    doc: 'scrub',
    release: '0.0.0-test',
  });
  const frame = await frameOf(cdp, served);
  const text = `before ${SECRET} after`;
  const reply = await runCheck(page, frame, text, 1);
  assert.deepEqual(reply, { id: 1, text: `before ${MARKER} after`, scrubVersion: 1 });
  const hashed = await recheck(page, 2);
  assert.deepEqual(hashed, {
    id: 2,
    sha256: digest(reply.text),
    scrubVersion: reply.scrubVersion,
  });
  const again = await recheck(page, 3);
  assert.equal(again.error.code, 'EBUSY');
});
