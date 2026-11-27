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

const { served, chrome, embedder, cdp } = await scrubSetup();

test('the output holds no placeholder, record name, count or length hint', async (t) => {
  const { sealed } = await sealSeven(embedder, t);
  const page = await openPilot(chrome, served, t);
  await mount(page);
  const frame = await frameOf(cdp, served);
  const encoded = btoa(SECRET);
  const text = `raw:${SECRET} b64:${encoded} json:${JSON.stringify({ SECRET })} named:[redacted:SCRUB_TOKEN] ph:${sealed.placeholder}`;
  const reply = await runCheck(page, frame, text, 1);
  assert.deepEqual(Object.keys(reply).sort(), ['id', 'scrubVersion', 'text']);
  assert.equal(reply.text.includes(SECRET), false);
  assert.equal(reply.text.includes(sealed.placeholder), false);
  assert.equal(reply.text.includes('SCRUB_TOKEN'), false);
  assert.equal('replaced' in reply, false);
  assert.equal(reply.text.includes('[redacted:'), false);
  assert.match(reply.text, new RegExp(MARKER));
});
