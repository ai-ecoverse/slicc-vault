import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  armed,
  frameOf,
  mount,
  openPilot,
  postCheck,
  SECRET,
  scrubSetup,
  sealSeven,
} from './scrub-harness.mjs';

const { served, chrome, embedder, cdp } = await scrubSetup();

test('the button reads only Check N bytes for stored values and shows no excerpt text', async (t) => {
  await sealSeven(embedder, t);
  const page = await openPilot(chrome, served, t);
  await mount(page);
  const frame = await frameOf(cdp, served);
  const text = `unique-canary-${SECRET}-excerpt`;
  const bytes = new TextEncoder().encode(text).length;
  await postCheck(page, text, 1);
  const shown = await armed(frame);
  assert.equal(shown.label, `Check ${bytes} bytes for stored values`);
  const html = await frame.evaluate(() => document.documentElement.outerHTML);
  assert.equal(html.includes(text), false);
  assert.equal(html.includes(SECRET), false);
  assert.equal(html.includes('unique-canary'), false);
  assert.equal(await frame.evaluate(() => document.title.includes(SECRET)), false);
});
