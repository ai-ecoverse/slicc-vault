import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  armed,
  awaitReply,
  frameOf,
  mount,
  openPilot,
  postCheck,
  press,
  SECRET,
  scrubSetup,
  sealSeven,
} from './scrub-harness.mjs';

const { served, chrome, embedder, cdp } = await scrubSetup();

test('no output without a trusted click; synthetic events and the arm delay do nothing', async (t) => {
  await sealSeven(embedder, t);
  const page = await openPilot(chrome, served, t);
  await mount(page);
  const frame = await frameOf(cdp, served);
  await postCheck(page, SECRET, 1);
  await frame.until(() => document.querySelector('button')?.disabled === true);
  await frame.evaluate(() => document.querySelector('button').click());
  await frame.evaluate(() =>
    document.querySelector('button').dispatchEvent(new MouseEvent('click', { bubbles: true }))
  );
  await page.evaluate(() => {
    const iframe = window.harness.frames[0].iframe;
    iframe.dispatchEvent(new MouseEvent('click', { bubbles: true }));
  });
  await new Promise((resolve) => setTimeout(resolve, 200));
  assert.equal(
    await page.evaluate(() => window.harness.frames[0].replies.some((row) => row.id === 1)),
    false
  );
  assert.equal(await frame.evaluate(() => document.querySelector('button').disabled), true);
  await new Promise((resolve) => setTimeout(resolve, 400));
  assert.equal(await frame.evaluate(() => document.querySelector('button').disabled), true);
  await armed(frame);
  const reply = awaitReply(page, 1);
  await press(frame);
  assert.equal((await reply).text.includes(SECRET), false);
});
