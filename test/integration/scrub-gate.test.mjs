import assert from 'node:assert/strict';
import { test } from 'node:test';
import { click } from './browser.mjs';
import {
  armed,
  awaitReply,
  budget,
  frameOf,
  mount,
  openPilot,
  pollWhile,
  postCheck,
  press,
  SECRET,
  scrubSetup,
  sealSeven,
} from './scrub-harness.mjs';

const { served, chrome, embedder, cdp, pilot } = await scrubSetup();

test('a trusted click before arming does nothing; after armed() untrusted clicks do nothing; then press works', async (t) => {
  await sealSeven(embedder, t);
  const page = await openPilot(chrome, served, t);
  await mount(page);
  const frame = await frameOf(cdp, served);
  await postCheck(page, SECRET, 1);
  await frame.until(() => document.querySelector('button') !== null);
  assert.equal(await budget(frame, pilot), null);
  const early = await pollWhile(450, async () => {
    await click(frame, 'button').catch(() => undefined);
    const replied = await page.evaluate(() =>
      window.harness.frames[0].replies.some((row) => row.id === 1)
    );
    const stamps = await budget(frame, pilot);
    return !replied && stamps === null;
  });
  assert.equal(early, true);
  assert.equal(
    await page.evaluate(() => window.harness.frames[0].replies.some((row) => row.id === 1)),
    false
  );
  assert.equal(await budget(frame, pilot), null);
  await armed(frame);
  await frame.evaluate(() => document.querySelector('button').click());
  await frame.evaluate(() =>
    document.querySelector('button').dispatchEvent(new MouseEvent('click', { bubbles: true }))
  );
  assert.equal(
    await page.evaluate(() => window.harness.frames[0].replies.some((row) => row.id === 1)),
    false
  );
  assert.equal(await budget(frame, pilot), null);
  const reply = awaitReply(page, 1);
  await press(frame);
  assert.equal((await reply).text.includes(SECRET), false);
  assert.equal((await budget(frame, pilot)).length, 2);
});
