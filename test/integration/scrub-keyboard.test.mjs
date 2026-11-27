import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  armed,
  awaitReply,
  frameOf,
  mount,
  openPilot,
  postCheck,
  SECRET,
  scrubSetup,
  sealSeven,
} from './scrub-harness.mjs';

const { served, chrome, embedder, cdp } = await scrubSetup();

test('a key activation needs a trusted key event on the focused button', async (t) => {
  await sealSeven(embedder, t);
  const page = await openPilot(chrome, served, t);
  await mount(page);
  const frame = await frameOf(cdp, served);
  await postCheck(page, `hold ${SECRET}`, 1);
  await armed(frame);
  await frame.evaluate(() => document.querySelector('button').focus());
  await frame.evaluate(() =>
    document
      .querySelector('button')
      .dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }))
  );
  await new Promise((resolve) => setTimeout(resolve, 200));
  assert.equal(
    await page.evaluate(() => window.harness.frames[0].replies.some((row) => row.id === 1)),
    false
  );
  const reply = awaitReply(page, 1);
  await frame.send('Input.dispatchKeyEvent', {
    type: 'rawKeyDown',
    key: 'Enter',
    code: 'Enter',
    windowsVirtualKeyCode: 13,
  });
  await frame.send('Input.dispatchKeyEvent', {
    type: 'keyUp',
    key: 'Enter',
    code: 'Enter',
    windowsVirtualKeyCode: 13,
  });
  assert.equal((await reply).text.includes(SECRET), false);
});
