import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  armed,
  awaitReply,
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

const { served, chrome, embedder, cdp } = await scrubSetup();

test('an occluded or zero-size frame never arms; without IntersectionObserver v2 a check is EACCES', async (t) => {
  await sealSeven(embedder, t);
  const page = await openPilot(chrome, served, t);
  await mount(page, {
    tag: 'tiny',
    style: 'width: 0; height: 0; border: 0; overflow: hidden;',
  });
  const tiny = await frameOf(cdp, served, 'tiny');
  await postCheck(page, SECRET, 1);
  await tiny.until(() => document.querySelector('button') !== null);
  assert.equal(
    await pollWhile(1500, async () =>
      tiny.evaluate(() => document.querySelector('button')?.disabled === true)
    ),
    true
  );
  await page.evaluate(() => window.harness.frames[0].iframe.remove());
  await mount(page, {
    tag: 'covered',
    style: 'width: 420px; height: 72px; border: 0;',
    id: 'covered',
  });
  const frame = await frameOf(cdp, served, 'covered');
  await page.evaluate(() => {
    const cover = document.createElement('div');
    cover.id = 'cover';
    cover.style.cssText = 'position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 1000;';
    document.body.append(cover);
  });
  await postCheck(page, SECRET, 2, 1);
  await frame.until(() => document.querySelector('button') !== null);
  assert.equal(
    await pollWhile(1500, async () =>
      frame.evaluate(() => document.querySelector('button')?.disabled === true)
    ),
    true
  );
  await page.evaluate(() => document.getElementById('cover').remove());
  await armed(frame);
  const reply = awaitReply(page, 2, 1);
  await press(frame);
  assert.equal((await reply).text.includes(SECRET), false);
  await page.evaluate(() => window.harness.frames[1].iframe.remove());
  await mount(page, { tag: 'blind' });
  const blind = await frameOf(cdp, served, 'blind');
  await blind.evaluate(() => {
    delete IntersectionObserverEntry.prototype.isVisible;
  });
  const denied = await page.evaluate(() =>
    window.harness.call(window.harness.frames[2], { id: 3, op: 'check', text: 'x' })
  );
  assert.equal(denied.error.code, 'EACCES');
  assert.equal(await blind.evaluate(() => document.querySelector('button')), null);
});
