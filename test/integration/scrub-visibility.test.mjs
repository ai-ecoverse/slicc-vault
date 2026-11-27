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

test('zero-size, overlay, transformed parent and off-screen never arm; no IO v2 is EACCES', async (t) => {
  await sealSeven(embedder, t);
  const page = await openPilot(chrome, served, t);

  await mount(page, {
    tag: 'tiny',
    style: 'width: 0; height: 0; border: 0; overflow: hidden;',
  });
  const tiny = await frameOf(cdp, served, 'tiny');
  await postCheck(page, SECRET, 1, 0);
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
  const covered = await frameOf(cdp, served, 'covered');
  await page.evaluate(() => {
    const cover = document.createElement('div');
    cover.id = 'cover';
    cover.style.cssText = 'position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 1000;';
    document.body.append(cover);
  });
  await postCheck(page, SECRET, 2, 1);
  await covered.until(() => document.querySelector('button') !== null);
  assert.equal(
    await pollWhile(1500, async () =>
      covered.evaluate(() => document.querySelector('button')?.disabled === true)
    ),
    true
  );
  await page.evaluate(() => {
    document.getElementById('cover')?.remove();
    window.harness.frames[1].iframe.remove();
  });

  await page.evaluate(() => {
    const wrap = document.createElement('div');
    wrap.id = 'transformed';
    wrap.style.cssText = 'transform: scale(0.01); opacity: 0.01;';
    document.body.append(wrap);
  });
  await mount(page, {
    tag: 'scaled',
    style: 'width: 420px; height: 72px; border: 0;',
    id: 'scaled',
  });
  await page.evaluate(() => {
    document.getElementById('transformed').append(window.harness.frames[2].iframe);
  });
  const scaled = await frameOf(cdp, served, 'scaled');
  await postCheck(page, SECRET, 3, 2);
  await scaled.until(() => document.querySelector('button') !== null);
  assert.equal(
    await pollWhile(1500, async () =>
      scaled.evaluate(() => document.querySelector('button')?.disabled === true)
    ),
    true
  );
  await page.evaluate(() => document.getElementById('transformed')?.remove());

  await mount(page, {
    tag: 'offscreen',
    style: 'width: 420px; height: 72px; border: 0; position: fixed; left: -10000px; top: -10000px;',
    id: 'offscreen',
  });
  const off = await frameOf(cdp, served, 'offscreen');
  await postCheck(page, SECRET, 4, 3);
  await off.until(() => document.querySelector('button') !== null);
  assert.equal(
    await pollWhile(1500, async () =>
      off.evaluate(() => document.querySelector('button')?.disabled === true)
    ),
    true
  );
  await page.evaluate(() => window.harness.frames[3].iframe.remove());

  await mount(page, {
    tag: 'ok',
    style: 'width: 420px; height: 72px; border: 0;',
    id: 'ok',
  });
  const ok = await frameOf(cdp, served, 'ok');
  await postCheck(page, SECRET, 5, 4);
  await armed(ok);
  const reply = awaitReply(page, 5, 4);
  await press(ok);
  assert.equal((await reply).text.includes(SECRET), false);

  await page.evaluate(() => window.harness.frames[4].iframe.remove());
  await mount(page, { tag: 'blind' });
  const blind = await frameOf(cdp, served, 'blind');
  await blind.evaluate(() => {
    delete IntersectionObserverEntry.prototype.isVisible;
  });
  const denied = await page.evaluate(() =>
    window.harness.call(window.harness.frames[5], { id: 6, op: 'check', text: 'x' })
  );
  assert.equal(denied.error.code, 'EACCES');
  assert.equal(await blind.evaluate(() => document.querySelector('button')), null);
});
