import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  awaitReply,
  frameOf,
  openPilot,
  postCheck,
  press,
  recheck,
  SECRET,
  scrubSetup,
  sealSeven,
} from './scrub-harness.mjs';

const { served, chrome, embedder, cdp } = await scrubSetup();

test('seven visible frames: four checks succeed, three get EBUSY, and each winner rechecks', async (t) => {
  await sealSeven(embedder, t);
  const page = await openPilot(chrome, served, t);
  const mounted = await page.evaluate(() =>
    window.harness.mounts(7, {
      style: 'width: 360px; height: 48px; border: 0; display: block; margin: 2px;',
    })
  );
  assert.equal(mounted.length, 7);
  assert.ok(mounted.every((entry) => entry.welcome?.op === 'welcome'));
  const frames = [];
  for (let i = 0; i < 7; i++) frames.push(await frameOf(cdp, served, `scrub-${i}`));
  const replies = [];
  for (let i = 0; i < 7; i++) {
    await postCheck(page, `${SECRET}-${i}`, i + 1, i);
    replies.push(awaitReply(page, i + 1, i));
    await press(frames[i]);
  }
  const results = await Promise.all(replies);
  const ok = results.filter((row) => row.text);
  const busy = results.filter((row) => row.error?.code === 'EBUSY');
  assert.equal(ok.length, 4);
  assert.equal(busy.length, 3);
  for (let i = 0; i < 7; i++) {
    if (!results[i].text) continue;
    const hashed = await recheck(page, 100 + i, i);
    assert.equal(typeof hashed.sha256, 'string');
  }
});
