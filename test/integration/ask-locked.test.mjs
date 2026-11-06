import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { browser, openPopup, press, typeInto } from './browser.mjs';
import { setup } from './setup.mjs';

const { chrome, embedder } = await setup();
const cdp = await browser(chrome);
after(() => cdp.close());

const stamp = { pid: 70, ppid: 1, uid: 2100, gid: 2100, tag: null, users: 'enforce' };
const requester = {
  kind: 'user',
  name: 'lars',
  exe: '/usr/bin/sealed',
  argv: ['sealed', 'ask', 'LOCKED_ASK'],
  cwd: '/',
  tty: null,
  stdin: 'none',
};

async function clickIn(page, frame, text) {
  const inner = await frame.until((label) => {
    const found = [...document.querySelectorAll('button')].find(
      (b) => b.textContent === label && !b.disabled
    );
    if (!found) return false;
    const rect = found.getBoundingClientRect();
    return { x: rect.x + rect.width / 2, y: rect.y + rect.height / 2 };
  }, text);
  const outer = await page.evaluate(() => {
    const shown = document.getElementById('value');
    shown.scrollIntoView();
    const rect = shown.getBoundingClientRect();
    return { x: rect.x, y: rect.y };
  });
  const at = { x: outer.x + inner.x, y: outer.y + inner.y };
  for (const type of ['mouseMoved', 'mousePressed', 'mouseReleased']) {
    await page.send('Input.dispatchMouseEvent', { type, ...at, button: 'left', clickCount: 1 });
  }
}

test('a locked vault shows Unlock in the frame first, then the field', async (t) => {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.connect());
  const manage = await openPopup(cdp, page, { kind: 'protect' }, 'Vault lock');
  await press(manage, 'Protect with a passphrase');
  await typeInto(manage, '#passphrase', 'correct horse battery');
  await typeInto(manage, '#confirm', 'correct horse battery');
  await press(manage, 'Protect');
  await manage.until(() => document.body.textContent.includes('Protected with a passphrase.'));
  await press(manage, 'Lock now');
  await page.until(async () => (await window.harness.call('status')).status.locked === true);
  await manage.evaluate(() => window.close());
  const id = await page.evaluate(
    (req, s) => window.harness.hold(req, s),
    { v: 1, op: 'ask', name: 'LOCKED_ASK', reveal: true, requester },
    stamp
  );
  const asked = await page.until(
    (call) => window.harness.events.find((e) => e.event === 'asked' && e.call === call),
    id
  );
  await page.evaluate((request) => window.harness.value(request), asked.request);
  const frame = await cdp.target(/\/value\.html$/);
  await frame.until(
    () => document.querySelector('p')?.textContent === 'Unlock the vault to continue.'
  );
  assert.equal(await frame.evaluate(() => document.querySelector('input')), null);
  let unlock = null;
  for (let attempt = 0; !unlock && attempt < 3; attempt++) {
    await clickIn(page, frame, 'Unlock');
    unlock = await cdp.target(/\/popup\.html#[0-9a-f]{32}$/, 4000).catch(() => null);
  }
  await typeInto(unlock, '#passphrase', 'correct horse battery');
  await press(unlock, 'Unlock');
  await frame.until(() => document.querySelector('input') !== null);
  await frame.evaluate(() => {
    const input = document.querySelector('input');
    input.value = 'typed-after-unlock-05';
    input.dispatchEvent(new Event('input'));
  });
  await clickIn(page, frame, 'Save');
  const answer = await page.until((call) => window.harness.replies[call], id);
  assert.equal(answer.state, 'done');
  assert.equal(answer.value, 'typed-after-unlock-05');
});
