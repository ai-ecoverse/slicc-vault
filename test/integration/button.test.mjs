import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { browser, click } from './browser.mjs';
import { setup } from './setup.mjs';

const { chrome, embedder } = await setup();
const cdp = await browser(chrome);
after(() => cdp.close());

const events = (kind) => window.harness.buttonEvents.filter((e) => e.event === kind);

test('a repeated button message restyles the button in place', async (t) => {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.button({ intent: { kind: 'protect' } }));
  await page.until(() =>
    window.harness.buttonEvents.some((e) => e.event === 'label' && e.label === 'Vault lock')
  );
  const frame = await cdp.target(/vault\.sliccy\.localhost:\d+\/button\.html$/);
  const loaded = await frame.evaluate(() => performance.timeOrigin);
  await page.evaluate(() =>
    window.harness.configure({
      intent: { kind: 'unlock' },
      variant: 'accent',
      treatment: 'outline',
      size: 'l',
      quiet: true,
      scale: 'large',
      theme: 'dark',
      dir: 'rtl',
      lang: 'de',
    })
  );
  await page.until(() =>
    window.harness.buttonEvents.some((e) => e.event === 'label' && e.label === 'Unlock vault')
  );
  const state = await frame.until(() => {
    const button = document.querySelector('button');
    return (
      button.className.includes('accent') && {
        className: button.className,
        body: document.body.className,
        dir: document.documentElement.dir,
        lang: document.documentElement.lang,
        origin: performance.timeOrigin,
      }
    );
  });
  assert.equal(state.origin, loaded);
  assert.equal(
    state.className,
    'spectrum-Button spectrum-Button--accent spectrum-Button--outline spectrum-Button--sizeL spectrum-Button--quiet'
  );
  assert.match(state.body, /spectrum--dark/);
  assert.match(state.body, /spectrum--large/);
  assert.equal(state.dir, 'rtl');
  assert.equal(state.lang, 'de');
  await page.evaluate(() =>
    window.harness.configure({
      intent: { kind: 'protect' },
      label: 'Lock settings',
      disabled: true,
    })
  );
  await page.until(() =>
    window.harness.buttonEvents.some((e) => e.event === 'label' && e.label === 'Lock settings')
  );
  assert.equal(await frame.until(() => document.querySelector('button').disabled), true);
  assert.equal(await page.evaluate(events, 'ready').then((list) => list.length), 1);
});

test('focus leaves and enters the button through the embedder', async (t) => {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.button({ intent: { kind: 'protect' } }));
  await page.until(() => document.getElementById('button')?.width > 0);
  const frame = await cdp.target(/vault\.sliccy\.localhost:\d+\/button\.html$/);
  await page.evaluate(() => {
    const button = document.getElementById('button');
    button.contentWindow.postMessage(
      { type: 'slicc-vault', v: 1, op: 'focus' },
      window.harness.vault
    );
  });
  await frame.until(() => document.activeElement?.tagName === 'BUTTON');
  await page.send('Input.dispatchKeyEvent', {
    type: 'rawKeyDown',
    key: 'Tab',
    code: 'Tab',
    windowsVirtualKeyCode: 9,
  });
  await page.send('Input.dispatchKeyEvent', {
    type: 'keyUp',
    key: 'Tab',
    code: 'Tab',
    windowsVirtualKeyCode: 9,
  });
  await page.send('Input.dispatchKeyEvent', {
    type: 'rawKeyDown',
    key: 'Tab',
    code: 'Tab',
    windowsVirtualKeyCode: 9,
    modifiers: 8,
  });
  await page.send('Input.dispatchKeyEvent', {
    type: 'keyUp',
    key: 'Tab',
    code: 'Tab',
    windowsVirtualKeyCode: 9,
    modifiers: 8,
  });
  const moves = await page.until(() => {
    const found = window.harness.buttonEvents
      .filter((e) => e.event === 'focus')
      .map((e) => e.direction);
    return found.length === 2 && found;
  });
  assert.deepEqual(moves, ['next', 'previous']);
});

test('a popup opened without a user gesture is reported as blocked', async (t) => {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.button({ intent: { kind: 'protect' } }));
  await page.until(() => document.getElementById('button')?.width > 0);
  const frame = await cdp.target(/vault\.sliccy\.localhost:\d+\/button\.html$/);
  await frame.evaluate(() => document.querySelector('button').click());
  const blocked = await page.until(() =>
    window.harness.buttonEvents.find((e) => e.event === 'popup')
  );
  assert.equal(blocked.state, 'blocked');
  assert.deepEqual(blocked.intent, { kind: 'protect' });
  await click(page, '#button');
  const opened = await page.until(() =>
    window.harness.buttonEvents.find((e) => e.event === 'popup' && e.state === 'opened')
  );
  assert.deepEqual(opened.intent, { kind: 'protect' });
});
