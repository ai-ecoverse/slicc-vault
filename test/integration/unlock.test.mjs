import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { browser, openPopup, press, typeInto } from './browser.mjs';
import { setup } from './setup.mjs';

const { chrome, embedder } = await setup();
const cdp = await browser(chrome);
after(() => cdp.close());

const seal = (name, value) => window.harness.sealed({ v: 1, op: 'seal', name, value });

test('a passphrase lock locks injection-side ops and unlocks from the popup', async (t) => {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.connect());
  const first = await page.evaluate(seal, 'BEFORE_LOCK', 'value-before-lock');
  const manage = await openPopup(cdp, page, { kind: 'protect' }, 'Vault lock');
  await press(manage, 'Protect with a passphrase');
  const protect = () =>
    [...document.querySelectorAll('button')].find((b) => b.textContent === 'Protect').disabled;
  await typeInto(manage, '#passphrase', 'too short');
  assert.equal(
    await manage.evaluate(() => document.querySelector('#strength').textContent),
    'At least 12 characters: 3 more.'
  );
  assert.equal(await manage.evaluate(protect), true);
  await manage.evaluate(() => {
    document.querySelector('#passphrase').value = '';
  });
  await typeInto(manage, '#passphrase', 'correct horse battery');
  await typeInto(manage, '#confirm', 'correct horse battery');
  assert.equal(await manage.evaluate(protect), false);
  await press(manage, 'Protect');
  await manage.until(() => document.body.textContent.includes('Protected with a passphrase.'));
  await page.until(async () => (await window.harness.call('status')).status.lock === 'passphrase');
  const stillOpen = await page.evaluate(seal, 'WHILE_UNLOCKED', 'value-while-unlocked');
  assert.match(stillOpen.placeholder, /^fnox_proxy_/);
  await press(manage, 'Lock now');
  await page.until(async () => (await window.harness.call('status')).status.locked === true);
  const refused = await page.evaluate(seal, 'WHILE_LOCKED', 'value-while-locked');
  assert.equal(refused.error.code, 'EACCES');
  assert.match(refused.error.message, /^vault is locked/);
  const looked = await page.evaluate(() =>
    window.harness.sealed({ v: 1, op: 'placeholder', name: 'BEFORE_LOCK' })
  );
  assert.equal(looked.placeholder, first.placeholder);
  await page.reload();
  await page.until(() => document.title === 'ready');
  const welcome = await page.evaluate(() => window.harness.connect());
  assert.equal(welcome.status.locked, true);
  assert.deepEqual(welcome.status.scrub, { needed: true, version: 2, ready: false });
  const unlock = await openPopup(cdp, page, 'auto', 'Unlock vault');
  await typeInto(unlock, '#passphrase', 'wrong passphrase');
  await press(unlock, 'Unlock');
  await unlock.until(
    () =>
      document.querySelector('.error').textContent === "That passphrase doesn't unlock this vault."
  );
  assert.equal(await unlock.evaluate(() => document.querySelector('#passphrase').value), '');
  assert.equal(await unlock.evaluate(() => document.activeElement?.id), 'passphrase');
  await typeInto(unlock, '#passphrase', 'correct horse battery');
  await press(unlock, 'Unlock');
  await page.until(async () => (await window.harness.call('status')).status.locked === false);
  const ready = await page.evaluate(async () => (await window.harness.call('status')).status.scrub);
  assert.equal(ready.ready, true);
  const after = await page.evaluate(seal, 'AFTER_UNLOCK', 'value-after-unlock');
  assert.match(after.placeholder, /^fnox_proxy_/);
  const seen = await page.evaluate(() => JSON.stringify(window.harness.seen));
  for (const value of [
    'value-before-lock',
    'value-while-unlocked',
    'value-after-unlock',
    'correct horse',
  ]) {
    assert.ok(!seen.includes(value), value);
  }
});

test('a passkey with PRF protects the vault and unlocks it', async (t) => {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.connect());
  const manage = await openPopup(cdp, page, { kind: 'protect' }, 'Vault lock');
  await manage.send('WebAuthn.enable', { enableUI: false });
  await manage.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      ctap2Version: 'ctap2_1',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      hasPrf: true,
      automaticPresenceSimulation: true,
    },
  });
  await press(manage, 'Protect with a passkey');
  await manage.until(
    () =>
      document.body.textContent.includes('Protected with a passkey.') ||
      document.querySelector('.error')?.textContent
  );
  assert.equal(
    await manage.evaluate(() => document.querySelector('.error')?.textContent ?? ''),
    ''
  );
  await press(manage, 'Lock now');
  await page.until(async () => (await window.harness.call('status')).status.locked === true);
  await manage.until(() =>
    [...document.querySelectorAll('button')].some((b) => b.textContent === 'Unlock with passkey')
  );
  await press(manage, 'Unlock with passkey');
  await page.until(async () => (await window.harness.call('status')).status.locked === false);
  await manage.until(() => document.body.textContent.includes('Protected with a passkey.'));
  await press(manage, 'Remove protection');
  await manage.until(() => document.querySelector('main h1').textContent === 'Remove protection?');
  assert.match(
    await manage.evaluate(() => document.querySelector('main').textContent),
    /unlock by itself on this device/
  );
  await press(manage, 'Remove protection');
  await page.until(async () => (await window.harness.call('status')).status.lock === 'auto');
  const sealed = await page.evaluate(seal, 'WITH_PASSKEY', 'value-with-passkey');
  assert.match(sealed.placeholder, /^fnox_proxy_/);
});
