import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { browser, openPopup, press, typeInto } from './browser.mjs';
import { setup } from './setup.mjs';

const { chrome, embedder, served } = await setup();
const cdp = await browser(chrome);
after(() => cdp.close());

const TOKEN = 'fake-locked-notes-0601';
const PASS = 'correct horse battery';

const call = (url, placeholder) => ({
  method: 'POST',
  url,
  headers: [['authorization', `Bearer ${placeholder}`]],
  body: '{}',
});

test('NEGATIVE agent registrations made while a locked vault waits to migrate never shape the migration, and a sign-in works after the unlock', async (t) => {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.connect());
  const token = await page.evaluate(
    (value) =>
      window.harness.call('put', { name: 'NOTES_MCP', value, kind: 'mcp', server: 'notes' }),
    TOKEN
  );
  const manage = await openPopup(cdp, page, { kind: 'protect' }, 'Vault lock');
  await press(manage, 'Protect with a passphrase');
  await typeInto(manage, '#passphrase', PASS);
  await typeInto(manage, '#confirm', PASS);
  await press(manage, 'Protect');
  await manage.until(() => document.body.textContent.includes('Protected with a passphrase.'));
  await press(manage, 'Lock now');
  await page.until(async () => (await window.harness.call('status')).status.locked === true);
  const ns = served.origin('seven');
  await page.goto(`${served.vault}/config.json`);
  await page.evaluate(
    (key) =>
      new Promise((resolve, reject) => {
        const open = indexedDB.open('slicc-vault', 1);
        open.onupgradeneeded = () => reject(new Error('the vault database is missing'));
        open.onsuccess = () => {
          const tx = open.result.transaction(['meta'], 'readwrite');
          tx.objectStore('meta').put(
            {
              model: [],
              mcp: [{ server: 'notes', url: 'https://notes.example.com/mcp', names: [] }],
            },
            key
          );
          tx.oncomplete = () => resolve(true);
          tx.onerror = () => reject(tx.error);
        };
      }),
    `endpoints:${ns}`
  );
  await embedder(t, 'seven', page);
  const welcome = await page.evaluate(() => window.harness.connect());
  assert.equal(welcome.status.locked, true);
  await page.evaluate(() => window.harness.agent());
  const ask = (op, fields) => page.evaluate((o, f) => window.harness.ask(o, f), op, fields);
  const early = await ask('endpoints', {
    mcp: [
      { server: 'notes', url: 'https://evil.example.com/mcp' },
      {
        server: 'docs',
        url: 'https://docs.example.com/mcp',
        tokenUrl: 'https://auth.example.com/token',
      },
    ],
  });
  assert.equal(early.ok, true);
  const unlock = await openPopup(cdp, page, 'auto', 'Unlock vault');
  await typeInto(unlock, '#passphrase', PASS);
  await press(unlock, 'Unlock');
  await page.until(async () => (await window.harness.call('status')).status.locked === false);
  const granted = await ask('grant', {
    server: 'docs',
    oauth: { tokenUrl: 'https://auth.example.com/token', clientId: 'fake-client' },
    response: JSON.stringify({ token_type: 'Bearer', access_token: 'fake-docs-access-0602' }),
  });
  assert.ok(granted.records?.length, JSON.stringify(granted));
  const own = await ask('mcp', {
    server: 'notes',
    request: call('https://notes.example.com/mcp', token.placeholder),
  });
  assert.deepEqual(
    own.request?.headers,
    [['authorization', `Bearer ${TOKEN}`]],
    JSON.stringify(own)
  );
  const moved = await ask('mcp', {
    server: 'notes',
    request: call('https://evil.example.com/mcp', token.placeholder),
  });
  assert.equal(moved.error.code, 'EACCES');
  assert.ok(!JSON.stringify(moved).includes(TOKEN));
  const audit = (await page.evaluate(() => window.harness.call('audit'))).audit;
  assert.deepEqual(
    audit.filter((entry) => entry.type === 'endpoints').map((entry) => entry.adopted),
    [[{ server: 'notes', host: 'notes.example.com' }]]
  );
});
