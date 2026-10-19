import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { SIGN_INS } from '../../src/providers.ts';
import { setup } from './setup.mjs';

const { embedder } = await setup();

const ACCESS = 'fake-xai-access-0801';
const REFRESH = 'fake-xai-refresh-0802';

async function ready(t) {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.connect());
  await page.evaluate(() => window.harness.agent());
  const ask = (op, fields) => page.evaluate((o, f) => window.harness.ask(o, f), op, fields);
  const answer = (body) =>
    page.evaluate((b) => {
      window.harness.egress.answer = { status: 200, headers: [], body: b };
    }, JSON.stringify(body));
  return { page, ask, answer };
}

const response = (fields = {}) =>
  JSON.stringify({ access_token: ACCESS, refresh_token: REFRESH, expires_in: 3600, ...fields });
const chat = (url, placeholder) => ({
  method: 'POST',
  url,
  headers: [['authorization', `Bearer ${placeholder}`]],
  body: '{}',
});

test('an xAI sign-in seals a model key that only reaches xAI and refreshes through the vault table', async (t) => {
  const { page, ask, answer } = await ready(t);
  const granted = await ask('grant', {
    provider: 'xai',
    name: 'XAI_OAUTH_TOKEN',
    response: response(),
  });
  assert.deepEqual(
    granted.records.map((r) => [r.kind, r.name]),
    [
      ['model', 'XAI_OAUTH_TOKEN'],
      ['grant', 'XAI_OAUTH_TOKEN_GRANT'],
    ]
  );
  assert.ok(granted.expiresAt > Date.now());
  assert.ok(!JSON.stringify(granted).includes('fake-xai'));
  const key = granted.records[0].placeholder;
  const own = await ask('model', {
    provider: 'xai',
    request: chat('https://api.x.ai/v1/chat/completions', key),
  });
  assert.deepEqual(own.request.headers, [['authorization', `Bearer ${ACCESS}`]]);
  const elsewhere = await ask('model', {
    provider: 'xai',
    request: chat('https://api.openai.com/v1/chat', key),
  });
  assert.match(elsewhere.error.message, /sent only to xai's own endpoints/);
  const crossed = await ask('model', {
    provider: 'openai',
    request: chat('https://api.openai.com/v1/chat', key),
  });
  assert.match(crossed.error.message, /isn't a credential of openai/);
  const redacted = await ask('redact', { texts: [`${ACCESS} ${REFRESH}`] });
  assert.ok(!redacted.texts[0].includes('fake-xai'));
  await answer({ access_token: 'fake-xai-access-0803', expires_in: 3600 });
  const refreshed = await ask('refresh', { provider: 'xai', name: 'XAI_OAUTH_TOKEN' });
  assert.equal(refreshed.state, 'refreshed');
  const sent = await page.evaluate(() => window.harness.egress.requests.at(-1));
  assert.equal(sent.url, 'https://auth.x.ai/oauth2/token');
  assert.match(sent.body, /client_id=b1a00492-073a-47ea-816f-4c329264a828/);
  assert.match(sent.body, /refresh_token=fake-xai-refresh-0802/);
  const again = await ask('model', {
    provider: 'xai',
    request: chat('https://api.x.ai/v1/chat/completions', key),
  });
  assert.deepEqual(again.request.headers, [['authorization', 'Bearer fake-xai-access-0803']]);
});

test('NEGATIVE a sign-in never takes its token endpoint from the agent, and refuses what it cannot vouch for', async (t) => {
  const { ask } = await ready(t);
  const rows = [
    [
      {
        provider: 'xai',
        name: 'X',
        response: response(),
        oauth: { tokenUrl: 'https://evil.example.com/t', clientId: 'c' },
      },
      'EINVAL',
    ],
    [{ provider: 'xai', name: 'X', response: response(), server: 'docs' }, 'EINVAL'],
    [{ provider: 'openai', name: 'X', response: response() }, 'ENOTSUP'],
    [{ provider: 'xai', response: response() }, 'EINVAL'],
    [{ provider: 'xai', name: 'X', response: 7 }, 'EINVAL'],
    [{ provider: 'xai', name: 'X', response: response({ token_type: 'mac' }) }, 'EACCES'],
    [
      { provider: 'xai', name: 'X', response: JSON.stringify({ error: 'access_denied' }) },
      'EACCES',
    ],
  ];
  for (const [fields, code] of rows) {
    const reply = await ask('grant', fields);
    assert.equal(reply.error?.code, code, JSON.stringify(fields));
  }
  const kimi = await ask('grant', {
    provider: 'kimi-coding',
    name: 'KIMI_OAUTH_TOKEN',
    response: response({ token_type: 'bearer' }),
  });
  assert.equal(kimi.records.length, 2);
  const clash = await ask('grant', {
    provider: 'xai',
    name: 'KIMI_OAUTH_TOKEN',
    response: response(),
  });
  assert.equal(clash.error.code, 'EEXIST');
});

test('NEGATIVE an agent sign-in over a pasted key keeps the pasted key restorable', async (t) => {
  const { page, ask } = await ready(t);
  const pasted = await page.evaluate(() =>
    window.harness.call('put', {
      name: 'XAI_KEY',
      value: 'fake-xai-pasted-0804',
      kind: 'model',
      provider: 'xai',
    })
  );
  const granted = await ask('grant', { provider: 'xai', name: 'XAI_KEY', response: response() });
  assert.equal(granted.records[0].placeholder, pasted.placeholder);
  const signedIn = await ask('model', {
    provider: 'xai',
    request: chat('https://api.x.ai/v1/chat', pasted.placeholder),
  });
  assert.deepEqual(signedIn.request.headers, [['authorization', `Bearer ${ACCESS}`]]);
  const view = (await page.evaluate(() => window.harness.call('list'))).list.secrets.find(
    (r) => r.name === 'XAI_KEY'
  );
  assert.deepEqual([view.source, view.replaced], ['oauth:xai', true]);
  const hidden = await ask('redact', { texts: ['echo fake-xai-pasted-0804'] });
  assert.equal(hidden.texts[0], `echo ${pasted.placeholder}`);
  const back = await page.evaluate(() =>
    window.harness.call('restore', { name: 'XAI_KEY', kind: 'model' })
  );
  assert.equal(back.placeholder, pasted.placeholder);
  const restored = await ask('model', {
    provider: 'xai',
    request: chat('https://api.x.ai/v1/chat', pasted.placeholder),
  });
  assert.deepEqual(restored.request.headers, [['authorization', 'Bearer fake-xai-pasted-0804']]);
  const list = (await page.evaluate(() => window.harness.call('list'))).list.secrets;
  assert.deepEqual(
    list
      .filter((r) => r.name.startsWith('XAI_KEY'))
      .map((r) => [r.name, r.state, r.source, r.replaced]),
    [
      ['XAI_KEY', 'inert', 'settings', undefined],
      ['XAI_KEY_GRANT', 'removed', 'oauth:xai', undefined],
    ]
  );
  const again = await ask('grant', { provider: 'xai', name: 'XAI_KEY', response: response() });
  const rotated = await ask('grant', {
    provider: 'xai',
    name: 'XAI_KEY',
    response: response({ access_token: 'fake-xai-access-0805' }),
  });
  assert.equal(rotated.records[0].placeholder, again.records[0].placeholder);
  await page.evaluate(() => window.harness.call('restore', { name: 'XAI_KEY', kind: 'model' }));
  const pastedAgain = await ask('model', {
    provider: 'xai',
    request: chat('https://api.x.ai/v1/chat', pasted.placeholder),
  });
  assert.deepEqual(pastedAgain.request.headers, [['authorization', 'Bearer fake-xai-pasted-0804']]);
});

test("NEGATIVE a sign-in never writes a returned token into its name or settings, nor takes another credential's grant", async (t) => {
  const { page, ask } = await ready(t);
  const leaked = await ask('grant', {
    provider: 'xai',
    name: 'XAI_LEAK',
    response: response(),
    settings: { NOTE: ACCESS },
  });
  assert.equal(leaked.error.code, 'EINVAL');
  await page.evaluate(
    (note) =>
      window.harness.call('put', {
        name: 'XAI_NOTED',
        value: 'fake-xai-noted-0817',
        kind: 'model',
        provider: 'xai',
        settings: { NOTE: note },
      }),
    ACCESS
  );
  const inherited = await ask('grant', {
    provider: 'xai',
    name: 'XAI_NOTED',
    response: response(),
  });
  assert.equal(inherited.error.code, 'EINVAL');
  const stored = await ask('grant', {
    provider: 'xai',
    name: 'XAI_STORED',
    response: response(),
    settings: { OLD: 'fake-xai-noted-0817' },
  });
  assert.equal(stored.error.code, 'EINVAL');
  const viewed = await page.evaluate(
    (text) =>
      window.harness.ask('grant', {
        provider: 'xai',
        name: 'XAI_VIEW',
        response: new Int8Array(new TextEncoder().encode(text).buffer),
      }),
    response({ access_token: 'fake-xai-view-0818', refresh_token: 'fake-xai-view-0819' })
  );
  assert.equal(viewed.records.length, 2);
  const named = await ask('grant', {
    provider: 'xai',
    name: 'FAKE_TOKEN_NAME_0809',
    response: response({ access_token: 'FAKE_TOKEN_NAME_0809' }),
  });
  assert.equal(named.error.code, 'EINVAL');
  await ask('endpoints', {
    mcp: [
      {
        server: 'docs',
        url: 'https://docs.example.com/mcp',
        tokenUrl: 'https://auth.example.com/token',
      },
    ],
  });
  const mcp = await ask('grant', {
    server: 'docs',
    name: 'SHARED',
    oauth: { tokenUrl: 'https://auth.example.com/token', clientId: 'fake-client' },
    response: JSON.stringify({
      token_type: 'Bearer',
      access_token: 'fake-mcp-shared-0810',
      refresh_token: 'fake-mcp-shared-0811',
    }),
  });
  assert.equal(mcp.records.length, 2);
  const taken = await ask('grant', { provider: 'xai', name: 'SHARED', response: response() });
  assert.equal(taken.error.code, 'EEXIST');
  const list = (await page.evaluate(() => window.harness.call('list'))).list.secrets;
  assert.equal(list.find((r) => r.name === 'SHARED_GRANT').source, 'oauth:mcp');
});

test('a repeat sign-in without a refresh token retires the old grant, and the next sign-in works', async (t) => {
  const { page, ask } = await ready(t);
  await ask('grant', { provider: 'xai', name: 'XAI_AGAIN', response: response() });
  const bare = await ask('grant', {
    provider: 'xai',
    name: 'XAI_AGAIN',
    response: JSON.stringify({ access_token: 'fake-xai-again-0814' }),
  });
  assert.deepEqual(
    bare.records.map((r) => r.kind),
    ['model']
  );
  const grant = (await page.evaluate(() => window.harness.call('list'))).list.secrets.find(
    (r) => r.name === 'XAI_AGAIN_GRANT'
  );
  assert.equal(grant.state, 'removed');
  const full = await ask('grant', {
    provider: 'xai',
    name: 'XAI_AGAIN',
    response: response({
      access_token: 'fake-xai-again-0815',
      refresh_token: 'fake-xai-again-0816',
    }),
  });
  assert.equal(full.records.length, 2);
});

const saved = {};

test('NEGATIVE a backup made over a pasted key carries the pasted key, not the sign-in', async (t) => {
  const { page, ask } = await ready(t);
  const pasted = await page.evaluate(() =>
    window.harness.call('put', {
      name: 'XAI_SAVED',
      value: 'fake-xai-saved-0820',
      kind: 'model',
      provider: 'xai',
    })
  );
  await ask('grant', { provider: 'xai', name: 'XAI_SAVED', response: response() });
  saved.placeholder = pasted.placeholder;
  saved.bundle = await page.evaluate(async () => {
    const reply = await window.harness.call('export', { passphrase: 'fake backup passphrase' });
    return btoa(String.fromCharCode(...reply.bundle));
  });
});

test('NEGATIVE that backup restores the pasted key into another vault', async (t) => {
  const { page, ask } = await ready(t);
  const done = await page.evaluate(
    (b) =>
      window.harness.call('import', {
        kind: 'bundle',
        bytes: Uint8Array.from(atob(b), (c) => c.charCodeAt(0)),
        password: 'fake backup passphrase',
        pick: [{ name: 'XAI_SAVED', kind: 'model' }],
      }),
    saved.bundle
  );
  assert.deepEqual(
    done.imported.map((r) => r.placeholder),
    [saved.placeholder]
  );
  const filled = await ask('model', {
    provider: 'xai',
    request: chat('https://api.x.ai/v1/chat', saved.placeholder),
  });
  assert.deepEqual(filled.request.headers, [['authorization', 'Bearer fake-xai-saved-0820']]);
});

test('removing a signed-in key removes its grant, and restore brings both back', async (t) => {
  const { page, ask } = await ready(t);
  await ask('grant', { provider: 'openai-codex', name: 'CODEX_TOKEN', response: response() });
  await page.evaluate(() => window.harness.call('remove', { name: 'CODEX_TOKEN', kind: 'model' }));
  const state = async () =>
    (await page.evaluate(() => window.harness.call('list'))).list.secrets
      .filter((r) => r.name.startsWith('CODEX_TOKEN'))
      .map((r) => [r.name, r.state]);
  assert.deepEqual(await state(), [
    ['CODEX_TOKEN', 'removed'],
    ['CODEX_TOKEN_GRANT', 'removed'],
  ]);
  await page.evaluate(() => window.harness.call('restore', { name: 'CODEX_TOKEN', kind: 'model' }));
  assert.deepEqual(await state(), [
    ['CODEX_TOKEN', 'inert'],
    ['CODEX_TOKEN_GRANT', 'inert'],
  ]);
});

test('a refused refresh shows the key expired, a network failure keeps it refreshing', async (t) => {
  const { page, ask } = await ready(t);
  await page.evaluate(() =>
    window.harness.call('put', { name: 'LITERAL', value: 'invalid_grant' })
  );
  await ask('grant', { provider: 'xai', name: 'XAI_SHORT', response: response({ expires_in: 0 }) });
  await ask('grant', {
    provider: 'kimi-coding',
    name: 'KIMI_SHORT',
    response: response({
      access_token: 'fake-kimi-access-0806',
      refresh_token: 'fake-kimi-refresh-0807',
      expires_in: 0,
    }),
  });
  await page.evaluate(() => {
    window.harness.egress.answer = { error: 'offline' };
  });
  const offline = await ask('refresh', { provider: 'kimi-coding', name: 'KIMI_SHORT' });
  assert.equal(offline.error.code, 'ENOTCONN');
  await page.evaluate(() => {
    window.harness.egress.answer = {
      status: 400,
      headers: [],
      body: JSON.stringify({ error: 'invalid_grant' }),
    };
  });
  const refused = await ask('refresh', { provider: 'xai', name: 'XAI_SHORT' });
  assert.match(refused.error.message, /^refresh failed: /);
  const records = (await ask('records', {})).records;
  const of = (name) => records.find((r) => r.name === name).state;
  assert.deepEqual([of('XAI_SHORT'), of('KIMI_SHORT')], ['expired', 'refreshing']);
  await ask('grant', {
    provider: 'xai',
    name: 'XAI_LIVE',
    response: response({ access_token: 'fake-xai-live-0812', refresh_token: 'fake-xai-live-0813' }),
  });
  const live = (await ask('records', {})).records.find((r) => r.name === 'XAI_LIVE');
  const manual = await ask('refresh', { provider: 'xai', name: 'XAI_LIVE' });
  assert.match(manual.error.message, /^refresh failed: /);
  assert.equal(
    (await ask('records', {})).records.find((r) => r.name === 'XAI_LIVE').state,
    'expired'
  );
  const used = await ask('model', {
    provider: 'xai',
    request: chat('https://api.x.ai/v1/chat', live.placeholder),
  });
  assert.match(used.error.message, /XAI_LIVE expired; sign in again/);
  const egressed = await page.evaluate(() => window.harness.egress.requests.length);
  const again = await ask('refresh', { provider: 'xai', name: 'XAI_SHORT' });
  assert.match(again.error.message, /^refresh failed: /);
  assert.equal(await page.evaluate(() => window.harness.egress.requests.length), egressed);
  const renewed = await ask('grant', { provider: 'xai', name: 'XAI_SHORT', response: response() });
  assert.ok(renewed.records.length === 2);
  assert.equal(
    (await ask('records', {})).records.find((r) => r.name === 'XAI_SHORT').state,
    'ready'
  );
});

test("the vault's sign-in table matches the installed pi-ai", async () => {
  const dir = new URL('../../node_modules/@earendil-works/pi-ai/dist/auth/oauth/', import.meta.url);
  const read = (file) => readFile(new URL(file, dir), 'utf8');
  const xai = await read('xai.js');
  assert.ok(xai.includes(`"${SIGN_INS.xai.clientId}"`));
  assert.ok(xai.includes(`"${SIGN_INS.xai.tokenUrl}"`));
  const kimi = await read('kimi-coding.js');
  assert.ok(kimi.includes(`"${SIGN_INS['kimi-coding'].clientId}"`));
  assert.ok(kimi.includes('"https://auth.kimi.com"') && kimi.includes('/api/oauth/token'));
  assert.equal(SIGN_INS['kimi-coding'].tokenUrl, 'https://auth.kimi.com/api/oauth/token');
  const codex = await read('openai-codex.js');
  assert.ok(codex.includes(`"${SIGN_INS['openai-codex'].clientId}"`));
  assert.ok(codex.includes('"https://auth.openai.com"') && codex.includes('/oauth/token`'));
  assert.equal(SIGN_INS['openai-codex'].tokenUrl, 'https://auth.openai.com/oauth/token');
});
