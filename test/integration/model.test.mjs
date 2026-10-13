import assert from 'node:assert/strict';
import { test } from 'node:test';
import { setup } from './setup.mjs';

const { embedder } = await setup();

const MODEL_KEY = 'fake-model-key-0101';
const OTHER_KEY = 'fake-model-key-0102';
const SECRET = 'fake-secret-value-0103';
const BRIDGE = 'fake-bridge-token-0104';

async function ready(t) {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.connect());
  const put = (fields) => page.evaluate((f) => window.harness.call('put', f), fields);
  const model = await put({
    name: 'ANTHROPIC_API_KEY',
    value: MODEL_KEY,
    kind: 'model',
    provider: 'anthropic',
    settings: { NOTE: 'n' },
  });
  const other = await put({
    name: 'OPENAI_API_KEY',
    value: OTHER_KEY,
    kind: 'model',
    provider: 'openai',
  });
  const secret = await put({ name: 'GH_TOKEN', value: SECRET });
  const bridge = await put({ name: 'BRIDGE', value: BRIDGE, kind: 'mcp', server: 'bridge' });
  assert.equal((await page.evaluate(() => window.harness.agent())).role, 'agent');
  const ask = (op, fields) => page.evaluate((o, f) => window.harness.ask(o, f), op, fields);
  const registered = await ask('endpoints', {
    model: [{ provider: 'openai', url: 'https://llm.example.com/v1' }],
    mcp: [
      { server: 'bridge', url: 'http://8080.kernel.localhost/mcp' },
      {
        server: 'docs',
        url: 'https://docs.example.com/mcp',
        tokenUrl: 'https://auth.example.com/token',
      },
    ],
  });
  assert.deepEqual(registered.ok, true);
  return { page, ask, model, other, secret, bridge };
}

const req = (url, headers = [], body) => ({
  method: 'POST',
  url,
  headers,
  ...(body === undefined ? {} : { body }),
});

test('model prepares a request with its provider key and the body scrubbed', async (t) => {
  const { page, ask, model, other, secret } = await ready(t);
  const got = await ask('model', {
    provider: 'anthropic',
    request: req(
      'https://api.anthropic.com/v1/messages',
      [['x-api-key', model.placeholder]],
      `{"system":"token ${SECRET}"}`
    ),
  });
  assert.deepEqual(got.request.headers, [['x-api-key', MODEL_KEY]]);
  assert.equal(got.request.body, `{"system":"token ${secret.placeholder}"}`);
  assert.deepEqual(got.hits, [{ name: 'GH_TOKEN', form: 'raw', count: 1 }]);
  const inferred = await ask('model', {
    request: req(`https://llm.example.com/v1/chat?key=${other.placeholder}`),
  });
  assert.equal(inferred.request.url, `https://llm.example.com/v1/chat?key=${OTHER_KEY}`);
  const keyless = await ask('model', {
    request: req('https://local-gateway.example.com/v1', [], 'hi'),
  });
  assert.equal(keyless.request.body, 'hi');
  const elsewhere = await ask('model', {
    provider: 'anthropic',
    request: req('https://evil.example.com/v1', [['x-api-key', model.placeholder]]),
  });
  assert.equal(elsewhere.error.code, 'EACCES');
  assert.match(elsewhere.error.message, /sent only to anthropic's own endpoints/);
  const crossed = await ask('model', {
    provider: 'anthropic',
    request: req('https://api.anthropic.com/v1', [['x-api-key', other.placeholder]]),
  });
  assert.match(crossed.error.message, /isn't a credential of anthropic/);
  const leaked = await ask('model', {
    provider: 'anthropic',
    request: req('https://api.anthropic.com/v1', [
      ['authorization', `Bearer ${secret.placeholder}`],
    ]),
  });
  assert.match(leaked.error.message, /never sent to model or MCP endpoints/);
  const insecure = await ask('model', { request: req('http://localhost:11434/v1', []) });
  assert.match(insecure.error.message, /https only/);
  const raw = await ask('model', {
    request: req('https://elsewhere.example.com/v1', [['x-api-key', MODEL_KEY]]),
  });
  assert.match(raw.error.message, /head carries a value/);
  const nested = await page.evaluate(
    (inner) =>
      window.harness.call('put', {
        name: 'NESTED',
        value: `wrap-${inner}-wrap`,
        kind: 'model',
        provider: 'anthropic',
      }),
    SECRET
  );
  const holds = await ask('model', {
    provider: 'anthropic',
    request: req('https://api.anthropic.com/v1', [['x-api-key', nested.placeholder]]),
  });
  assert.match(holds.error.message, /contains another stored value/);
  const named = await ask('model', {
    request: req('https://elsewhere.example.com/v1', [[MODEL_KEY, 'x']]),
  });
  assert.match(named.error.message, /head carries a value/);
});

test('mcp fills its server credential on the kernel loopback, and never sends one elsewhere', async (t) => {
  const { ask, bridge, model } = await ready(t);
  const got = await ask('mcp', {
    server: 'bridge',
    request: req(
      'http://8080.kernel.localhost/mcp',
      [['authorization', `Bearer ${bridge.placeholder}`]],
      `{"args":"${SECRET}"}`
    ),
  });
  assert.deepEqual(got.request.headers, [['authorization', `Bearer ${BRIDGE}`]]);
  assert.ok(!got.request.body.includes(SECRET));
  const cdp = await ask('mcp', {
    server: 'bridge',
    request: req('http://9222.kernel.localhost/json', []),
  });
  assert.match(cdp.error.message, /https only/);
  const foreignLoop = await ask('mcp', {
    server: 'docs',
    request: req('http://8080.kernel.localhost/mcp', []),
  });
  assert.match(foreignLoop.error.message, /https only/);
  const discovery = await ask('mcp', {
    server: 'docs',
    request: req('https://docs.example.com/.well-known/oauth-protected-resource'),
  });
  assert.equal(
    discovery.request.url,
    'https://docs.example.com/.well-known/oauth-protected-resource'
  );
  const wrongServer = await ask('mcp', {
    server: 'docs',
    request: req('https://docs.example.com/mcp', [
      ['authorization', `Bearer ${bridge.placeholder}`],
    ]),
  });
  assert.match(wrongServer.error.message, /isn't a credential of docs/);
  const modelKey = await ask('mcp', {
    server: 'bridge',
    request: req('http://8080.kernel.localhost/mcp', [['authorization', model.placeholder]]),
  });
  assert.match(modelKey.error.message, /isn't a credential of bridge/);
});

test('records lists model and mcp records, never values or secrets', async (t) => {
  const { page, ask } = await ready(t);
  await page.evaluate(() =>
    window.harness.call('put', {
      name: 'ECHOED',
      value: 'fake-echoed-0120',
      kind: 'mcp',
      server: 'bridge',
      settings: { SAME: 'fake-echoed-0120', fake_key_name_0121: 'x' },
    })
  );
  await page.evaluate(() =>
    window.harness.call('put', { name: 'KEYNAME', value: 'fake_key_name_0121' })
  );
  await page.evaluate(() =>
    window.harness.call('put', {
      name: 'fake_key_name_0121',
      value: 'fake-named-0122',
      kind: 'mcp',
    })
  );
  const listed = (await ask('records', {})).records;
  assert.ok(!JSON.stringify(listed).includes('fake-'));
  assert.ok(!JSON.stringify(listed).includes('fake_key'));
  assert.deepEqual(listed.map((r) => r.name).sort(), [
    'ANTHROPIC_API_KEY',
    'BRIDGE',
    'ECHOED',
    'OPENAI_API_KEY',
  ]);
  const anthropic = listed.find((r) => r.name === 'ANTHROPIC_API_KEY');
  assert.deepEqual(
    [anthropic.kind, anthropic.provider, anthropic.state, anthropic.settings],
    ['model', 'anthropic', 'ready', { NOTE: 'n' }]
  );
  const rotated = await page.evaluate(() =>
    window.harness.call('put', {
      name: 'ANTHROPIC_API_KEY',
      value: 'fake-model-key-0199',
      kind: 'model',
    })
  );
  assert.equal(rotated.placeholder, anthropic.placeholder);
  const fresh = await page.evaluate(() =>
    window.harness.call('put', { name: 'NEW_MODEL', value: 'fake-model-key-0198', kind: 'model' })
  );
  assert.equal(fresh.error.message, 'a model record needs its provider');
  const asked = await page.evaluate(() =>
    window.harness.sealed({ v: 1, op: 'request', kind: 'value', name: 'NEW_MODEL' })
  );
  const answered = await page.evaluate(
    (id) =>
      window.harness.call('put', {
        name: 'NEW_MODEL',
        value: 'fake-model-key-0197',
        kind: 'model',
        provider: 'openai',
        request: id,
      }),
    asked.id
  );
  assert.match(answered.error.message, /asks for another value/);
  const after = (await ask('records', {})).records.find((r) => r.name === 'ANTHROPIC_API_KEY');
  assert.equal(after.provider, 'anthropic');
  await page.evaluate(() =>
    window.harness.call('put', {
      name: 'BRIDGE',
      value: 'fake-bridge-token-0105',
      kind: 'mcp',
      server: 'bridge-two',
      settings: { HOST: 'fake-model-key-0102' },
    })
  );
  const pageList = (await page.evaluate(() => window.harness.call('list'))).list.secrets;
  const bridgeView = pageList.find((r) => r.name === 'BRIDGE');
  assert.equal(bridgeView.server, 'bridge-two');
  assert.ok(!bridgeView.settings.HOST.includes('fake-'));
});

test('an MCP sign-in is sealed by grant and refreshed in the vault through egress', async (t) => {
  const { page, ask } = await ready(t);
  const oauth = { tokenUrl: 'https://auth.example.com/token', clientId: 'fake-client' };
  const exchange = await ask('mcp', {
    server: 'docs',
    request: req(
      'https://auth.example.com/token',
      [['content-type', 'application/x-www-form-urlencoded']],
      'grant_type=authorization_code&code=c&code_verifier=v'
    ),
  });
  assert.equal(exchange.request.url, 'https://auth.example.com/token');
  const granted = await ask('grant', {
    server: 'docs',
    oauth,
    response: JSON.stringify({
      access_token: 'fake-mcp-access-0105',
      refresh_token: 'fake-mcp-refresh-0106',
      expires_in: 3600,
      token_type: 'Bearer',
      id_token: 'fake-id-token-0108',
    }),
  });
  const shown = JSON.parse(granted.response);
  assert.deepEqual(
    granted.records.map((r) => r.name),
    ['DOCS_ACCESS_TOKEN', 'DOCS_ACCESS_TOKEN_GRANT']
  );
  assert.equal(shown.access_token, granted.records[0].placeholder);
  assert.equal(shown.refresh_token, granted.records[1].placeholder);
  assert.equal(shown.id_token, undefined);
  const call = await ask('mcp', {
    server: 'docs',
    request: req('https://docs.example.com/mcp', [
      ['authorization', `Bearer ${shown.access_token}`],
    ]),
  });
  assert.deepEqual(call.request.headers, [['authorization', 'Bearer fake-mcp-access-0105']]);
  const scrubbed = await ask('redact', {
    texts: ['out fake-mcp-access-0105 fake-mcp-refresh-0106'],
  });
  assert.equal(scrubbed.texts[0], `out ${shown.access_token} ${shown.refresh_token}`);
  await page.evaluate(() => {
    window.harness.egress.answer = {
      status: 200,
      headers: [],
      body: JSON.stringify({ access_token: 'fake-mcp-access-0107', expires_in: 3600 }),
    };
  });
  const refreshed = await ask('refresh', { server: 'docs' });
  assert.equal(refreshed.state, 'refreshed');
  const sent = await page.evaluate(() => window.harness.egress.requests.at(-1));
  assert.equal(sent.url, 'https://auth.example.com/token');
  assert.match(sent.body, /refresh_token=fake-mcp-refresh-0106/);
  const again = await ask('mcp', {
    server: 'docs',
    request: req('https://docs.example.com/mcp', [
      ['authorization', `Bearer ${shown.access_token}`],
    ]),
  });
  assert.deepEqual(again.request.headers, [['authorization', 'Bearer fake-mcp-access-0107']]);
  await ask('endpoints', {
    mcp: [
      {
        server: 'DOCS',
        url: 'https://docs2.example.com/mcp',
        tokenUrl: 'https://auth.example.com/token',
      },
    ],
  });
  const clash = await ask('grant', {
    server: 'DOCS',
    oauth,
    response: JSON.stringify({ access_token: 'fake-mcp-access-0109' }),
  });
  assert.equal(clash.error.code, 'EEXIST');
  const second = await ask('grant', {
    server: 'docs',
    name: 'DOCS_SECOND',
    oauth,
    response: JSON.stringify({
      access_token: 'fake-mcp-access-0110',
      refresh_token: 'fake-mcp-refresh-0111',
    }),
  });
  assert.equal(second.records[0].name, 'DOCS_SECOND');
  const scoped = await ask('grant', {
    server: 'docs',
    name: 'DOCS_THIRD',
    oauth,
    response: JSON.stringify({
      access_token: 'fake-mcp-access-0112',
      scope: 'read fake-mcp-access-0112',
    }),
  });
  assert.equal(JSON.parse(scoped.response).scope, `read ${scoped.records[0].placeholder}`);
  const ambiguous = await ask('refresh', { server: 'docs' });
  assert.match(ambiguous.error.message, /several; name the one/);
  const none = await ask('refresh', { provider: 'anthropic' });
  assert.equal(none.error.code, 'ENOENT');
  const short = await ask('grant', { server: 'docs', oauth, response: '{"access_token":"short"}' });
  await page.evaluate(() =>
    window.harness.call('put', { name: 'NAMEVAL', value: 'fake_key_name_0124' })
  );
  const named = await ask('grant', {
    server: 'docs',
    name: 'fake_key_name_0124',
    oauth,
    response: '{"access_token":"fake-mcp-access-0123"}',
  });
  assert.equal(named.error.code, 'EINVAL');
  const sameAsToken = await ask('grant', {
    server: 'docs',
    name: 'SAME_AS_TOKEN_02',
    oauth,
    response: '{"access_token":"SAME_AS_TOKEN_02"}',
  });
  assert.equal(sameAsToken.error.code, 'EINVAL');
  const grantNamed = await ask('grant', {
    server: 'docs',
    name: 'DOCSY',
    oauth,
    response: '{"access_token":"fake-mcp-access-0125","refresh_token":"DOCSY_GRANT"}',
  });
  assert.equal(grantNamed.error.code, 'EINVAL');
  assert.equal(short.error.code, 'EINVAL');
  const badGrant = await ask('grant', {
    server: 'docs',
    oauth: { ...oauth, tokenUrl: 'https://other.example.com/token' },
    response: '{}',
  });
  assert.equal(badGrant.error.code, 'EACCES');
});

test('a kernel bridge seals its own loopback token, which only that server gets', async (t) => {
  const { page, ask } = await ready(t);
  const seal = (fields, uid = 1000) =>
    page.evaluate(
      (f, u) =>
        window.harness.sealed(
          { v: 1, op: 'seal', name: 'MCP_BRIDGE_TOKEN', ...f },
          { pid: 77, ppid: 1, uid: u, gid: 1000, tag: null }
        ),
      fields,
      uid
    );
  const remote = await seal({
    value: 'fake-bridge-tok-0130',
    kind: 'mcp',
    server: 'bridge',
    url: 'https://bridge.example.com/mcp',
  });
  assert.equal(remote.error.code, 'EACCES');
  const sealed = await seal({
    value: 'fake-bridge-tok-0131',
    kind: 'mcp',
    server: 'bridge',
    url: 'http://8080.kernel.localhost/mcp',
  });
  const again = await seal({
    value: 'fake-bridge-tok-0132',
    kind: 'mcp',
    server: 'bridge',
    url: 'http://8080.kernel.localhost/mcp',
  });
  assert.equal(again.placeholder, sealed.placeholder);
  const stranger = await seal(
    {
      value: 'fake-bridge-tok-0133',
      kind: 'mcp',
      server: 'bridge',
      url: 'http://8080.kernel.localhost/mcp',
    },
    1001
  );
  assert.equal(stranger.error.code, 'EEXIST');
  const user = await seal(
    {
      name: 'BRIDGE',
      value: 'fake-bridge-tok-0134',
      kind: 'mcp',
      server: 'bridge',
      url: 'http://8080.kernel.localhost/mcp',
    },
    0
  );
  assert.equal(user.error.code, 'EEXIST');
  const filled = await ask('mcp', {
    server: 'bridge',
    request: req('http://8080.kernel.localhost/mcp', [
      ['authorization', `Bearer ${sealed.placeholder}`],
    ]),
  });
  assert.deepEqual(filled.request.headers, [['authorization', 'Bearer fake-bridge-tok-0132']]);
  await ask('endpoints', {
    mcp: [
      {
        server: 'bridge',
        url: 'http://8080.kernel.localhost/mcp',
        tokenUrl: 'https://auth.example.com/bridge-token',
      },
    ],
  });
  const exfil = await ask('mcp', {
    server: 'bridge',
    request: req('https://auth.example.com/bridge-token', [
      ['authorization', `Bearer ${sealed.placeholder}`],
    ]),
  });
  assert.match(exfil.error.message, /isn't a credential of bridge/);
  const elsewhere = await ask('mcp', {
    server: 'docs',
    request: req('https://docs.example.com/mcp', [
      ['authorization', `Bearer ${sealed.placeholder}`],
    ]),
  });
  assert.match(elsewhere.error.message, /isn't a credential of docs/);
  await page.evaluate(() =>
    window.harness.call('put', {
      name: 'MCP_BRIDGE_TOKEN',
      value: 'fake-rebound-0135',
      kind: 'mcp',
      server: 'docs',
    })
  );
  const rebound = await ask('mcp', {
    server: 'docs',
    request: req('https://docs.example.com/mcp', [
      ['authorization', `Bearer ${sealed.placeholder}`],
    ]),
  });
  assert.deepEqual(rebound.request.headers, [['authorization', 'Bearer fake-rebound-0135']]);
});
