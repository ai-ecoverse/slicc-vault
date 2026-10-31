import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { attest, CONFIG, config } from './attest.mjs';
import { setup } from './setup.mjs';

const { embedder } = await setup();
const pkg = JSON.parse(await readFile(new URL('../../package.json', import.meta.url), 'utf8'));
const piAi = JSON.parse(
  await readFile(
    new URL('../../node_modules/@earendil-works/pi-ai/package.json', import.meta.url),
    'utf8'
  )
);

test('the published package names the pi-ai it was built against, which is the one installed', () => {
  assert.equal(pkg.piAi, pkg.devDependencies['@earendil-works/pi-ai']);
  assert.equal(pkg.piAi, piAi.version);
});

test('keys reach the current catalog: opencode inference, Vertex global and Azure Cognitive Services', async (t) => {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.connect());
  const put = (fields) => page.evaluate((f) => window.harness.call('put', f), fields);
  const keys = {
    opencode: await put({
      name: 'OPENCODE_API_KEY',
      value: 'fake-opencode-key-0301',
      kind: 'model',
      provider: 'opencode',
    }),
    'opencode-go': await put({
      name: 'OPENCODE_GO_KEY',
      value: 'fake-opencode-go-0302',
      kind: 'model',
      provider: 'opencode-go',
    }),
    'google-vertex': await put({
      name: 'VERTEX_KEY',
      value: 'fake-vertex-key-0303',
      kind: 'model',
      provider: 'google-vertex',
    }),
    azure: await put({
      name: 'AZURE_KEY',
      value: 'fake-azure-key-0304',
      kind: 'model',
      provider: 'azure',
    }),
  };
  await page.evaluate(() => window.harness.agent());
  const ask = (provider, url) =>
    page.evaluate(
      (p, u, k) =>
        window.harness.ask('model', {
          provider: p,
          request: {
            method: 'POST',
            url: u,
            headers: [['authorization', `Bearer ${k}`]],
            body: '{}',
          },
        }),
      provider,
      url,
      keys[provider].placeholder
    );
  for (const [provider, url, value] of [
    ['opencode', 'https://opencode.ai/inference/v1/chat/completions', 'fake-opencode-key-0301'],
    [
      'opencode-go',
      'https://opencode.ai/inference/go/v1/chat/completions',
      'fake-opencode-go-0302',
    ],
    [
      'google-vertex',
      'https://aiplatform.googleapis.com/v1/projects/p/locations/global/publishers/google/models/m:generateContent',
      'fake-vertex-key-0303',
    ],
    [
      'azure',
      'https://my-resource.cognitiveservices.azure.com/openai/deployments/d/chat/completions',
      'fake-azure-key-0304',
    ],
  ]) {
    const got = await ask(provider, url);
    assert.deepEqual(
      got.request?.headers,
      [['authorization', `Bearer ${value}`]],
      `${provider}: ${JSON.stringify(got.error)}`
    );
  }
  const stale = await ask('opencode', 'https://opencode.ai/zen/v1/chat/completions');
  assert.match(stale.error.message, /sent only to opencode's own endpoints/);
  for (const url of [
    'https://a.b.cognitiveservices.azure.com/openai/deployments/d/chat/completions',
    'https://cognitiveservices.azure.com.example.com/openai/deployments/d/chat/completions',
    'https://my-resource.cognitiveservices.azure.com/speechtotext/v3.2/transcriptions',
  ]) {
    const wide = await ask('azure', url);
    assert.match(wide.error.message, /sent only to azure's own endpoints/, url);
  }
});

test('retired and new model hosts stay refused for secrets, and Azure Speech rules keep working', async (t) => {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.connect());
  const gh = await page.evaluate(() =>
    window.harness.call('put', { name: 'SVC_KEY', value: 'fake-service-key-0305' })
  );
  const domains = [
    'opencode.ai',
    'api.kimi.com',
    'aiplatform.googleapis.com',
    'my-resource.cognitiveservices.azure.com',
  ];
  const text = config(
    { SVC_KEY: gh.placeholder },
    domains.map((domain) => ({ secret: 'SVC_KEY', domain }))
  );
  await page.evaluate((files) => window.harness.policy(files), [attest(CONFIG, text)]);
  const list = (await page.evaluate(() => window.harness.call('list'))).list;
  assert.deepEqual(
    list.refused.map((r) => r.rule.domain),
    ['aiplatform.googleapis.com']
  );
  const send = (url) =>
    page.evaluate((f) => window.harness.forward(f), {
      head: { method: 'POST', url, headers: [['Authorization', `Bearer ${gh.placeholder}`]] },
      owner: { pid: 9, ppid: 1, uid: 1000, gid: 1000, tag: 'cone', users: 'enforce' },
      exit: 'page',
      bodyPresent: false,
      rawTraits: { manualRedirects: true },
    });
  for (const url of [
    'https://opencode.ai/zen/v1/chat/completions',
    'https://opencode.ai/zen/go/v1/chat/completions',
    'https://api.kimi.com/coding/chat',
    'https://my-resource.cognitiveservices.azure.com/openai/deployments/d/chat/completions',
  ]) {
    const refused = await send(url);
    assert.equal(refused.reply.refused?.status, 403, url);
    assert.match(
      refused.reply.refused.reason,
      /is a model or MCP endpoint; the vault never injects there/
    );
  }
  const speech = await send(
    'https://my-resource.cognitiveservices.azure.com/speechtotext/v3.2/transcriptions'
  );
  assert.deepEqual(speech.reply.head.headers, [['Authorization', 'Bearer fake-service-key-0305']]);
  const other = await send('https://opencode.ai/docs');
  assert.ok(other.reply.head);
});
