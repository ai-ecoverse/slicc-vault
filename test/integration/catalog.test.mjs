import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
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
});
