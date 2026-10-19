import assert from 'node:assert/strict';
import { test } from 'node:test';
import { setup } from './setup.mjs';

const { embedder } = await setup();

async function ready(t) {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.connect());
  const put = (fields) => page.evaluate((f) => window.harness.call('put', f), fields);
  await page.evaluate(() => window.harness.agent());
  const ask = (provider, url, placeholder) =>
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
      placeholder
    );
  return { page, put, ask };
}

const filled = (reply, value) => {
  assert.deepEqual(
    reply.request?.headers,
    [['authorization', `Bearer ${value}`]],
    JSON.stringify(reply.error)
  );
};
const refused = (reply, provider) => {
  assert.equal(reply.error?.code, 'EACCES');
  assert.match(reply.error.message, new RegExp(`sent only to ${provider}'s own endpoints`));
  assert.ok(!JSON.stringify(reply).includes('fake-'));
};

test('NEGATIVE a Cloudflare gateway key with its account and gateway goes only to that tenant', async (t) => {
  const { put, ask } = await ready(t);
  const gw = await put({
    name: 'CF_GATEWAY_KEY',
    value: 'fake-cf-gateway-0701',
    kind: 'model',
    provider: 'cloudflare-ai-gateway',
    settings: { CLOUDFLARE_ACCOUNT_ID: 'acct1', CLOUDFLARE_GATEWAY_ID: 'gw1' },
  });
  const base = 'https://gateway.ai.cloudflare.com/v1';
  filled(
    await ask('cloudflare-ai-gateway', `${base}/acct1/gw1/openai/chat/completions`, gw.placeholder),
    'fake-cf-gateway-0701'
  );
  refused(
    await ask('cloudflare-ai-gateway', `${base}/acct2/gw1/openai/chat/completions`, gw.placeholder),
    'cloudflare-ai-gateway'
  );
  refused(
    await ask('cloudflare-ai-gateway', `${base}/acct1/gw2/anthropic/v1/messages`, gw.placeholder),
    'cloudflare-ai-gateway'
  );
  const workers = await put({
    name: 'CF_WORKERS_KEY',
    value: 'fake-cf-workers-0702',
    kind: 'model',
    provider: 'cloudflare-workers-ai',
    settings: { CLOUDFLARE_ACCOUNT_ID: 'acct1' },
  });
  filled(
    await ask(
      'cloudflare-workers-ai',
      'https://api.cloudflare.com/client/v4/accounts/acct1/ai/v1/chat/completions',
      workers.placeholder
    ),
    'fake-cf-workers-0702'
  );
  refused(
    await ask(
      'cloudflare-workers-ai',
      'https://api.cloudflare.com/client/v4/accounts/acct9/ai/v1/chat/completions',
      workers.placeholder
    ),
    'cloudflare-workers-ai'
  );
});

test('NEGATIVE an Azure key with its resource goes only to that resource', async (t) => {
  const { put, ask } = await ready(t);
  const azure = await put({
    name: 'AZURE_OPENAI_API_KEY',
    value: 'fake-azure-0703',
    kind: 'model',
    provider: 'azure',
    settings: { AZURE_OPENAI_RESOURCE_NAME: 'Mine' },
  });
  filled(
    await ask(
      'azure',
      'https://mine.openai.azure.com/openai/v1/chat/completions',
      azure.placeholder
    ),
    'fake-azure-0703'
  );
  filled(
    await ask(
      'azure',
      'https://mine.services.ai.azure.com/models/chat/completions',
      azure.placeholder
    ),
    'fake-azure-0703'
  );
  filled(
    await ask(
      'azure',
      'https://mine.cognitiveservices.azure.com/openai/v1/chat/completions',
      azure.placeholder
    ),
    'fake-azure-0703'
  );
  for (const url of [
    'https://other.openai.azure.com/openai/v1/chat/completions',
    'https://other.services.ai.azure.com/models/chat/completions',
    'https://other.cognitiveservices.azure.com/openai/v1/chat/completions',
  ]) {
    refused(await ask('azure', url, azure.placeholder), 'azure');
  }
});

test('a key without tenant settings keeps reaching any tenant, and new settings rebind it without its value', async (t) => {
  const { page, put, ask } = await ready(t);
  const loose = await put({
    name: 'AZURE_LOOSE_KEY',
    value: 'fake-azure-loose-0704',
    kind: 'model',
    provider: 'azure',
  });
  filled(
    await ask('azure', 'https://anyone.openai.azure.com/openai/v1/chat', loose.placeholder),
    'fake-azure-loose-0704'
  );
  const rebound = await put({
    name: 'AZURE_LOOSE_KEY',
    kind: 'model',
    provider: 'azure',
    settings: { AZURE_OPENAI_RESOURCE_NAME: 'mine' },
  });
  assert.equal(rebound.placeholder, loose.placeholder);
  refused(
    await ask('azure', 'https://anyone.openai.azure.com/openai/v1/chat', loose.placeholder),
    'azure'
  );
  filled(
    await ask('azure', 'https://mine.openai.azure.com/openai/v1/chat', loose.placeholder),
    'fake-azure-loose-0704'
  );
  const missing = await page.evaluate(() =>
    window.harness.call('put', {
      name: 'NO_SUCH_KEY',
      kind: 'model',
      settings: { AZURE_OPENAI_RESOURCE_NAME: 'x' },
    })
  );
  assert.equal(missing.error.code, 'ENOENT');
  const secret = await page.evaluate(() => window.harness.call('put', { name: 'NO_VALUE' }));
  assert.equal(secret.error.code, 'EINVAL');
});
