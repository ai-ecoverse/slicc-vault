import assert from 'node:assert/strict';
import { test } from 'node:test';
import { setup } from './setup.mjs';

const { embedder } = await setup();

async function connected(t) {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.connect());
  return page;
}

test('the minute sweep refreshes a due token without being asked', {
  timeout: 120000,
}, async (t) => {
  const page = await connected(t);
  await page.evaluate(async () => {
    await window.harness.call('seal', {
      name: 'SWEPT_GRANT',
      value: 'fake-refresh-token-0301',
      kind: 'grant',
      source: 'oauth:github',
      oauth: { tokenUrl: 'https://auth.example.com/token', clientId: 'fake-client' },
    });
    await window.harness.call('seal', {
      name: 'SWEPT_TOKEN',
      value: 'fake-access-token-0301',
      source: 'oauth:github',
      refresh: 'SWEPT_GRANT',
      expiresAt: Date.now() + 60000,
    });
    window.harness.egress.answer = {
      status: 200,
      headers: [],
      body: JSON.stringify({
        token_type: 'Bearer',
        access_token: 'fake-access-token-0302',
        expires_in: 3600,
      }),
    };
  });
  let sent = 0;
  for (let i = 0; i < 80 && sent === 0; i++) {
    await new Promise((resolve) => setTimeout(resolve, 1000));
    sent = await page.evaluate(() => window.harness.egress.requests.length);
  }
  assert.equal(sent, 1);
  let audit = [];
  for (let i = 0; i < 10 && !audit.some((e) => e.type === 'refresh'); i++) {
    await new Promise((resolve) => setTimeout(resolve, 200));
    audit = (await page.evaluate(() => window.harness.call('audit', { limit: 5 }))).audit;
  }
  assert.ok(audit.some((e) => e.type === 'refresh' && e.name === 'SWEPT_TOKEN'));
});
