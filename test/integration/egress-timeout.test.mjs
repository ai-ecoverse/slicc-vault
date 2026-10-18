import assert from 'node:assert/strict';
import { test } from 'node:test';
import { setup } from './setup.mjs';

const { embedder } = await setup();

async function connected(t) {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.connect());
  return page;
}

test('a page port that stopped answering egress gets no more, and the next refresh goes to a live one', {
  timeout: 90000,
}, async (t) => {
  const page = await connected(t);
  assert.equal((await page.evaluate(() => window.harness.twin(true, true))).op, 'welcome');
  await page.evaluate(async () => {
    await window.harness.call('seal', {
      name: 'CLOSED_GRANT',
      value: 'fake-refresh-token-0201',
      kind: 'grant',
      source: 'oauth:github',
      oauth: { tokenUrl: 'https://auth.example.com/token', clientId: 'fake-client' },
    });
    await window.harness.call('seal', {
      name: 'CLOSED_TOKEN',
      value: 'fake-access-token-0201',
      source: 'oauth:github',
      refresh: 'CLOSED_GRANT',
      expiresAt: Date.now() + 60000,
    });
    window.harness.egress.answer = {
      status: 200,
      headers: [],
      body: JSON.stringify({
        token_type: 'Bearer',
        access_token: 'fake-access-token-0202',
        expires_in: 3600,
      }),
    };
    window.harness.call('refresh', { name: 'CLOSED_TOKEN' }).then((reply) => {
      window.first = reply;
    });
  });
  let first = null;
  while (!first) {
    await new Promise((resolve) => setTimeout(resolve, 1000));
    first = await page.evaluate(() => window.first ?? null);
  }
  assert.equal(first.error.code, 'ETIMEDOUT');
  const refreshed = await page.evaluate(() =>
    window.harness.call('refresh', { name: 'CLOSED_TOKEN' })
  );
  assert.equal(refreshed.state, 'refreshed');
  const kept = await page.evaluate(async () => {
    const before = window.harness.twinEvents.length;
    const list = await window.harness.call('list', {}, [], window.harness.twins[0]);
    await window.harness.call('seal', {
      name: 'AFTER',
      value: 'fake-after-value-0001',
      source: 'settings',
    });
    await new Promise((resolve) => setTimeout(resolve, 300));
    return { list: Boolean(list.list), events: window.harness.twinEvents.length - before };
  });
  assert.equal(kept.list, true);
  assert.ok(kept.events > 0);
});
