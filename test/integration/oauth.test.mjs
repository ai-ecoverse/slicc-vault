import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { setup } from './setup.mjs';

const { embedder } = await setup();
const read = async (name) =>
  JSON.parse(await readFile(new URL(`./fixtures/${name}`, import.meta.url), 'utf8'));
const { cases } = await read('b4-oauth-refresh-cases.json');
const { expect } = await read('b4-vault-expectations.json');
const LONG = {
  at: 'fake-b4-access-0001',
  rt: 'fake-b4-refresh-01',
  'rt-a': 'fake-b4-refresh-0a',
  'rt-b': 'fake-b4-refresh-0b',
  first: 'fake-b4-first-0001',
  second: 'fake-b4-second-001',
};
const lengthen = (body) =>
  body.replace(/"(at|rt|rt-a|rt-b|first|second)"/g, (_, value) => JSON.stringify(LONG[value]));

async function connected(t) {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.connect());
  return page;
}

const grant = (page, tokenUrl, value = 'fake-b4-rt-000001') =>
  page.evaluate(
    (url, v) =>
      window.harness.call('seal', {
        name: 'B4_GRANT',
        value: v,
        kind: 'grant',
        source: 'oauth:b4',
        oauth: { tokenUrl: url, clientId: 'cid' },
      }),
    tokenUrl,
    value
  );

const token = (page) =>
  page.evaluate(() =>
    window.harness.call('seal', {
      name: 'B4_TOKEN',
      value: 'fake-b4-access-0000',
      source: 'oauth:b4',
      refresh: 'B4_GRANT',
      expiresAt: Date.now() + 60000,
    })
  );

test("B4's token-url cases: the vault seals only https token URLs, and sends jerk-oauth's serialized URL", async (t) => {
  const page = await connected(t);
  for (const entry of cases.filter((c) => c.area === 'token-url')) {
    const sealed = await grant(page, entry.setup.tokenUrl);
    assert.equal(!sealed.error, expect[entry.id].sealed, entry.id);
    if (!expect[entry.id].sealed) continue;
    await token(page);
    const sent = await page.evaluate(async () => {
      window.harness.egress.answer = { error: 'stop here' };
      await window.harness.call('refresh', { name: 'B4_TOKEN' });
      return window.harness.egress.requests.at(-1);
    });
    assert.equal(sent.url, expect[entry.id].url, entry.id);
    assert.equal(
      sent.body,
      'grant_type=refresh_token&refresh_token=fake-b4-rt-000001&client_id=cid',
      entry.id
    );
  }
});

test("B4's token-response and error-echo cases, verbatim and with tokens long enough to seal", async (t) => {
  const page = await connected(t);
  await grant(page, 'https://auth.example/token');
  const replayed = cases.filter((c) => c.setup.response && c.area !== 'rotation');
  for (const entry of replayed) {
    const variants = [['', entry.setup.response.body]];
    const long = lengthen(entry.setup.response.body);
    if (long !== entry.setup.response.body) variants.push(['+long', long]);
    for (const [suffix, body] of variants) {
      await token(page);
      const reply = await page.evaluate(
        (answer) => {
          window.harness.egress.answer = answer;
          return window.harness.call('refresh', { name: 'B4_TOKEN' });
        },
        {
          status: entry.setup.response.status,
          headers: Object.entries(entry.setup.response.headers ?? {}),
          body,
        }
      );
      const got = reply.error
        ? reply.error.message
        : `refreshed ${reply.expiresAt ? 'exp' : 'noexp'}`;
      assert.equal(got, expect[entry.id + suffix], entry.id + suffix);
      assert.ok(!got.includes('TOKMARK7f3a-rt1'), entry.id + suffix);
    }
  }
});

test("B4's rotation cases, live against B4's fake authorization server", async (t) => {
  const server = spawn(process.execPath, [
    new URL('./fixtures/b4-oauth-fake-as.mjs', import.meta.url).pathname,
    '0',
  ]);
  t.after(() => server.kill());
  const base = await new Promise((resolve) =>
    server.stdout.on('data', (chunk) => {
      const found = /http:\/\/127\.0\.0\.1:\d+/.exec(String(chunk));
      if (found) resolve(found[0]);
    })
  );
  const page = await connected(t);
  await page.evaluate(() => {
    window.harness.egress.manual = true;
  });
  const refreshOnce = async () => {
    await page.evaluate(() => {
      window.pending = window.harness.call('refresh', { name: 'B4_TOKEN' });
    });
    await page.until(() => window.harness.egress.held.length === 1);
    const request = await page.evaluate(() => window.harness.egress.requests.at(-1));
    const answer = await fetch(`${base}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: request.body,
    });
    const body = await answer.text();
    await page.evaluate((a) => window.harness.egress.release(a), {
      status: answer.status,
      headers: [['content-type', 'application/json']],
      body,
    });
    return { request, reply: await page.evaluate(() => window.pending) };
  };
  const mode = (query) => fetch(`${base}/rotation/mode?${query}`);
  const outcome = (reply, rotatedTo) =>
    reply.error ? reply.error.message : `refreshed, grant ${rotatedTo}`;

  await mode('rotate=true&live=TOKMARK7f3a-rt1');
  await grant(page, 'https://auth.example/token', 'TOKMARK7f3a-rt1');
  await token(page);
  const rotated = await refreshOnce();
  const second = await refreshOnce();
  assert.equal(outcome(rotated.reply, 'rotated to TOKMARK7f3a-rt2'), expect['rot-rotated']);
  assert.match(second.request.body, /refresh_token=TOKMARK7f3a-rt2/);

  await mode('rotate=true&live=TOKMARK7f3a-rt2');
  await grant(page, 'https://auth.example/token', 'TOKMARK7f3a-rt1');
  await token(page);
  const reused = await refreshOnce();
  assert.equal(outcome(reused.reply), expect['rot-reused']);

  await mode('rotate=false&live=TOKMARK7f3a-rt2');
  await grant(page, 'https://auth.example/token', 'TOKMARK7f3a-rt2');
  await token(page);
  const kept = await refreshOnce();
  await mode('rotate=false&live=TOKMARK7f3a-rt2');
  const again = await refreshOnce();
  assert.equal(outcome(kept.reply, 'kept'), expect['rot-no-new-token']);
  assert.match(again.request.body, /refresh_token=TOKMARK7f3a-rt2/);
});
