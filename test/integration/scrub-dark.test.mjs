import assert from 'node:assert/strict';
import { request } from 'node:http';
import { test } from 'node:test';
import { setup } from './setup.mjs';

const { served, chrome } = await setup();

function get(url) {
  const target = new URL(url);
  return new Promise((resolve, reject) => {
    const req = request(
      {
        host: '127.0.0.1',
        port: target.port,
        path: target.pathname,
        method: 'GET',
        headers: { host: target.host },
      },
      (response) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () =>
          resolve({
            status: response.statusCode,
            csp: response.headers['content-security-policy'],
            body: Buffer.concat(chunks),
          })
        );
      }
    );
    req.on('error', reject);
    req.end();
  });
}

test('with an empty mapping, no origin gets an answer and frame-ancestors is none', async (t) => {
  assert.equal(served.state.config, null);
  const headers = await get(`${served.vault}/scrub.html`);
  assert.equal(headers.status, 200);
  assert.match(headers.csp, /frame-ancestors 'none'/);
  const page = await chrome.page(t);
  await page.goto(`${served.origin('pilot')}/pilot.html?vault=${encodeURIComponent(served.vault)}`);
  await page.until(() => document.title === 'ready');
  const welcome = await page.evaluate(() => window.harness.mount({ timeout: 1500 }));
  assert.equal(welcome.welcome, null);
  for (const host of ['seven', 'preview', 'evil']) {
    const tab = await chrome.page(t);
    await tab.goto(`${served.origin(host)}/?vault=${encodeURIComponent(served.vault)}`);
    await tab.until(() => document.title === 'ready');
    const seen = await tab.evaluate(async (vault) => {
      const iframe = document.createElement('iframe');
      iframe.src = `${vault}/scrub.html`;
      document.body.append(iframe);
      await new Promise((resolve) => iframe.addEventListener('load', resolve, { once: true }));
      const channel = new MessageChannel();
      const replies = [];
      channel.port1.onmessage = (event) => replies.push(event.data);
      iframe.contentWindow.postMessage({ type: 'slicc-vault', v: 1, op: 'scrub' }, vault, [
        channel.port2,
      ]);
      await new Promise((resolve) => setTimeout(resolve, 1000));
      return replies;
    }, served.vault);
    assert.deepEqual(seen, [], host);
  }
});
