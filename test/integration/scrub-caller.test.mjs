import assert from 'node:assert/strict';
import { test } from 'node:test';
import { scrubSetup } from './scrub-harness.mjs';

const { served, chrome, pilot, seven } = await scrubSetup();

async function silent(page, vault) {
  return page.evaluate(async (target) => {
    const iframe = document.createElement('iframe');
    iframe.src = `${target}/scrub.html`;
    iframe.style.cssText = 'width: 420px; height: 72px; border: 0;';
    document.body.append(iframe);
    await new Promise((resolve) => iframe.addEventListener('load', resolve, { once: true }));
    const channel = new MessageChannel();
    const replies = [];
    channel.port1.onmessage = (event) => replies.push(event.data);
    iframe.contentWindow.postMessage({ type: 'slicc-vault', v: 1, op: 'scrub' }, target, [
      channel.port2,
    ]);
    await new Promise((resolve) => setTimeout(resolve, 1500));
    return replies;
  }, vault);
}

test('seven, www, preview, evil, nested, blank, srcdoc, sandbox, popup, second hello and other path are silent', async (t) => {
  for (const host of ['seven', 'www', 'preview', 'evil']) {
    const page = await chrome.page(t);
    await page.goto(`${served.origin(host)}/?vault=${encodeURIComponent(served.vault)}`);
    await page.until(() => document.title === 'ready');
    assert.deepEqual(await silent(page, served.vault), [], host);
  }
  const page = await chrome.page(t);
  await page.goto(`${served.origin('pilot')}/pilot.html?vault=${encodeURIComponent(served.vault)}`);
  await page.until(() => document.title === 'ready');
  const first = await page.evaluate(() => window.harness.mount());
  assert.equal(first.welcome?.op, 'welcome');
  const second = await page.evaluate(async (vault) => {
    const iframe = window.harness.frames[0].iframe;
    const channel = new MessageChannel();
    const replies = [];
    channel.port1.onmessage = (event) => replies.push(event.data);
    iframe.contentWindow.postMessage({ type: 'slicc-vault', v: 1, op: 'scrub' }, vault, [
      channel.port2,
    ]);
    await new Promise((resolve) => setTimeout(resolve, 1000));
    return replies;
  }, served.vault);
  assert.deepEqual(second, []);
  const nested = await page.evaluate(async (vault) => {
    const shell = document.createElement('iframe');
    shell.src = `${location.origin}/pilot.html?vault=${encodeURIComponent(vault)}`;
    shell.style.cssText = 'width: 480px; height: 120px; border: 0;';
    document.body.append(shell);
    await new Promise((resolve) => shell.addEventListener('load', resolve, { once: true }));
    return shell.contentWindow.eval(`(async () => {
      const inner = document.createElement('iframe');
      inner.src = ${JSON.stringify(vault)} + '/scrub.html';
      document.body.append(inner);
      await new Promise((r) => inner.addEventListener('load', r, { once: true }));
      const channel = new MessageChannel();
      const replies = [];
      channel.port1.onmessage = (e) => replies.push(e.data);
      inner.contentWindow.postMessage(
        { type: 'slicc-vault', v: 1, op: 'scrub' },
        ${JSON.stringify(vault)},
        [channel.port2]
      );
      await new Promise((r) => setTimeout(r, 1000));
      return replies;
    })()`);
  }, served.vault);
  assert.deepEqual(nested, []);
  const blank = await page.evaluate(async (vault) => {
    const shell = document.createElement('iframe');
    shell.src = 'about:blank';
    document.body.append(shell);
    await new Promise((resolve) => shell.addEventListener('load', resolve, { once: true }));
    const inner = shell.contentDocument.createElement('iframe');
    inner.src = `${vault}/scrub.html`;
    shell.contentDocument.body.append(inner);
    await new Promise((resolve) => inner.addEventListener('load', resolve, { once: true }));
    const channel = new MessageChannel();
    const replies = [];
    channel.port1.onmessage = (event) => replies.push(event.data);
    inner.contentWindow.postMessage({ type: 'slicc-vault', v: 1, op: 'scrub' }, vault, [
      channel.port2,
    ]);
    await new Promise((resolve) => setTimeout(resolve, 1000));
    return replies;
  }, served.vault);
  assert.deepEqual(blank, []);
  const srcdoc = await page.evaluate(async (vault) => {
    const shell = document.createElement('iframe');
    shell.srcdoc = '<!doctype html><title>x</title><body></body>';
    document.body.append(shell);
    await new Promise((resolve) => shell.addEventListener('load', resolve, { once: true }));
    const inner = shell.contentDocument.createElement('iframe');
    inner.src = `${vault}/scrub.html`;
    shell.contentDocument.body.append(inner);
    await new Promise((resolve) => inner.addEventListener('load', resolve, { once: true }));
    const channel = new MessageChannel();
    const replies = [];
    channel.port1.onmessage = (event) => replies.push(event.data);
    inner.contentWindow.postMessage({ type: 'slicc-vault', v: 1, op: 'scrub' }, vault, [
      channel.port2,
    ]);
    await new Promise((resolve) => setTimeout(resolve, 1000));
    return replies;
  }, served.vault);
  assert.deepEqual(srcdoc, []);
  const sandboxed = await page.evaluate(async (vault) => {
    const iframe = document.createElement('iframe');
    iframe.sandbox = 'allow-scripts';
    iframe.src = `${vault}/scrub.html`;
    document.body.append(iframe);
    await new Promise((resolve) => iframe.addEventListener('load', resolve, { once: true }));
    const channel = new MessageChannel();
    const replies = [];
    channel.port1.onmessage = (event) => replies.push(event.data);
    try {
      iframe.contentWindow.postMessage({ type: 'slicc-vault', v: 1, op: 'scrub' }, vault, [
        channel.port2,
      ]);
    } catch {
      return [];
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
    return replies;
  }, served.vault);
  assert.deepEqual(sandboxed, []);
  const popup = await page.evaluate(async (vault) => {
    const win = window.open(`${vault}/scrub.html`, 'scrub-popup', 'width=420,height=120');
    if (!win) return null;
    await new Promise((resolve) => {
      const timer = setInterval(() => {
        try {
          if (win.document?.readyState === 'complete') {
            clearInterval(timer);
            resolve();
          }
        } catch {
          clearInterval(timer);
          resolve();
        }
      }, 50);
    });
    const channel = new MessageChannel();
    const replies = [];
    channel.port1.onmessage = (event) => replies.push(event.data);
    try {
      win.postMessage({ type: 'slicc-vault', v: 1, op: 'scrub' }, vault, [channel.port2]);
    } catch {
      win.close();
      return [];
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
    win.close();
    return replies;
  }, served.vault);
  assert.ok(popup === null || popup.length === 0);
  const otherPath = await page.evaluate(async (vault) => {
    const iframe = document.createElement('iframe');
    iframe.src = `${vault}/button.html`;
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
  assert.deepEqual(otherPath, []);
  assert.ok(pilot.startsWith('http://pilot.'));
  assert.ok(seven.startsWith('http://seven.'));
});
