import { readFile } from 'node:fs/promises';
import { connect } from '@ai-ecoverse/slicc-shared-web/harness';

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function session(cdp, sessionId) {
  const send = (method, params = {}) => cdp.send(method, params, sessionId, 30000);
  async function evaluate(fn, ...args) {
    const { result, exceptionDetails } = await send('Runtime.evaluate', {
      expression: `(${fn})(...${JSON.stringify(args)})`,
      awaitPromise: true,
      returnByValue: true,
    });
    if (exceptionDetails)
      throw new Error(exceptionDetails.exception?.description ?? exceptionDetails.text);
    return result.value;
  }
  async function until(fn, ...args) {
    const deadline = Date.now() + 20000;
    let last;
    while (Date.now() < deadline) {
      last = await evaluate(fn, ...args).catch((error) => error.message);
      if (last && typeof last !== 'string') return last;
      if (last === true || (typeof last === 'string' && !last.includes('Error'))) return last;
      await sleep(50);
    }
    throw new Error(`timed out waiting for ${fn}: ${JSON.stringify(last)}`);
  }
  return { sessionId, send, evaluate, until };
}

async function activePort(profile) {
  for (let tries = 0; ; tries++) {
    const text = await readFile(`${profile}/DevToolsActivePort`, 'utf8').catch(() => '');
    const [port, path] = text.trim().split('\n');
    if (port && path) return { port, path };
    if (tries > 100) throw new Error('no DevToolsActivePort');
    await sleep(50);
  }
}

export async function browser(chrome) {
  const { port, path } = await activePort(chrome.profile);
  const cdp = await connect(`ws://127.0.0.1:${port}${path}`);
  const used = new Set();
  async function target(pattern, ms = 15000) {
    const deadline = Date.now() + ms;
    while (Date.now() < deadline) {
      const { targetInfos } = await cdp.send('Target.getTargets');
      const found = targetInfos.find((info) => pattern.test(info.url) && !used.has(info.targetId));
      if (found) {
        used.add(found.targetId);
        const { sessionId } = await cdp.send('Target.attachToTarget', {
          targetId: found.targetId,
          flatten: true,
        });
        const attached = session(cdp, sessionId);
        await attached.send('Runtime.enable');
        return Object.assign(attached, { targetId: found.targetId, url: found.url });
      }
      await sleep(50);
    }
    throw new Error(`no target matches ${pattern}`);
  }
  async function targets(pattern) {
    const { targetInfos } = await cdp.send('Target.getTargets');
    return targetInfos.filter((info) => pattern.test(info.url));
  }
  return { cdp, target, targets, close: () => cdp.close() };
}

export async function click(page, selector) {
  const box = await page.evaluate((query) => {
    const rect = document.querySelector(query).getBoundingClientRect();
    return { x: rect.x + rect.width / 2, y: rect.y + rect.height / 2 };
  }, selector);
  await page.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: box.x, y: box.y });
  await page.send('Input.dispatchMouseEvent', {
    type: 'mousePressed',
    x: box.x,
    y: box.y,
    button: 'left',
    clickCount: 1,
  });
  await page.send('Input.dispatchMouseEvent', {
    type: 'mouseReleased',
    x: box.x,
    y: box.y,
    button: 'left',
    clickCount: 1,
  });
}

export async function openPopup(cdp, page, intent, label) {
  const exists = await page.evaluate(() => document.getElementById('button') !== null);
  const before = await page.evaluate(() => window.harness.buttonEvents.length);
  if (exists) await page.evaluate((config) => window.harness.configure(config), { intent });
  else await page.evaluate((config) => window.harness.button(config), { intent });
  await page
    .within(
      15000,
      (from, text) =>
        window.harness.buttonEvents
          .slice(text === null ? 0 : from)
          .some((e) => e.event === 'label' && (text === null || e.label === text)) &&
        document.getElementById('button')?.width > 0,
      before,
      label ?? null
    )
    .catch(async (error) => {
      const state = await page.evaluate(() => [
        window.harness.buttonEvents,
        document.getElementById('button')?.width,
      ]);
      throw new Error(`${error.message}\nbutton: ${JSON.stringify(state)}`);
    });
  for (let attempt = 0; ; attempt++) {
    const clicks = await page.evaluate(() => window.harness.buttonEvents.length);
    await click(page, '#button');
    const opened = await page
      .within(
        5000,
        (from) => window.harness.buttonEvents.slice(from).find((e) => e.event === 'popup'),
        clicks
      )
      .catch(() => null);
    if (opened?.state === 'opened' || attempt === 2) break;
  }
  const popup = await cdp.target(/\/popup\.html#[0-9a-f]{32}$/);
  await popup.until(() => document.querySelector('main h1') !== null);
  return popup;
}

export async function press(popup, label) {
  await popup.until(
    (text) => [...document.querySelectorAll('button')].some((b) => b.textContent === text),
    label
  );
  await popup.evaluate((text) => {
    [...document.querySelectorAll('button')].find((b) => b.textContent === text).click();
  }, label);
}

export async function typeInto(popup, selector, text) {
  await popup.until((query) => document.querySelector(query) !== null, selector);
  await popup.evaluate((query) => document.querySelector(query).focus(), selector);
  await popup.send('Input.insertText', { text });
}
