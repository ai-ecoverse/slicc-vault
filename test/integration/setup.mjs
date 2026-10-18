import { env } from 'node:process';
import { after } from 'node:test';
import { launch } from '@ai-ecoverse/slicc-shared-web/harness';
import { serveVault } from './serve.mjs';

export async function setup(options = {}) {
  const served = await serveVault(options);
  const coverage = env.SLICC_COVERAGE ? ['/'] : [];
  const chrome = await launch({ roots: [['/', 'test/integration/page/']], coverage });
  after(async () => {
    await chrome.close();
    await served.close();
  });
  async function embedder(t, name = 'seven', page = null) {
    const tab = page ?? (await chrome.page(t));
    await tab.goto(`${served.origin(name)}/?vault=${encodeURIComponent(served.vault)}`);
    await tab.until(() => document.title === 'ready');
    return tab;
  }
  return { served, chrome, embedder };
}
