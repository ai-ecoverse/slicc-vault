import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import {
  headersDocument,
  PRODUCTION_EMBEDDERS,
  pageHeaders,
  servedHeaders,
} from '../../scripts/headers.mjs';
import { EMBEDDERS, serveVault } from './serve.mjs';

const exec = promisify(execFile);
const root = fileURLToPath(new URL('../../', import.meta.url));
const site = join(root, 'dist/site');

const NAMES = [
  'content-security-policy',
  'cross-origin-embedder-policy',
  'cross-origin-resource-policy',
  'cross-origin-opener-policy',
  'origin-agent-cluster',
  'x-content-type-options',
  'referrer-policy',
  'cache-control',
  'content-type',
];

async function filesUnder(dir, prefix = '') {
  const found = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) found.push(...(await filesUnder(join(dir, entry.name), rel)));
    else found.push(rel);
  }
  return found;
}

function picked(response) {
  return Object.fromEntries(NAMES.map((name) => [name, response.headers.get(name)]));
}

function asServed(headers, embedders, extension) {
  return { ...headers, ...servedHeaders(embedders, extension) };
}

test('the package lists every built site file, and headers.json matches the server', async () => {
  const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
  assert.deepEqual(pkg.files, ['dist/types', 'dist/site', 'dist/headers.json']);
  assert.deepEqual(pkg.exports, { '.': { types: './dist/types/contract.d.ts' } });
  const { stdout } = await exec('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], {
    cwd: root,
  });
  const packed = JSON.parse(stdout);
  const row = Array.isArray(packed) ? packed[0] : packed;
  const listed = new Set(row.files.map((file) => (typeof file === 'string' ? file : file.path)));
  for (const rel of await filesUnder(site)) assert.ok(listed.has(`dist/site/${rel}`), rel);
  assert.ok(listed.has('dist/headers.json'));
  const doc = JSON.parse(await readFile(join(root, 'dist/headers.json'), 'utf8'));
  assert.deepEqual(doc, headersDocument());
  for (const name of [
    'documents',
    'scripts',
    'css',
    'fonts',
    'wasm',
    'config.json',
    'embedders.json',
  ]) {
    assert.ok(doc.classes[name], name);
  }
  assert.deepEqual(doc.embedders, { embedders: [...PRODUCTION_EMBEDDERS] });
  assert.deepEqual(doc.config.embedders, ['https://seven.sliccy.ai']);
  const served = await serveVault();
  const probe = join(site, 'probe-class.wasm');
  try {
    await writeFile(probe, Buffer.from([0]));
    const cases = [
      ['/', 'documents', '.html'],
      ['/index.html', 'documents', '.html'],
      ['/button.html', 'documents', '.html'],
      ['/value.html', 'documents', '.html'],
      ['/popup.html', 'documents', '.html'],
      ['/frame.js', 'scripts', '.js'],
      ['/vault.css', 'css', '.css'],
      ['/fonts/AdobeClean-Regular.woff2', 'fonts', '.woff2'],
      ['/probe-class.wasm', 'wasm', '.wasm'],
      ['/config.json', 'config.json', '.json'],
      ['/embedders.json', 'embedders.json', '.json'],
    ];
    for (const [path, name, extension] of cases) {
      const response = await fetch(`${served.vault}${path}`);
      assert.equal(response.status, 200, path);
      assert.deepEqual(
        picked(response),
        asServed(doc.classes[name].headers, EMBEDDERS, extension),
        path
      );
      for (const extra of Object.keys(doc.productionOnly)) {
        assert.equal(response.headers.get(extra), null, extra);
      }
      await response.arrayBuffer();
    }
    const embedders = await fetch(`${served.vault}/embedders.json`);
    assert.deepEqual(await embedders.json(), { embedders: EMBEDDERS });
    const config = await fetch(`${served.vault}/config.json`);
    const body = await config.json();
    assert.equal(typeof body.version, 'string');
    assert.deepEqual(body.embedders, doc.config.embedders);
    const page = await fetch(`${served.origin('seven')}/`);
    assert.equal(page.status, 200);
    assert.equal(page.headers.get('content-type'), 'text/html; charset=utf-8');
    assert.equal(page.headers.get('cache-control'), pageHeaders['cache-control']);
    assert.equal(
      page.headers.get('cross-origin-resource-policy'),
      pageHeaders['cross-origin-resource-policy']
    );
    assert.equal(page.headers.get('content-security-policy'), null);
    await page.arrayBuffer();
  } finally {
    await rm(probe, { force: true });
    await served.close();
  }
});
