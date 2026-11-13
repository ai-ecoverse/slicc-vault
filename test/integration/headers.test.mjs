import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { request } from 'node:http';
import { extname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { CLASSES, headersDocument, PRODUCTION_EMBEDDERS } from '../../scripts/headers.mjs';
import { EMBEDDERS, serveVault } from './serve.mjs';

const exec = promisify(execFile);
const root = fileURLToPath(new URL('../../', import.meta.url));
const site = join(root, 'dist/site');

const PRODUCTION_CSP =
  "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self' https: http://localhost:* http://127.0.0.1:*; worker-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors https://seven.sliccy.ai https://www.sliccy.ai";

const LOCAL_CSP =
  "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self' https: http://localhost:* http://127.0.0.1:*; worker-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors http://seven.sliccy.localhost:* http://preview.sliccy.localhost:*";

const SECURITY = {
  'cross-origin-embedder-policy': 'require-corp',
  'cross-origin-resource-policy': 'same-site',
  'cross-origin-opener-policy': 'same-origin',
  'origin-agent-cluster': '?1',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
};

function classHeaders(csp, cacheControl, type) {
  return {
    'content-security-policy': csp,
    ...SECURITY,
    'cache-control': cacheControl,
    'content-type': type,
  };
}

function get(url) {
  const target = new URL(url);
  return new Promise((resolve, reject) => {
    const req = request(
      {
        host: '127.0.0.1',
        port: target.port,
        path: `${target.pathname}${target.search}`,
        method: 'GET',
        headers: { host: target.host },
      },
      (response) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () => {
          const body = Buffer.concat(chunks);
          resolve({
            status: response.statusCode,
            headers: {
              get(name) {
                const value = response.headers[name.toLowerCase()];
                if (Array.isArray(value)) return value.join(', ');
                return value ?? null;
              },
            },
            json: async () => JSON.parse(body.toString('utf8')),
            arrayBuffer: async () =>
              body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength),
          });
        });
      }
    );
    req.on('error', reject);
    req.end();
  });
}

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

function coveredExtensions() {
  const covered = new Set();
  for (const spec of CLASSES) {
    for (const extension of spec.extensions ?? []) covered.add(extension);
    for (const path of spec.paths ?? []) {
      const extension = extname(path);
      if (extension) covered.add(extension);
    }
  }
  return covered;
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
  const siteFiles = await filesUnder(site);
  for (const rel of siteFiles) assert.ok(listed.has(`dist/site/${rel}`), rel);
  const covered = coveredExtensions();
  for (const rel of siteFiles) assert.ok(covered.has(extname(rel)), rel);
  assert.ok(siteFiles.some((rel) => rel.endsWith('.map')));
  assert.ok(listed.has('dist/headers.json'));
  const doc = JSON.parse(await readFile(join(root, 'dist/headers.json'), 'utf8'));
  assert.deepEqual(doc, headersDocument());
  assert.deepEqual(doc.contentTypes, {
    '.wasm': 'application/wasm',
    '.woff2': 'font/woff2',
    '.js': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.map': 'application/json',
    '.txt': 'text/plain; charset=utf-8',
    '.json': 'application/json',
    '.html': 'text/html; charset=utf-8',
  });
  assert.deepEqual(doc.classes.maps.extensions, ['.map']);
  assert.deepEqual(doc.classes.text.extensions, ['.txt']);
  assert.deepEqual(doc.embedders, { embedders: [...PRODUCTION_EMBEDDERS] });
  assert.deepEqual(doc.config.embedders, ['https://seven.sliccy.ai']);
  const served = await serveVault();
  const probes = [
    join(site, 'probe-class.wasm'),
    join(site, 'probe-class.map'),
    join(site, 'probe-class.txt'),
  ];
  try {
    await writeFile(probes[0], Buffer.from([0]));
    await writeFile(probes[1], Buffer.from('{}'));
    await writeFile(probes[2], Buffer.from('legal\n'));
    const cases = [
      ['/', 'documents', 'no-store', 'text/html; charset=utf-8'],
      ['/index.html', 'documents', 'no-store', 'text/html; charset=utf-8'],
      ['/button.html', 'documents', 'no-store', 'text/html; charset=utf-8'],
      ['/value.html', 'documents', 'no-store', 'text/html; charset=utf-8'],
      ['/popup.html', 'documents', 'no-store', 'text/html; charset=utf-8'],
      ['/frame.js', 'scripts', 'no-cache', 'text/javascript; charset=utf-8'],
      ['/vault.css', 'css', 'no-cache', 'text/css; charset=utf-8'],
      ['/fonts/AdobeClean-Regular.woff2', 'fonts', 'no-cache', 'font/woff2'],
      ['/probe-class.map', 'maps', 'no-cache', 'application/json'],
      ['/probe-class.txt', 'text', 'no-cache', 'text/plain; charset=utf-8'],
      ['/probe-class.wasm', 'wasm', 'no-cache', 'application/wasm'],
      ['/config.json', 'config.json', 'no-cache', 'application/json'],
      ['/embedders.json', 'embedders.json', 'no-cache', 'application/json'],
    ];
    for (const [, name, cache, type] of cases) {
      assert.deepEqual(doc.classes[name].headers, classHeaders(PRODUCTION_CSP, cache, type), name);
    }
    for (const [path, , cache, type] of cases) {
      const response = await get(`${served.vault}${path}`);
      assert.equal(response.status, 200, path);
      assert.deepEqual(picked(response), classHeaders(LOCAL_CSP, cache, type), path);
      for (const extra of Object.keys(doc.productionOnly)) {
        assert.equal(response.headers.get(extra), null, extra);
      }
      await response.arrayBuffer();
    }
    const embedders = await get(`${served.vault}/embedders.json`);
    assert.deepEqual(await embedders.json(), { embedders: EMBEDDERS });
    const config = await get(`${served.vault}/config.json`);
    const body = await config.json();
    assert.equal(typeof body.version, 'string');
    assert.deepEqual(body.embedders, doc.config.embedders);
    const page = await get(`${served.origin('seven')}/`);
    assert.equal(page.status, 200);
    assert.equal(page.headers.get('content-type'), 'text/html; charset=utf-8');
    assert.equal(page.headers.get('cache-control'), 'no-cache');
    assert.equal(page.headers.get('cross-origin-opener-policy'), 'same-origin');
    assert.equal(page.headers.get('cross-origin-embedder-policy'), 'require-corp');
    assert.equal(page.headers.get('cross-origin-resource-policy'), 'same-origin');
    assert.equal(page.headers.get('content-security-policy'), null);
    await page.arrayBuffer();
  } finally {
    await Promise.all(probes.map((probe) => rm(probe, { force: true })));
    await served.close();
  }
});
