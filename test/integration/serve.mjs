import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import { createServer } from 'node:http';
import { extname, join, normalize, resolve, sep } from 'node:path';
import { argv } from 'node:process';
import { fileURLToPath } from 'node:url';

const site = resolve(fileURLToPath(new URL('../../dist/site/', import.meta.url)));
const page = resolve(fileURLToPath(new URL('./page/', import.meta.url)));

const types = {
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
};

export const EMBEDDERS = ['http://seven.sliccy.localhost:*', 'http://preview.sliccy.localhost:*'];

export function vaultHeaders(embedders = EMBEDDERS) {
  return {
    'content-security-policy': [
      "default-src 'none'",
      "script-src 'self' 'wasm-unsafe-eval'",
      "style-src 'self'",
      "img-src 'self' data:",
      "font-src 'self'",
      "connect-src 'self' https: http://localhost:* http://127.0.0.1:*",
      "worker-src 'self'",
      "manifest-src 'self'",
      "base-uri 'none'",
      "form-action 'none'",
      `frame-ancestors ${embedders.join(' ') || "'none'"}`,
    ].join('; '),
    'cross-origin-embedder-policy': 'require-corp',
    'cross-origin-resource-policy': 'same-site',
    'cross-origin-opener-policy': 'same-origin',
    'origin-agent-cluster': '?1',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'cache-control': 'no-cache',
  };
}

export const pageHeaders = {
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-embedder-policy': 'require-corp',
  'cross-origin-resource-policy': 'same-origin',
  'cache-control': 'no-cache',
};

function locate(root, pathname) {
  const rel = pathname.endsWith('/') ? `${pathname}index.html` : pathname;
  const file = join(root, normalize(rel));
  return file.startsWith(`${root}${sep}`) ? file : null;
}

export async function serveVault({ port = 0, embedders = EMBEDDERS, frameAncestors = true } = {}) {
  const state = { embedders, frameAncestors, requests: [] };
  const server = createServer(async (request, response) => {
    const url = new URL(request.url, 'http://localhost');
    const host = (request.headers.host ?? '').split(':')[0];
    const vault = host.startsWith('vault.');
    state.requests.push(`${host}${url.pathname}`);
    const headers = vault
      ? vaultHeaders(state.frameAncestors ? state.embedders : ['*'])
      : pageHeaders;
    if (vault && url.pathname === '/embedders.json') {
      const body = JSON.stringify({ embedders: state.embedders });
      return response.writeHead(200, { ...headers, 'content-type': types['.json'] }).end(body);
    }
    const file = locate(vault ? site : page, decodeURIComponent(url.pathname));
    const info = file ? await stat(file).catch(() => null) : null;
    if (!info?.isFile()) return response.writeHead(404, headers).end();
    response.writeHead(200, {
      ...headers,
      'content-type': types[extname(file)] ?? 'application/octet-stream',
      'content-length': info.size,
    });
    createReadStream(file).pipe(response);
  });
  await new Promise((done) => server.listen(port, '127.0.0.1', done));
  const bound = server.address().port;
  return {
    state,
    port: bound,
    vault: `http://vault.sliccy.localhost:${bound}`,
    origin: (name) => `http://${name}.sliccy.localhost:${bound}`,
    close: () =>
      new Promise((done) => {
        server.close(done);
        server.closeAllConnections();
      }),
  };
}

if (argv[1] === fileURLToPath(import.meta.url)) {
  const served = await serveVault({ port: Number(argv[2] ?? 8790) });
  console.log(`vault:    ${served.vault}/`);
  console.log(`embedder: ${served.origin('seven')}/?vault=${encodeURIComponent(served.vault)}`);
}
