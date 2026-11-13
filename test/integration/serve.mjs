import { createReadStream, realpathSync } from 'node:fs';
import { stat } from 'node:fs/promises';
import { createServer } from 'node:http';
import { extname, join, normalize, resolve, sep } from 'node:path';
import { argv } from 'node:process';
import { fileURLToPath } from 'node:url';
import { contentType, pageHeaders, servedHeaders, vaultHeaders } from '../../scripts/headers.mjs';

const site = resolve(fileURLToPath(new URL('../../dist/site/', import.meta.url)));
const page = resolve(fileURLToPath(new URL('./page/', import.meta.url)));

export { pageHeaders, vaultHeaders };

export const EMBEDDERS = ['http://seven.sliccy.localhost:*', 'http://preview.sliccy.localhost:*'];

function locate(root, pathname) {
  const rel = pathname.endsWith('/') ? `${pathname}index.html` : pathname;
  const file = join(root, normalize(rel));
  return file.startsWith(`${root}${sep}`) ? file : null;
}

export async function serveVault({ port = 0, embedders = EMBEDDERS, frameAncestors = true } = {}) {
  const state = { embedders, frameAncestors, servesEmbedders: true, config: null, requests: [] };
  const server = createServer(async (request, response) => {
    const url = new URL(request.url, 'http://localhost');
    const host = (request.headers.host ?? '').split(':')[0];
    const vault = host.startsWith('vault.');
    state.requests.push(`${host}${url.pathname}`);
    const frames = state.frameAncestors ? state.embedders : ['*'];
    const headers = vault ? vaultHeaders(frames) : pageHeaders;
    if (vault && url.pathname === '/config.json' && state.config) {
      const body = JSON.stringify(state.config);
      return response.writeHead(200, servedHeaders(frames, '.json')).end(body);
    }
    if (vault && url.pathname === '/embedders.json' && !state.servesEmbedders) {
      return response.writeHead(404, headers).end();
    }
    if (vault && url.pathname === '/embedders.json') {
      const body = JSON.stringify({ embedders: state.embedders });
      return response.writeHead(200, servedHeaders(frames, '.json')).end(body);
    }
    const file = locate(vault ? site : page, decodeURIComponent(url.pathname));
    const info = file ? await stat(file).catch(() => null) : null;
    if (!info?.isFile()) return response.writeHead(404, headers).end();
    const sent = vault
      ? servedHeaders(frames, extname(file))
      : { ...pageHeaders, 'content-type': contentType(extname(file)) };
    response.writeHead(200, {
      ...sent,
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

function isMain() {
  try {
    return (
      Boolean(argv[1]) && realpathSync(argv[1]) === realpathSync(fileURLToPath(import.meta.url))
    );
  } catch {
    return false;
  }
}

if (isMain()) {
  const served = await serveVault({ port: Number(argv[2] ?? 8790) });
  console.log(`vault:    ${served.vault}/`);
  console.log(`embedder: ${served.origin('seven')}/?vault=${encodeURIComponent(served.vault)}`);
}
