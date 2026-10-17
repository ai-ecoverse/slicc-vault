import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, symlink } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../../', import.meta.url));

async function linked(t) {
  const dir = await mkdtemp(join(tmpdir(), 'slicc-vault-link-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const link = join(dir, 'checkout');
  await symlink(root, link, 'dir');
  return link;
}

function run(script, args, env, until) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [script, ...args], { env, stdio: 'pipe' });
    let out = '';
    const take = (chunk) => {
      out += chunk;
      if (until?.test(out)) child.kill();
    };
    child.stdout.on('data', take);
    child.stderr.on('data', take);
    child.on('exit', (code) => resolve({ code, out }));
  });
}

async function oidcServer(t) {
  const hits = [];
  const server = createServer((req, res) => {
    hits.push(req.url);
    res.writeHead(500).end();
  });
  await new Promise((done) => server.listen(0, '127.0.0.1', done));
  t.after(() => new Promise((done) => server.close(done)));
  return { hits, url: `http://127.0.0.1:${server.address().port}/token` };
}

for (const via of ['the checkout', 'a symlinked checkout']) {
  test(`edge/publish.mjs publishes when run through ${via}`, async (t) => {
    const base = via === 'the checkout' ? root : await linked(t);
    const oidc = await oidcServer(t);
    const env = {
      PATH: process.env.PATH,
      ACTIONS_ID_TOKEN_REQUEST_URL: oidc.url,
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'fake-oidc-request-0001',
    };
    const got = await run(join(base, 'edge/publish.mjs'), [], env);
    assert.equal(oidc.hits.length, 1, got.out);
    assert.match(oidc.hits[0], /audience=https%3A%2F%2Fsliccy\.ai/);
    assert.notEqual(got.code, 0);
    assert.match(got.out, /GitHub's OIDC token: 500/);
  });

  test(`test/integration/serve.mjs serves when run through ${via}`, async (t) => {
    const base = via === 'the checkout' ? root : await linked(t);
    const got = await run(
      join(base, 'test/integration/serve.mjs'),
      ['0'],
      { PATH: process.env.PATH },
      /embedder: http:\/\/seven\.sliccy\.localhost:\d+\//
    );
    assert.match(got.out, /vault: {4}http:\/\/vault\.sliccy\.localhost:\d+\//);
  });
}
