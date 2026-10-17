import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
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

test('the verdict line matches exactly what the publish steps grep for, and needs an https URL', async () => {
  const { isMain, publish, verdict } = await import('../../edge/publish.mjs');
  const workflows = await Promise.all(
    ['release.yml', 'deploy.yml'].map((name) =>
      readFile(new URL(`../../.github/workflows/${name}`, import.meta.url), 'utf8')
    )
  );
  const patterns = workflows.map((text) => /grep '(\^publish: PASS [^']*)'/.exec(text)[1]);
  assert.deepEqual(patterns, ['^publish: PASS https://', '^publish: PASS https://']);
  const line = verdict('https://vault.sliccy.ai/', 'abc123');
  assert.equal(line, 'publish: PASS https://vault.sliccy.ai/ abc123');
  assert.ok(line.startsWith(patterns[0].slice(1)));
  for (const bad of ['', undefined, 'http://vault.sliccy.ai/']) {
    assert.throws(() => verdict(bad, 'abc123'), /no https URL/);
  }
  assert.equal(isMain('/no/such/script'), false);
  assert.equal(isMain(undefined), false);
  const dir = await mkdtemp(join(tmpdir(), 'slicc-vault-site-'));
  await writeFile(join(dir, 'index.html'), 'x');
  const answers = { manifest: { files: [] }, put: {}, done: {} };
  const fetcher = async (url, init = {}) => {
    const path = String(url).split('/api/publish/')[1];
    const body =
      path === 'manifest' && init.method === 'PUT'
        ? answers.done
        : path === 'manifest'
          ? answers.manifest
          : answers.put;
    return { ok: true, json: async () => body };
  };
  await assert.rejects(
    publish({ fetcher, token: 'fake-token-0001', dir }),
    /without the published https URL/
  );
  answers.done = { url: 'https://vault.sliccy.ai/' };
  assert.equal(
    await publish({ fetcher, token: 'fake-token-0001', dir }),
    'https://vault.sliccy.ai/'
  );
  await rm(dir, { recursive: true, force: true });
});

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
    assert.doesNotMatch(got.out, /publish: PASS/);
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
