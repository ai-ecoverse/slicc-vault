import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { chmod, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { load } from 'js-yaml';

const dir = new URL('../../.github/workflows/', import.meta.url);
const RELEASING =
  /semantic-release|npm publish|npm\s+dist-tag|gh release|git tag|git push[^\n]*--tags|edge\/publish\.mjs/;

async function workflows() {
  const names = (await readdir(dir)).filter((name) => /\.ya?ml$/.test(name));
  return Promise.all(
    names.map(async (name) => ({
      name,
      doc: load(await readFile(new URL(name, dir), 'utf8')),
    }))
  );
}

const named = async (name) => (await workflows()).find((w) => w.name === name).doc;

const script = (job) =>
  (job.steps ?? []).map((step) => `${step.run ?? ''} ${step.uses ?? ''}`).join('\n');

test('the only workflows are the CI caller and the branch preview', async () => {
  assert.deepEqual((await workflows()).map((w) => w.name).sort(), ['ci.yml', 'deploy.yml']);
});

test('only main releases: the pipeline releases and deploys vault.sliccy.ai, and the preview publishes only branches', async () => {
  const seen = [];
  for (const { name, doc } of await workflows()) {
    for (const [id, job] of Object.entries(doc.jobs ?? {})) {
      if (!RELEASING.test(script(job))) continue;
      seen.push(`${name}:${id}`);
    }
  }
  assert.deepEqual(seen, ['deploy.yml:preview']);
  const deploy = await named('deploy.yml');
  assert.deepEqual(deploy.on, { push: { 'branches-ignore': ['main', 'gh-readonly-queue/**'] } });
  const { preview } = deploy.jobs;
  assert.equal(preview.if, undefined);
  assert.equal(preview.environment, undefined);
  assert.deepEqual(preview.permissions, { contents: 'read', 'id-token': 'write' });
  assert.doesNotMatch(script(preview), /semantic-release|npm publish|gh release|git tag/);
  const { ci } = (await named('ci.yml')).jobs;
  assert.equal(ci.with['release-environment'], 'production');
  assert.match(ci.with['after-release'], /^set -eo pipefail\n/);
  assert.match(
    ci.with['after-release'],
    /export VAULT_VERSION="\$RELEASE_VERSION"\nnpm run build\n/
  );
  assert.match(ci.with['after-release'], /node edge\/publish\.mjs/);
  assert.equal(ci.with.deploy, undefined);
});

test('CI is the shared pipeline at the slicc-shared-web version in package.json', async () => {
  const ci = await named('ci.yml');
  const pkg = JSON.parse(await readFile(new URL('../../package.json', import.meta.url), 'utf8'));
  assert.equal(ci.name, 'CI');
  assert.ok('merge_group' in ci.on);
  assert.ok('pull_request' in ci.on);
  assert.deepEqual(ci.on.push, { branches: ['main'] });
  assert.deepEqual(Object.keys(ci.jobs), ['ci']);
  const { ci: job } = ci.jobs;
  const version = pkg.devDependencies['@ai-ecoverse/slicc-shared-web'];
  assert.equal(job.uses, `ai-ecoverse/slicc-shared-web/.github/workflows/pipeline.yml@v${version}`);
  assert.equal(job.secrets, 'inherit');
  assert.equal(job.with['runs-on'], undefined);
  assert.equal(job.with['test-glob'], 'test/integration/*.test.mjs');
  assert.match(pkg.scripts.test, /'test\/integration\/\*\.test\.mjs'/);
  assert.deepEqual(ci.permissions, {
    contents: 'write',
    actions: 'read',
    issues: 'write',
    'pull-requests': 'write',
    statuses: 'write',
    'id-token': 'write',
    attestations: 'write',
  });
  assert.equal(ci.concurrency['cancel-in-progress'], "${{ github.event_name == 'pull_request' }}");
  assert.equal(pkg.fledgling.workflow, 'ci.yml');
  assert.match(pkg.scripts.pretest, /slicc-cdp install-browser/);
  assert.doesNotMatch(JSON.stringify(pkg), /playwright|xvfb/);
});

test('no workflow names a self-hosted runner label', async () => {
  const names = (await readdir(dir)).filter((name) => /\.ya?ml$/.test(name));
  for (const name of names) {
    const text = await readFile(new URL(name, dir), 'utf8');
    assert.doesNotMatch(text, /cloud-run-(bench|job)/, name);
  }
});

test('semantic-release publishes to npm without a repository variable', async () => {
  const { default: config } = await import('../../release.config.mjs');
  assert.deepEqual(config.branches, ['main']);
  assert.ok(config.plugins.includes('@semantic-release/npm'));
});

async function step(t, run, publish, flags) {
  const bin = await mkdtemp(join(tmpdir(), 'slicc-vault-step-'));
  t.after(() => rm(bin, { recursive: true, force: true }));
  await writeFile(
    join(bin, 'npm'),
    '#!/bin/sh\necho "built $VAULT_VERSION" >> "$GITHUB_STEP_SUMMARY"\n'
  );
  await writeFile(join(bin, 'node'), `#!/bin/sh\n${publish}\n`);
  await chmod(join(bin, 'npm'), 0o755);
  await chmod(join(bin, 'node'), 0o755);
  const summary = join(bin, 'summary.md');
  const env = {
    PATH: `${bin}:/usr/bin:/bin`,
    GITHUB_STEP_SUMMARY: summary,
    RELEASE_VERSION: '1.2.3',
  };
  return new Promise((resolve) => {
    execFile('bash', ['--noprofile', '--norc', ...flags, '-c', run], { env }, async (error) =>
      resolve({
        code: error ? error.code : 0,
        summary: await readFile(summary, 'utf8').catch(() => ''),
      })
    );
  });
}

test('a publish fails unless edge/publish.mjs prints its verdict, even when it exits 0', async (t) => {
  const preview = (await named('deploy.yml')).jobs.preview.steps.find((s) =>
    /edge\/publish\.mjs/.test(s.run ?? '')
  );
  assert.equal(preview.shell, 'bash');
  const release = (await named('ci.yml')).jobs.ci.with['after-release'];
  const runs = [
    ['preview', preview.run, ['-eo', 'pipefail']],
    ['after-release', release, []],
  ];
  for (const [name, run, flags] of runs) {
    const code = async (publish) => (await step(t, run, publish, flags)).code;
    const pass = 'echo "publish: PASS https://vault.sliccy.ai/ abc123"';
    assert.equal(await code(pass), 0, `${name}: a verdict passes`);
    assert.notEqual(await code('exit 0'), 0, `${name}: silence fails`);
    assert.notEqual(await code('echo published'), 0, `${name}: no verdict fails`);
    assert.notEqual(await code('echo "publish: PASS  abc123"'), 0, `${name}: an empty URL fails`);
    const plain = 'echo "publish: PASS http://vault.sliccy.ai/ abc123"';
    assert.notEqual(await code(plain), 0, `${name}: a non-https URL fails`);
    assert.notEqual(await code(`${pass}; exit 1`), 0, `${name}: an error fails`);
  }
  const built = await step(t, release, 'echo "publish: PASS https://vault.sliccy.ai/ abc123"', []);
  assert.match(built.summary, /^built 1\.2\.3$/m, 'after-release builds with the release version');
});
