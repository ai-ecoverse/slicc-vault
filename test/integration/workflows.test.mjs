import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { test } from 'node:test';
import yaml from 'js-yaml';

const dir = new URL('../../.github/workflows/', import.meta.url);
const RELEASING =
  /semantic-release|npm publish|npm\s+dist-tag|gh release|git tag|git push[^\n]*--tags|edge\/publish\.mjs/;
const MAIN = "github.ref == 'refs/heads/main'";

async function workflows() {
  const names = (await readdir(dir)).filter((name) => /\.ya?ml$/.test(name));
  return Promise.all(
    names.map(async (name) => ({
      name,
      doc: yaml.load(await readFile(new URL(name, dir), 'utf8')),
    }))
  );
}

const script = (job) =>
  (job.steps ?? []).map((step) => `${step.run ?? ''} ${step.uses ?? ''}`).join('\n');

test('only main releases: every job that publishes, tags or releases runs on main only', async () => {
  const seen = [];
  for (const { name, doc } of await workflows()) {
    for (const [id, job] of Object.entries(doc.jobs ?? {})) {
      if (!RELEASING.test(script(job))) continue;
      const preview = name === 'deploy.yml';
      if (preview) {
        assert.deepEqual(
          doc.on.push,
          { 'branches-ignore': ['main', 'gh-readonly-queue/**'] },
          `${name} ${id}`
        );
        assert.equal(doc.on.workflow_dispatch, undefined, `${name} ${id}`);
        assert.doesNotMatch(
          script(job),
          /semantic-release|npm publish|gh release|git tag/,
          `${name} ${id}`
        );
        assert.equal(job.permissions?.contents, 'read', `${name} ${id}`);
      } else {
        assert.equal(job.if, MAIN, `${name} ${id}`);
      }
      seen.push(`${name}:${id}`);
    }
  }
  assert.deepEqual(seen.sort(), ['deploy.yml:publish', 'release.yml:release']);
});

test('CI runs for the merge queue as well as for pull requests and main', async () => {
  const ci = (await workflows()).find((w) => w.name === 'ci.yml').doc;
  assert.ok('merge_group' in ci.on);
  assert.ok('pull_request' in ci.on);
  assert.deepEqual(ci.on.push, { branches: ['main'] });
  assert.deepEqual(Object.keys(ci.jobs), ['runner', 'ci']);
});

test("CI picks the bench pool only for this repo's own code, and a hosted runner for forks", async () => {
  const ci = (await workflows()).find((w) => w.name === 'ci.yml').doc;
  const { runner, ci: job } = ci.jobs;
  assert.equal(
    runner['runs-on'],
    "${{ vars.CERT_LIGHT_RUNNER || vars.CERT_RUNNER || 'ubuntu-latest' }}"
  );
  assert.equal(job.needs, 'runner');
  assert.equal(job.with['runs-on'], '${{ needs.runner.outputs.runner }}');
  const decide = new Function(
    'context',
    'github',
    'core',
    'process',
    `return (async () => {${runner.steps[0].with.script}})();`
  );
  const run = async (context, entries = []) => {
    let picked;
    const core = {
      setOutput: (_, v) => (picked = v),
      summary: { addRaw: () => ({ write: async () => {} }) },
    };
    const github = {
      graphql: async () => ({ repository: { mergeQueue: { entries: { nodes: entries } } } }),
    };
    const env = { POOL: 'cloud-run-bench' };
    await decide(
      { repo: { owner: 'ai-ecoverse', repo: 'slicc-vault' }, ...context },
      github,
      core,
      { env }
    );
    return picked;
  };
  const pr = (full) => ({
    eventName: 'pull_request',
    payload: { pull_request: { head: { repo: { full_name: full } } } },
  });
  assert.equal(await run(pr('ai-ecoverse/slicc-vault')), 'cloud-run-bench');
  assert.equal(await run(pr('someone/slicc-vault')), 'ubuntu-latest');
  assert.equal(
    await run({ eventName: 'pull_request', payload: { pull_request: { head: { repo: null } } } }),
    'ubuntu-latest'
  );
  const group = {
    eventName: 'merge_group',
    payload: { merge_group: { base_ref: 'refs/heads/main' } },
  };
  assert.equal(
    await run(group, [{ pullRequest: { number: 1, isCrossRepository: false } }]),
    'cloud-run-bench'
  );
  assert.equal(
    await run(group, [{ pullRequest: { number: 1, isCrossRepository: true } }]),
    'ubuntu-latest'
  );
  assert.equal(await run(group, [{ pullRequest: null }]), 'ubuntu-latest');
  assert.equal(await run({ eventName: 'push', ref: 'refs/heads/main' }), 'cloud-run-bench');
  assert.equal(await run({ eventName: 'push', ref: 'refs/heads/x' }), 'ubuntu-latest');
});

test('the release workflow can still be dispatched, but only main gets past its guard', async () => {
  const release = (await workflows()).find((w) => w.name === 'release.yml').doc;
  assert.ok('workflow_dispatch' in release.on);
  assert.deepEqual(release.on.push, { branches: ['main'] });
  assert.equal(release.jobs.release.if, MAIN);
});
