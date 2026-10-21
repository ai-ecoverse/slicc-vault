import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { test } from 'node:test';

const root = new URL('../../', import.meta.url);
const json = async (name) => JSON.parse(await readFile(new URL(name, root), 'utf8'));

async function sources(dir) {
  const entries = await readdir(new URL(dir, root), { withFileTypes: true, recursive: true });
  return Promise.all(
    entries
      .filter((e) => e.isFile() && /\.ts$/.test(e.name))
      .map((e) => readFile(new URL(`${e.parentPath}/${e.name}`, 'file://'), 'utf8'))
  );
}

test('our packages bundled into the site are dependencies, and nothing else of ours is', async () => {
  const pkg = await json('package.json');
  const imported = new Set();
  for (const text of await sources('src/')) {
    for (const [, name] of text.matchAll(/from '(@ai-ecoverse\/[a-z0-9-]+)/g)) imported.add(name);
  }
  assert.ok(imported.size > 0);
  assert.deepEqual(Object.keys(pkg.dependencies).sort(), [...imported].sort());
  for (const name of imported) assert.equal(pkg.devDependencies[name], undefined);
});
