import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { createNodeKernel } from '@ai-ecoverse/slicc-kernel/node';
import { attest, CONFIG, config, POLICY } from './attest.mjs';
import { setup } from './setup.mjs';

const { embedder } = await setup();

const VALUES = {
  ANY_KEY: 'fake-value-any-0401',
  GH_TOKEN: 'fake-value-gh-0402',
  SHELL_KEY: 'fake-value-shell-0403',
  SCRIPT_KEY: 'fake-value-script-0404',
};
const POLICY_TEXT = `[exec]
ANY_KEY = true
GH_TOKEN = { argv = [["/usr/bin/printenv", "GH_TOKEN"], ["/usr/local/bin/show.sh"]] }
SHELL_KEY = { shell = true }
SCRIPT_KEY = { argv = [["/usr/local/bin/run.sh"], ["/tmp/run.sh"]] }
`;
const modules = new URL('../../node_modules/@ai-ecoverse/', import.meta.url);
const BOOK = `book() {
  exec 3<>/dev/sealed
  printf '%s' "$REQ" >&3
  R=$(cat <&3)
  exec 3>&-
  [[ $R =~ \\"ticket\\":\\"([0-9a-f]{32})\\" ]] && T=\${BASH_REMATCH[1]}
  printf '%s\\n' "$R" >&2
}
( book; SLICC_SEALED_TICKET=$T exec "$@" )
`;

async function install(kernel, name) {
  const base = new URL(`${name}/`, modules);
  const entries = await readdir(base, { recursive: true, withFileTypes: true });
  for (const entry of entries.filter((e) => e.isFile())) {
    const file = join(entry.parentPath, entry.name);
    await kernel.writeFile(
      `/node_modules/@ai-ecoverse/${name}/${relative(fileURLToPath(base), file)}`,
      await readFile(file)
    );
  }
}

async function vault(t) {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.connect());
  const placeholders = {};
  for (const [name, value] of Object.entries(VALUES)) {
    placeholders[name] = (
      await page.evaluate(
        (n, v) => window.harness.sealed({ v: 1, op: 'seal', name: n, value: v }),
        name,
        value
      )
    ).placeholder;
  }
  const reply = await page.evaluate(
    (files) => window.harness.policy(files),
    [attest(CONFIG, config(placeholders, [])), attest(POLICY, POLICY_TEXT)]
  );
  assert.equal(reply.accepted, true);
  return { page, placeholders };
}

async function kernelFor(t, page, users, consumed = []) {
  const sealed = async (req) => {
    const { caller, v, op, ...fields } = req;
    if (op === 'materializeConsume') {
      const reply = await page.evaluate(
        (f) => window.harness.call('materializeConsume', f),
        fields
      );
      consumed.push({
        resolved: fields.resolved,
        trusted: fields.trusted,
        error: reply.error?.message,
      });
      return reply.error ? reply : { values: reply.values, placeholders: reply.placeholders };
    }
    return page.evaluate((r, s) => window.harness.sealed(r, s), { v, op, ...fields }, caller);
  };
  const kernel = await createNodeKernel({ users, sealed });
  t.after(() => kernel.terminate());
  await install(kernel, 'wasm-bash');
  await install(kernel, 'wasm-coreutils');
  const setupScripts = await kernel.run(
    [
      'bash',
      '-c',
      `mkdir -p /usr/local/bin
printf '#!/usr/bin/bash\\nprintf %%s "$SCRIPT_KEY" > "$1"\\n' > /usr/local/bin/run.sh
printf '#!/usr/bin/bash\\nprintf %%s "$GH_TOKEN" > "$1"\\nprintf "%%s\\\\n" "$GH_TOKEN"\\n' > /usr/local/bin/show.sh
cp /usr/local/bin/run.sh /tmp/run.sh
chmod 755 /usr/local/bin/run.sh /usr/local/bin/show.sh /tmp/run.sh
ln -s /usr/bin/bash /tmp/l`,
    ],
    { cwd: '/' }
  );
  assert.equal(setupScripts.status, 0, setupScripts.stderr);
  return kernel;
}

function spawn(kernel, placeholders, names, argv, booked = argv) {
  const env = {
    REQ: JSON.stringify({
      v: 1,
      op: 'materialize',
      names,
      path: booked[0],
      argv: booked,
      cwd: '/',
    }),
  };
  for (const name of names) env[name] = placeholders[name];
  return kernel.run(['bash', '-c', BOOK, 'bash', ...argv], { cwd: '/', env });
}

const audited = async (page, name) =>
  (await page.evaluate(() => window.harness.call('audit', { limit: 50 }))).audit.find(
    (e) => e.type === 'materialize' && e.name === name
  );

async function enforced(t) {
  const { page, placeholders } = await vault(t);
  const consumed = [];
  const kernel = await kernelFor(t, page, 'enforce', consumed);
  return { page, placeholders, consumed, kernel };
}

const text = async (kernel, path) => new TextDecoder().decode(await kernel.readFile(path));

test('KS-8: exec true reveals a value to a trusted catalog program', async (t) => {
  const { page, placeholders, kernel } = await enforced(t);
  const plain = await spawn(kernel, placeholders, ['ANY_KEY'], ['/usr/bin/true']);
  assert.equal(plain.status, 0, plain.stderr);
  assert.equal((await audited(page, 'ANY_KEY')).consumed, true);
});

test('KS-8: an argv grant reveals the value, and S2 shows the placeholder on stdout', async (t) => {
  const { page, placeholders, consumed, kernel } = await enforced(t);
  const shown = await spawn(
    kernel,
    placeholders,
    ['GH_TOKEN'],
    ['/usr/local/bin/show.sh', '/tmp/shown']
  );
  assert.equal(shown.status, 0, shown.stderr);
  assert.equal(shown.stdout, `${placeholders.GH_TOKEN}\n`);
  assert.equal(await text(kernel, '/tmp/shown'), VALUES.GH_TOKEN);
  assert.deepEqual([consumed.length, consumed[0].error], [1, undefined]);
  assert.equal((await audited(page, 'GH_TOKEN')).consumed, true);
});

test('KS-8: a shell grant swaps the value in, and S2 scrubs its raw and encoded forms', async (t) => {
  const { placeholders, kernel } = await enforced(t);
  const shell = await spawn(
    kernel,
    placeholders,
    ['SHELL_KEY'],
    [
      '/usr/bin/bash',
      '-c',
      'printf %s "$SHELL_KEY" > /tmp/shell; printf %s "$SHELL_KEY" | base64; printf "%s\\n" "$SHELL_KEY"',
    ]
  );
  assert.equal(shell.status, 0, shell.stderr);
  assert.equal(shell.stdout, `[redacted:SHELL_KEY]\n${placeholders.SHELL_KEY}\n`);
  assert.equal(await text(kernel, '/tmp/shell'), VALUES.SHELL_KEY);
});

test('KS-8: an argv grant reveals the value to a trusted script, not to its untrusted copy', async (t) => {
  const { placeholders, consumed, kernel } = await enforced(t);
  const trusted = await spawn(
    kernel,
    placeholders,
    ['SCRIPT_KEY'],
    ['/usr/local/bin/run.sh', '/tmp/script-out']
  );
  assert.equal(trusted.status, 0, trusted.stderr);
  assert.equal(await text(kernel, '/tmp/script-out'), VALUES.SCRIPT_KEY);
  const copy = await spawn(kernel, placeholders, ['SCRIPT_KEY'], ['/tmp/run.sh', '/tmp/copy-out']);
  assert.equal(copy.status, 126);
  assert.match(copy.stderr, /"ticket":"[0-9a-f]{32}"/);
  assert.equal(consumed.at(-1).trusted, false);
  assert.match(consumed.at(-1).error, /can be changed by a non-root user/);
  assert.equal(await kernel.readFile('/tmp/copy-out').catch(() => null), null);
});

test('KS-8: a symlink to bash is refused under exec true, by the program the kernel resolved', async (t) => {
  const { placeholders, consumed, kernel } = await enforced(t);
  const got = await spawn(kernel, placeholders, ['ANY_KEY'], ['/tmp/l', '-c', 'true']);
  assert.equal(got.status, 126);
  assert.match(got.stderr, /"ticket":"[0-9a-f]{32}"/);
  assert.equal(consumed.length, 1);
  assert.equal(consumed[0].resolved, '/usr/bin/bash');
  assert.match(consumed[0].error, /ANY_KEY isn't revealed to \/usr\/bin\/bash/);
});

test('KS-8: an env dumper under exec true gets no ticket', async (t) => {
  const { placeholders, consumed, kernel } = await enforced(t);
  const got = await spawn(kernel, placeholders, ['ANY_KEY'], ['/usr/bin/printenv', 'ANY_KEY']);
  assert.equal(got.status, 126);
  assert.match(got.stderr, /"code":"EACCES".*printenv/);
  assert.equal(consumed.length, 0);
  assert.ok(!got.stdout.includes('fake-value'));
});

test('KS-8: another argv than the booked one is refused by the kernel before any consume', async (t) => {
  const { placeholders, consumed, kernel } = await enforced(t);
  const got = await spawn(
    kernel,
    placeholders,
    ['GH_TOKEN'],
    ['/usr/bin/printenv', 'GH_TOKEN', 'HOME'],
    ['/usr/bin/printenv', 'GH_TOKEN']
  );
  assert.equal(got.status, 126);
  assert.match(got.stderr, /"ticket":"[0-9a-f]{32}"/);
  assert.equal(consumed.length, 0);
});

test('KS-8: with kernel users off nothing is trusted, so exec true reveals nothing', async (t) => {
  const { page, placeholders } = await vault(t);
  const consumed = [];
  const kernel = await kernelFor(t, page, 'off', consumed);
  const got = await spawn(kernel, placeholders, ['ANY_KEY'], ['/usr/bin/true']);
  assert.equal(got.status, 126);
  assert.deepEqual([consumed[0].trusted, /non-root user/.test(consumed[0].error)], [false, true]);
});

test('KS-8: with kernel users off a shell grant still swaps the value in', async (t) => {
  const { page, placeholders } = await vault(t);
  const kernel = await kernelFor(t, page, 'off');
  const shell = await spawn(
    kernel,
    placeholders,
    ['SHELL_KEY'],
    ['/usr/bin/bash', '-c', 'printf %s "$SHELL_KEY" > /tmp/off; printf "%s\\n" "$SHELL_KEY"']
  );
  assert.equal(shell.status, 0, shell.stderr);
  assert.equal(shell.stdout, `${placeholders.SHELL_KEY}\n`);
  assert.equal(await text(kernel, '/tmp/off'), VALUES.SHELL_KEY);
});
