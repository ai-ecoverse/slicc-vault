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
GH_TOKEN = { argv = [["/usr/bin/printenv", "GH_TOKEN"]] }
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
cp /usr/local/bin/run.sh /tmp/run.sh
chmod 755 /usr/local/bin/run.sh /tmp/run.sh
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

test('KS-8 end to end: the kernel consumes vault tickets, swaps the values in, and scrubs the child', async (t) => {
  const { page, placeholders } = await vault(t);
  const consumed = [];
  const kernel = await kernelFor(t, page, 'enforce', consumed);

  const plain = await spawn(kernel, placeholders, ['ANY_KEY'], ['/usr/bin/true']);
  assert.equal(plain.status, 0, plain.stderr);
  assert.equal((await audited(page, 'ANY_KEY')).consumed, true);

  const shown = await spawn(kernel, placeholders, ['GH_TOKEN'], ['/usr/bin/printenv', 'GH_TOKEN']);
  assert.equal(shown.status, 0, shown.stderr);
  assert.equal(shown.stdout, `${placeholders.GH_TOKEN}\n`);

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
  assert.equal(new TextDecoder().decode(await kernel.readFile('/tmp/shell')), VALUES.SHELL_KEY);

  const trustedScript = await spawn(
    kernel,
    placeholders,
    ['SCRIPT_KEY'],
    ['/usr/local/bin/run.sh', '/tmp/script-out']
  );
  assert.equal(trustedScript.status, 0, trustedScript.stderr);
  assert.equal(
    new TextDecoder().decode(await kernel.readFile('/tmp/script-out')),
    VALUES.SCRIPT_KEY
  );

  const refused = [
    [
      'a symlink to bash under exec true',
      ['ANY_KEY'],
      ['/tmp/l', '-c', 'true'],
      /ANY_KEY isn't revealed to \/usr\/bin\/bash/,
    ],
    [
      'an untrusted copy of the script',
      ['SCRIPT_KEY'],
      ['/tmp/run.sh', '/tmp/copy-out'],
      /can be changed by a non-root user/,
    ],
  ];
  for (const [why, names, argv, reason] of refused) {
    const before = consumed.length;
    const got = await spawn(kernel, placeholders, names, argv);
    assert.equal(got.status, 126, why);
    assert.match(got.stderr, /"ticket":"[0-9a-f]{32}"/, why);
    assert.equal(consumed.length, before + 1, why);
    assert.match(consumed.at(-1).error, reason, why);
    assert.ok(!got.stdout.includes('fake-value'), why);
  }
  assert.deepEqual(consumed.at(-2).resolved, '/usr/bin/bash');
  assert.equal(consumed.at(-1).trusted, false);
  const dumper = await spawn(kernel, placeholders, ['ANY_KEY'], ['/usr/bin/printenv', 'ANY_KEY']);
  assert.equal(dumper.status, 126);
  assert.match(dumper.stderr, /"code":"EACCES".*printenv/);
  const before = consumed.length;
  const wrongArgv = await spawn(
    kernel,
    placeholders,
    ['GH_TOKEN'],
    ['/usr/bin/printenv', 'GH_TOKEN', 'HOME'],
    ['/usr/bin/printenv', 'GH_TOKEN']
  );
  assert.equal(wrongArgv.status, 126);
  assert.match(wrongArgv.stderr, /"ticket":"[0-9a-f]{32}"/);
  assert.equal(consumed.length, before);
  assert.equal(await kernel.readFile('/tmp/copy-out').catch(() => null), null);
});

test('KS-8 end to end: with kernel users off nothing is trusted, so exec true reveals nothing', async (t) => {
  const { page, placeholders } = await vault(t);
  const consumed = [];
  const kernel = await kernelFor(t, page, 'off', consumed);
  const got = await spawn(kernel, placeholders, ['ANY_KEY'], ['/usr/bin/true']);
  assert.equal(got.status, 126);
  assert.deepEqual([consumed[0].trusted, /non-root user/.test(consumed[0].error)], [false, true]);
  const shell = await spawn(
    kernel,
    placeholders,
    ['SHELL_KEY'],
    ['/usr/bin/bash', '-c', 'printf "%s\\n" "$SHELL_KEY"']
  );
  assert.equal(shell.status, 0, shell.stderr);
  assert.equal(shell.stdout, `${placeholders.SHELL_KEY}\n`);
});
