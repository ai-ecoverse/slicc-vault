import assert from 'node:assert/strict';
import { test } from 'node:test';
import { attest, CONFIG, config, POLICY } from './attest.mjs';
import { setup } from './setup.mjs';

const { embedder } = await setup();

const VALUES = {
  NPM_TOKEN: 'fake-value-npm-0001',
  GH_TOKEN: 'fake-value-gh-0002',
  SHELL_KEY: 'fake-value-shell-0003',
  PLAIN_KEY: 'fake-value-plain-0004',
};
const PARENT = { pid: 40, ppid: 1, uid: 1000, gid: 1000, tag: 'cone' };
const CHILD = { pid: 41, ppid: 40, uid: 1000, gid: 1000, tag: 'cone' };

async function ready(t, limits = '') {
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
  const extra = `[exec]
NPM_TOKEN = true
GH_TOKEN = { argv = [["/usr/bin/gh", "release", "upload"]] }
SHELL_KEY = { shell = true }
PLAIN_KEY = { argv = [["/opt/run.sh"], ["/bin/sh"]] }
${limits}`;
  const reply = await page.evaluate(
    (files) => window.harness.policy(files),
    [attest(CONFIG, config(placeholders, [])), attest(POLICY, extra)]
  );
  assert.equal(reply.accepted, true);
  return { page, placeholders };
}

const materialize = (page, fields, stamp = PARENT) =>
  page.evaluate(
    (f, s) => window.harness.sealed({ v: 1, op: 'materialize', ...f }, s),
    fields,
    stamp
  );
const consume = (page, fields) =>
  page.evaluate(
    (f) => window.harness.call('materializeConsume', { interpreters: [], ...f }),
    fields
  );

test('a ticket reveals exactly the exec-enabled values to the child it names', async (t) => {
  const { page, placeholders } = await ready(t);
  const ask = {
    names: ['NPM_TOKEN', 'PLAIN_KEY'],
    path: '/usr/bin/npm',
    argv: ['npm', 'publish'],
    cwd: '/home/cone/pkg',
  };
  const got = await materialize(page, ask);
  assert.match(got.ticket, /^[0-9a-f]{32}$/);
  assert.deepEqual(got.real, { NPM_TOKEN: true, PLAIN_KEY: false });
  assert.ok(got.expiresAt > Date.now());
  assert.ok(!JSON.stringify(got).includes('fake-value'));
  const values = await consume(page, {
    ticket: got.ticket,
    stamp: CHILD,
    path: ask.path,
    argv: ask.argv,
    cwd: ask.cwd,
  });
  assert.deepEqual(values.values, { NPM_TOKEN: VALUES.NPM_TOKEN });
  assert.deepEqual(values.placeholders, { NPM_TOKEN: placeholders.NPM_TOKEN });
  const again = await consume(page, {
    ticket: got.ticket,
    stamp: CHILD,
    path: ask.path,
    argv: ask.argv,
    cwd: ask.cwd,
  });
  assert.equal(again.error.code, 'EACCES');
  const audit = (await page.evaluate(() => window.harness.call('audit', { limit: 1 }))).audit[0];
  assert.deepEqual(
    [
      audit.type,
      audit.name,
      audit.exec,
      audit.path,
      audit.argv,
      audit.cwd,
      audit.pid,
      audit.uid,
      audit.tag,
      audit.consumed,
    ],
    [
      'materialize',
      'NPM_TOKEN',
      'any',
      '/usr/bin/npm',
      'npm publish',
      '/home/cone/pkg',
      40,
      1000,
      'cone',
      true,
    ]
  );
  assert.match(audit.argvSha256, /^[0-9a-f]{64}$/);
});

test('a ticket fails closed for any other child, program, argv or cwd', async (t) => {
  const { page } = await ready(t);
  const ask = {
    names: ['NPM_TOKEN'],
    path: '/usr/bin/npm',
    argv: ['npm', 'publish'],
    cwd: '/w',
    interpreters: [],
  };
  const cases = [
    [{ stamp: { ...CHILD, ppid: 99 } }, "isn't a child"],
    [{ path: '/usr/bin/npx' }, 'another program'],
    [{ argv: ['npm', 'publish', '--force'] }, 'another argv'],
    [{ cwd: '/tmp', interpreters: [] }, 'another cwd'],
    [{ ticket: 'nope' }, 'unknown'],
  ];
  for (const [change, reason] of cases) {
    const got = await materialize(page, ask);
    const fields = {
      ticket: got.ticket,
      stamp: CHILD,
      path: ask.path,
      argv: ask.argv,
      cwd: ask.cwd,
      ...change,
    };
    const refused = await consume(page, fields);
    assert.equal(refused.error.code, 'EACCES', reason);
    assert.ok(refused.error.message.includes(reason), refused.error.message);
    if (change.ticket) continue;
    const burned = await consume(page, { ...fields, ...ask, stamp: CHILD, ticket: got.ticket });
    assert.equal(burned.error.code, 'EACCES');
  }
});

test('shells and interpreters need an exact argv, and shell grants cover every bash', async (t) => {
  const { page } = await ready(t);
  const refused = await materialize(page, {
    names: ['NPM_TOKEN'],
    path: '/bin/bash',
    argv: ['bash', '-c', 'env'],
    cwd: '/',
  });
  assert.equal(refused.error.code, 'EACCES');
  assert.match(refused.error.message, /\/bin\/bash/);
  const viaInterpreter = await materialize(page, {
    names: ['NPM_TOKEN'],
    path: '/home/x/run.js',
    interpreter: '/usr/bin/node',
    argv: ['run.js'],
    cwd: '/',
  });
  assert.equal(viaInterpreter.error.code, 'EACCES');
  const listed = await materialize(page, {
    names: ['GH_TOKEN'],
    path: '/usr/bin/gh',
    argv: ['gh', 'release', 'upload', 'v1'],
    cwd: '/',
  });
  assert.deepEqual(listed.real, { GH_TOKEN: true });
  const unlisted = await materialize(page, {
    names: ['GH_TOKEN'],
    path: '/usr/bin/gh',
    argv: ['gh', 'auth', 'token'],
    cwd: '/',
  });
  assert.deepEqual(unlisted.real, { GH_TOKEN: false });
  const shell = await materialize(page, {
    shellGrants: true,
    path: '/bin/bash',
    argv: ['/bin/bash', '-c', 'ls'],
    cwd: '/',
  });
  assert.deepEqual(shell.real, { SHELL_KEY: true });
  const values = await consume(page, {
    ticket: shell.ticket,
    stamp: CHILD,
    path: '/bin/bash',
    argv: ['/bin/bash', '-c', 'ls'],
    cwd: '/',
  });
  assert.deepEqual(values.values, { SHELL_KEY: VALUES.SHELL_KEY });
  const missing = await materialize(page, {
    names: ['NOPE'],
    path: '/usr/bin/npm',
    argv: ['npm'],
    cwd: '/',
  });
  assert.equal(missing.error.code, 'ENOENT');
  const bad = await materialize(page, {
    names: ['NPM_TOKEN'],
    path: 'npm',
    argv: ['npm'],
    cwd: '/',
  });
  assert.equal(bad.error.code, 'EINVAL');
});

test('rate limits per secret and uid', async (t) => {
  const { page } = await ready(t, '[limits]\nmaterialize_per_minute = 2\nshell_per_day = 3\n');
  const ask = {
    names: ['NPM_TOKEN'],
    path: '/usr/bin/npm',
    argv: ['npm', 'whoami'],
    cwd: '/',
    interpreters: [],
  };
  assert.ok((await materialize(page, ask)).ticket);
  assert.ok((await materialize(page, ask)).ticket);
  const over = await materialize(page, ask);
  assert.equal(over.error.code, 'EAGAIN');
  assert.equal(over.error.message, 'materialize limit for NPM_TOKEN (2/min)');
  assert.ok((await materialize(page, ask, { ...PARENT, uid: 1001 })).ticket);
  const shell = {
    shellGrants: true,
    path: '/bin/bash',
    argv: ['bash'],
    cwd: '/',
    interpreters: [],
  };
  for (let i = 0; i < 3; i++) assert.ok((await materialize(page, shell)).ticket);
  const shellOver = await materialize(page, shell);
  assert.equal(shellOver.error.message, 'materialize limit for SHELL_KEY (3/day)');
});

test("the kernel's interpreter chain decides, not fnox's claim", async (t) => {
  const { page } = await ready(t);
  const script = { names: ['NPM_TOKEN'], path: '/home/cone/tool', argv: ['tool'], cwd: '/' };
  const got = await materialize(page, script);
  assert.deepEqual(got.real, { NPM_TOKEN: true });
  const viaSh = await consume(page, {
    ...script,
    ticket: got.ticket,
    stamp: CHILD,
    interpreters: ['/bin/sh'],
  });
  assert.equal(viaSh.error.code, 'EACCES');
  assert.match(viaSh.error.message, /fnox's interpreter isn't the one the kernel resolved/);
  const chained = await materialize(page, { ...script, interpreter: '/usr/bin/jq' });
  const viaChain = await consume(page, {
    ...script,
    ticket: chained.ticket,
    stamp: CHILD,
    interpreters: ['/usr/bin/jq', '/bin/sh'],
  });
  assert.match(viaChain.error.message, /NPM_TOKEN isn't revealed to \/bin\/sh/);
  const claimed = await materialize(page, { ...script, interpreter: '/usr/bin/jq' });
  const mismatch = await consume(page, {
    ...script,
    ticket: claimed.ticket,
    stamp: CHILD,
    interpreters: [],
  });
  assert.match(mismatch.error.message, /fnox's interpreter isn't the one the kernel resolved/);
  const noChain = await materialize(page, script);
  const missing = await consume(page, {
    ...script,
    ticket: noChain.ticket,
    stamp: CHILD,
    interpreters: 'x',
  });
  assert.match(missing.error.message, /no interpreter chain/);
  const run = { names: ['PLAIN_KEY'], path: '/opt/run.sh', argv: ['run.sh'], cwd: '/' };
  const listedChain = await materialize(page, { ...run, interpreter: '/bin/sh' });
  assert.deepEqual(listedChain.real, { PLAIN_KEY: true });
  const ok = await consume(page, {
    ...run,
    ticket: listedChain.ticket,
    stamp: CHILD,
    interpreters: ['/bin/sh'],
  });
  assert.deepEqual(ok.values, { PLAIN_KEY: VALUES.PLAIN_KEY });
  const other = await materialize(page, { ...run, interpreter: '/bin/bash' });
  const bash = await consume(page, {
    ...run,
    ticket: other.ticket,
    stamp: CHILD,
    interpreters: ['/bin/bash'],
  });
  assert.match(bash.error.message, /isn't revealed to \/bin\/bash/);
  const shell = await materialize(page, {
    shellGrants: true,
    path: '/home/cone/tool',
    interpreter: '/bin/bash',
    argv: ['tool'],
    cwd: '/',
  });
  const shellOk = await consume(page, {
    ticket: shell.ticket,
    stamp: CHILD,
    path: '/home/cone/tool',
    argv: ['tool'],
    cwd: '/',
    interpreters: ['/bin/bash'],
  });
  assert.deepEqual(Object.keys(shellOk.values), ['SHELL_KEY']);
});

test('an expired record is never revealed', async (t) => {
  const { page } = await ready(t);
  await page.evaluate(() =>
    window.harness.call('seal', {
      name: 'NPM_TOKEN',
      value: 'fake-lease-value-0009',
      source: 'jerk:npm@air',
      expiresAt: Date.now() - 1,
    })
  );
  const got = await materialize(page, {
    names: ['NPM_TOKEN'],
    path: '/usr/bin/npm',
    argv: ['npm'],
    cwd: '/',
  });
  assert.equal(got.error.code, 'EACCES');
  assert.match(got.error.message, /expired; refreshing/);
});
