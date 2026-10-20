import assert from 'node:assert/strict';
import { createHash, createHmac, pbkdf2Sync } from 'node:crypto';
import { test } from 'node:test';
import { attest, CONFIG, POLICY } from './attest.mjs';
import { setup } from './setup.mjs';

const { embedder } = await setup();

const STAMP = { pid: 71, ppid: 1, uid: 1000, gid: 1000, tag: 'cone', users: 'enforce' };
const CNONCE = 'rOprNGfwEbeRWgbNEkqO';
const NONCE = `${CNONCE}%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0`;
const SALT = 'W22ZaJ0SNY7soEsUEjb6gQ==';
const VALUES = {
  PG_SCRAM: 'fake-scram-value-0001',
  PG_OTHER: 'fake-scram-other-0002',
  PG_PLAIN: 'fake-scram-plain-0003',
};

function rule(secret, domain, position = 'scram-sha-256') {
  return `[[proxy.rules]]\nsecret = "${secret}"\ndomain = "${domain}"\nprotocol = "pg"\nposition = "${position}"\nport = 5432\n`;
}

async function ready(t, values = VALUES, rules = null) {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.connect());
  const placeholders = {};
  for (const [name, value] of Object.entries(values)) {
    placeholders[name] = (
      await page.evaluate(
        (n, v) => window.harness.sealed({ v: 1, op: 'seal', name: n, value: v }),
        name,
        value
      )
    ).placeholder;
  }
  const secrets = Object.entries(placeholders)
    .map(([name, placeholder]) => `${name} = { provider = "seven", value = "${placeholder}" }`)
    .join('\n');
  const stanzas =
    rules ??
    [
      rule('PG_SCRAM', 'db.example.com'),
      rule('PG_OTHER', 'db.example.com'),
      rule('PG_PLAIN', 'db.example.com', 'password-cleartext'),
    ].join('\n');
  const text = `default_provider = "seven"\n[secrets]\n${secrets}\n\n${stanzas}`;
  const reply = await page.evaluate(
    (files) => window.harness.policy(files),
    [attest(CONFIG, text), attest(POLICY, '')]
  );
  assert.deepEqual(reply.warnings, []);
  return { page, placeholders };
}

function proofOf(password, first, server, final) {
  const offer = /s=([^,]*),i=(\d+)/.exec(server);
  const salted = pbkdf2Sync(
    password,
    Buffer.from(offer[1], 'base64'),
    Math.max(1, Number(offer[2])),
    32,
    'sha256'
  );
  const clientKey = createHmac('sha256', salted).update('Client Key').digest();
  const stored = createHash('sha256').update(clientKey).digest();
  const signature = createHmac('sha256', stored).update(`${first},${server},${final}`).digest();
  return Buffer.from(clientKey.map((byte, i) => byte ^ signature[i])).toString('base64');
}

let counter = 0;
function exchange(password, change = {}) {
  const messages = {
    clientFirstBare: `n=,r=${CNONCE}`,
    serverFirst: `r=${NONCE},s=${SALT},i=4096`,
    clientFinalBare: `c=biws,r=${NONCE}`,
    ...change,
  };
  const proof = proofOf(
    password,
    messages.clientFirstBare,
    messages.serverFirst,
    messages.clientFinalBare
  );
  return { proof, ...messages };
}

function session(scram, fields = {}) {
  counter += 1;
  return {
    stamp: STAMP,
    session: `scram-session-${process.pid}-${counter}-0000`,
    host: 'db.example.com',
    port: 5432,
    protocol: 'pg',
    position: 'scram-sha-256',
    verified: true,
    handshakeAt: Date.now(),
    exit: 'page',
    scram,
    ...fields,
  };
}

function ask(page, fields) {
  return page.evaluate((f) => window.harness.call('sessionMaterialize', f), fields);
}

async function refused(page, fields, code, message) {
  const reply = await ask(page, fields);
  assert.equal(reply.values, undefined);
  assert.equal(reply.error.code, code);
  assert.match(reply.error.message, message);
  assert.ok(!JSON.stringify(reply).includes('fake-scram'));
}

test('a SCRAM proof made from a placeholder identifies its secret, which is handed out once and audited', async (t) => {
  const { page, placeholders } = await ready(t);
  const got = await ask(page, session(exchange(placeholders.PG_SCRAM)));
  assert.deepEqual(got.values, { [placeholders.PG_SCRAM]: VALUES.PG_SCRAM });
  const other = await ask(page, session(exchange(placeholders.PG_OTHER)));
  assert.deepEqual(other.values, { [placeholders.PG_OTHER]: VALUES.PG_OTHER });
  const audit = (await page.evaluate(() => window.harness.call('audit'))).audit;
  assert.deepEqual(
    audit
      .filter((entry) => entry.type === 'session')
      .map((entry) => [entry.name, entry.position, entry.rule])
      .reverse(),
    [
      ['PG_SCRAM', 'scram-sha-256', 1],
      ['PG_OTHER', 'scram-sha-256', 2],
    ]
  );
  assert.ok(!JSON.stringify(audit).includes('fake-scram'));
});

const bound = (header, data = '') => `c=${btoa(header + data)},r=${NONCE}`;
const digest = (n) =>
  String.fromCharCode(...Array.from({ length: n }, (_, i) => (i * 7 + 1) % 256));

test('n,,, y,, and p=tls-server-end-point with each SHA-2 digest are matched on the program transcript as sent', async (t) => {
  const { page, placeholders } = await ready(t);
  const finals = [
    `c=biws,r=${NONCE}`,
    `c=eSws,r=${NONCE}`,
    bound('p=tls-server-end-point,,', digest(32)),
    bound('p=tls-server-end-point,,', digest(48)),
    bound('p=tls-server-end-point,,', digest(64)),
  ];
  for (const [i, clientFinalBare] of finals.entries()) {
    const got = await ask(page, session(exchange(placeholders.PG_SCRAM, { clientFinalBare })));
    assert.deepEqual(got.values, { [placeholders.PG_SCRAM]: VALUES.PG_SCRAM }, clientFinalBare);
    const crossed = {
      ...exchange(placeholders.PG_SCRAM, { clientFinalBare }),
      clientFinalBare: finals[(i + 1) % finals.length],
    };
    await refused(page, session(crossed), 'EACCES', /no session rule's placeholder matches/);
  }
  const audit = JSON.stringify((await page.evaluate(() => window.harness.call('audit'))).audit);
  assert.ok(!audit.includes('tls-server-end-point'));
  assert.ok(!audit.includes(btoa(digest(32)).slice(0, 16)));
});

test('NEGATIVE no match: a proof from no rule-bound placeholder gets nothing', async (t) => {
  const { page, placeholders } = await ready(t);
  const message = /^session refused: no session rule's placeholder matches the SCRAM proof$/;
  await refused(page, session(exchange('pencil')), 'EACCES', message);
  await refused(page, session(exchange(VALUES.PG_SCRAM)), 'EACCES', message);
  await refused(page, session(exchange(placeholders.PG_PLAIN)), 'EACCES', message);
});

test('NEGATIVE broken nonce chain, iterations and channel binding are EINVAL before the burn', async (t) => {
  const { page, placeholders } = await ready(t);
  const ph = placeholders.PG_SCRAM;
  const cases = [
    [{ serverFirst: `r=other${NONCE},s=${SALT},i=4096` }, /doesn't extend the client nonce/],
    [
      { serverFirst: `r=${CNONCE},s=${SALT},i=4096`, clientFinalBare: `c=biws,r=${CNONCE}` },
      /doesn't extend/,
    ],
    [{ clientFinalBare: `c=biws,r=${NONCE}x` }, /c=<base64>,r=<the server's nonce>/],
    [{ serverFirst: `r=${NONCE},s=${SALT},i=0` }, /serverFirst must be/],
    [{ serverFirst: `r=${NONCE},s=${SALT},i=100001` }, /iterations must be at most 100000/],
    [
      { clientFinalBare: bound('p=tls-unique,,', digest(32)) },
      /c= must be n,,, y,, or p=tls-server-end-point/,
    ],
    [{ clientFinalBare: bound('p=tls-exporter,,', digest(32)) }, /c= must be/],
    [{ clientFinalBare: bound('p=tls-server-end-point,,', digest(20)) }, /SHA-256, -384 or -512/],
    [{ clientFinalBare: bound('p=tls-server-end-point,,', digest(33)) }, /SHA-256, -384 or -512/],
    [{ clientFinalBare: bound('p=tls-server-end-point,,') }, /c= must be/],
    [{ clientFinalBare: bound('p=tls-server-end-point,a=x,', digest(32)) }, /c= must be/],
    [{ clientFinalBare: bound('y,a=x,') }, /c= must be/],
    [{ clientFinalBare: bound('n,,', digest(32)) }, /c= must be/],
    [{ clientFinalBare: `c=eSwr,r=${NONCE}` }, /c= must be/],
    [{ clientFinalBare: `c=e$ws,r=${NONCE}` }, /c=<base64>/],
    [{ clientFinalBare: `c=biws,r=${NONCE},p=x` }, /c=<base64>/],
    [{ clientFirstBare: `p=tls-server-end-point,,n=,r=${CNONCE}` }, /clientFirstBare must be n=/],
    [{ serverFirst: `r=${NONCE},s=,i=4096` }, /the salt is empty/],
  ];
  const id = session(exchange(ph)).session;
  for (const [change, message] of cases) {
    await refused(page, session(exchange(ph, change), { session: id }), 'EINVAL', message);
  }
  await refused(
    page,
    session({ ...exchange(ph), proof: 'AAAA' }, { session: id }),
    'EINVAL',
    /32 bytes/
  );
  await refused(
    page,
    session(exchange(ph), { session: id, placeholders: [ph] }),
    'EINVAL',
    /names no placeholders/
  );
  await refused(
    page,
    session(exchange(ph), { session: id, position: 'password-cleartext', placeholders: [ph] }),
    'EINVAL',
    /only a scram-sha-256 session has scram/
  );
  assert.deepEqual((await ask(page, session(exchange(ph), { session: id }))).values, {
    [ph]: VALUES.PG_SCRAM,
  });
});

test('NEGATIVE wrong host or port, second use and deadline: the SCRAM position keeps every session gate', async (t) => {
  const { page, placeholders } = await ready(t);
  const ph = placeholders.PG_SCRAM;
  const none = /no session rule's placeholder matches the SCRAM proof/;
  await refused(page, session(exchange(ph), { host: 'db.evil.example' }), 'EACCES', none);
  await refused(page, session(exchange(ph), { port: 5433 }), 'EACCES', none);
  await refused(page, session(exchange(ph), { verified: false }), 'EACCES', /didn't verify/);
  await refused(
    page,
    session(exchange(ph), { handshakeAt: Date.now() - 61_000 }),
    'EACCES',
    /past its 60 s deadline/
  );
  const once = session(exchange(ph));
  assert.deepEqual((await ask(page, once)).values, { [ph]: VALUES.PG_SCRAM });
  await refused(page, { ...once, handshakeAt: Date.now() }, 'EACCES', /already had its request/);
});

test('NEGATIVE bounded work: more than 16 rule-bound placeholders to try is refused before any hashing', async (t) => {
  const values = Object.fromEntries(
    Array.from({ length: 17 }, (_, i) => [
      `PG_${i}`,
      `fake-scram-many-${String(i).padStart(4, '0')}`,
    ])
  );
  const rules = Object.keys(values)
    .map((name) => rule(name, 'db.example.com'))
    .join('\n');
  const { page, placeholders } = await ready(t, values, rules);
  await refused(
    page,
    session(exchange(placeholders.PG_0)),
    'EACCES',
    /more than 16 session rules' placeholders to try for SCRAM/
  );
});
