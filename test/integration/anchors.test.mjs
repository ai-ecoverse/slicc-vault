import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { attest, CONFIG, POLICY } from './attest.mjs';
import { setup } from './setup.mjs';

const { embedder } = await setup();

const STAMP = { pid: 72, ppid: 1, uid: 1000, gid: 1000, tag: 'cone', users: 'enforce' };
const VALUES = {
  MAIL_PASS: 'fake-anchor-mail-0001',
  BOTH_PASS: 'fake-anchor-both-0002',
  OPEN_PASS: 'fake-anchor-open-0003',
};
const der = (label) =>
  Buffer.concat([
    Buffer.from([0x30, 0x82, 0x01, 0x00]),
    Buffer.from(`fake-anchor-der-${label}`),
  ]).toString('base64');
const ANCHOR = der('mail-ca');
const OTHER = der('other-ca');
const PIN = createHash('sha256').update('fake-anchor-spki-mail').digest('base64');
const idOf = (b64) => createHash('sha256').update(Buffer.from(b64, 'base64')).digest('base64');

function rule(secret, domain, extra = '') {
  return `[[proxy.rules]]\nsecret = "${secret}"\ndomain = "${domain}"\nprotocol = "smtp"\nposition = "auth-plain"\nport = 465\n${extra}`;
}

const RULES = [
  rule('MAIL_PASS', 'mail.example.com', `anchors = ["${ANCHOR}"]\npins = ["${PIN}"]\n`),
  rule('BOTH_PASS', 'both.example.com', `anchors = ["${OTHER}"]\nroots = true\n`),
  rule('OPEN_PASS', 'open.example.com'),
  rule('OPEN_PASS', 'mail.example.com', `anchors = ["${OTHER}"]\n`),
].join('\n');

async function ready(t, extra = '', overrides = {}) {
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
  const secrets = Object.entries(placeholders)
    .map(([name, placeholder]) => `${name} = { provider = "seven", value = "${placeholder}" }`)
    .join('\n');
  const text = `default_provider = "seven"\n[secrets]\n${secrets}\n\n${RULES}\n${extra}`;
  const reply = await page.evaluate(
    (files) => window.harness.policy(files),
    [attest(CONFIG, text, overrides), attest(POLICY, '[exits]\nBOTH_PASS = ["proxy"]\n')]
  );
  return { page, placeholders, reply };
}

let counter = 0;
function fields(placeholders, change = {}) {
  counter += 1;
  return {
    stamp: STAMP,
    session: `anchor-session-${process.pid}-${counter}-0000`,
    host: 'mail.example.com',
    port: 465,
    protocol: 'smtp',
    position: 'auth-plain',
    verified: true,
    handshakeAt: Date.now(),
    exit: 'page',
    placeholders: [placeholders.MAIL_PASS],
    ...change,
  };
}

const call = (page, op, f) => page.evaluate((o, x) => window.harness.call(o, x), op, f);

test('sessionAnchors answers the anchors and pins of the session rules for that host, port, protocol and exit, without values', async (t) => {
  const { page, placeholders, reply } = await ready(t);
  assert.deepEqual(reply.warnings, []);
  const target = (change = {}) => {
    const {
      position,
      verified,
      handshakeAt,
      placeholders: _,
      ...rest
    } = fields(placeholders, change);
    return rest;
  };
  const mail = await call(page, 'sessionAnchors', target());
  assert.deepEqual([mail.anchors.sort(), mail.pins], [[ANCHOR, OTHER].sort(), [PIN]]);
  assert.ok(!JSON.stringify(mail).includes('fake-anchor-mail-0001'));
  assert.deepEqual(
    await call(page, 'sessionAnchors', target({ host: 'open.example.com' })).then((r) => [
      r.anchors,
      r.pins,
    ]),
    [[], []]
  );
  assert.deepEqual(
    await call(page, 'sessionAnchors', target({ port: 587 })).then((r) => [r.anchors, r.pins]),
    [[], []]
  );
  assert.deepEqual(
    await call(page, 'sessionAnchors', target({ host: 'both.example.com' })).then((r) => r.anchors),
    []
  );
  assert.deepEqual(
    await call(page, 'sessionAnchors', target({ host: 'both.example.com', exit: 'proxy' })).then(
      (r) => r.anchors
    ),
    [OTHER]
  );
  const off = await call(page, 'sessionAnchors', target({ stamp: { ...STAMP, users: 'off' } }));
  assert.equal(off.error.message, 'kernel users must be enforce');
  assert.equal(
    (await call(page, 'sessionAnchors', target({ protocol: 'ftp' }))).error.code,
    'EINVAL'
  );
});

test('an anchored session gets the secret only by its own rule anchor or pin', async (t) => {
  const { page, placeholders } = await ready(t);
  const byAnchor = await call(
    page,
    'sessionMaterialize',
    fields(placeholders, { verifiedBy: 'anchored', anchor: idOf(ANCHOR) })
  );
  assert.deepEqual(byAnchor.values, { [placeholders.MAIL_PASS]: VALUES.MAIL_PASS });
  const byPin = await call(
    page,
    'sessionMaterialize',
    fields(placeholders, { verifiedBy: 'anchored', anchor: PIN })
  );
  assert.deepEqual(byPin.values, { [placeholders.MAIL_PASS]: VALUES.MAIL_PASS });
  const other = await call(
    page,
    'sessionMaterialize',
    fields(placeholders, { verifiedBy: 'anchored', anchor: idOf(OTHER) })
  );
  assert.equal(
    other.error.message,
    "session refused: the anchor that verified the session isn't one of MAIL_PASS's session rule"
  );
  const open = await call(
    page,
    'sessionMaterialize',
    fields(placeholders, {
      verifiedBy: 'anchored',
      anchor: idOf(OTHER),
      placeholders: [placeholders.OPEN_PASS],
    })
  );
  assert.deepEqual(open.values, { [placeholders.OPEN_PASS]: VALUES.OPEN_PASS });
});

test('each session audit entry records how the kernel trusted the session', async (t) => {
  const { page, placeholders } = await ready(t);
  await call(
    page,
    'sessionMaterialize',
    fields(placeholders, { verifiedBy: 'anchored', anchor: idOf(ANCHOR) })
  );
  await call(
    page,
    'sessionMaterialize',
    fields(placeholders, { verifiedBy: 'anchored', anchor: PIN })
  );
  await call(
    page,
    'sessionMaterialize',
    fields(placeholders, { host: 'open.example.com', placeholders: [placeholders.OPEN_PASS] })
  );
  const audit = (await page.evaluate(() => window.harness.call('audit'))).audit;
  assert.deepEqual(
    audit
      .filter((entry) => entry.type === 'session')
      .map((entry) => [entry.name, entry.verifiedBy, entry.anchor])
      .reverse(),
    [
      ['MAIL_PASS', 'anchored', idOf(ANCHOR)],
      ['MAIL_PASS', 'anchored', PIN],
      ['OPEN_PASS', 'roots', undefined],
    ]
  );
  assert.ok(!JSON.stringify(audit).includes('fake-anchor-mail-0001'));
});

test('NEGATIVE public roots: a rule with anchors or pins refuses a roots-verified session unless it says roots = true', async (t) => {
  const { page, placeholders } = await ready(t);
  for (const change of [{}, { verifiedBy: 'roots' }]) {
    const reply = await call(page, 'sessionMaterialize', fields(placeholders, change));
    assert.equal(
      reply.error.message,
      "session refused: MAIL_PASS's session rule accepts only its anchors and pins, not public roots"
    );
  }
  const both = await call(
    page,
    'sessionMaterialize',
    fields(placeholders, {
      host: 'both.example.com',
      exit: 'proxy',
      placeholders: [placeholders.BOTH_PASS],
    })
  );
  assert.deepEqual(both.values, { [placeholders.BOTH_PASS]: VALUES.BOTH_PASS });
  const open = await call(
    page,
    'sessionMaterialize',
    fields(placeholders, { host: 'open.example.com', placeholders: [placeholders.OPEN_PASS] })
  );
  assert.deepEqual(open.values, { [placeholders.OPEN_PASS]: VALUES.OPEN_PASS });
});

test('NEGATIVE malformed trust fields are EINVAL before the burn', async (t) => {
  const { page, placeholders } = await ready(t);
  const id = fields(placeholders).session;
  for (const change of [
    { verifiedBy: 'pinned' },
    { verifiedBy: 'anchored' },
    { verifiedBy: 'anchored', anchor: 'AAAA' },
    { verifiedBy: 'roots', anchor: PIN },
  ]) {
    const reply = await call(
      page,
      'sessionMaterialize',
      fields(placeholders, { session: id, ...change })
    );
    assert.equal(reply.error.code, 'EINVAL');
  }
  const good = await call(
    page,
    'sessionMaterialize',
    fields(placeholders, { session: id, verifiedBy: 'anchored', anchor: PIN })
  );
  assert.deepEqual(good.values, { [placeholders.MAIL_PASS]: VALUES.MAIL_PASS });
});

test('NEGATIVE bad anchors, pins and roots in a rule drop it with a warning', async (t) => {
  const many = JSON.stringify(Array.from({ length: 9 }, (_, i) => der(`many-${i}`)));
  const extra = [
    rule('MAIL_PASS', 'a.example.com', `anchors = ${many}\n`),
    rule(
      'MAIL_PASS',
      'b.example.com',
      `anchors = ["${Buffer.from('fake-not-der').toString('base64')}"]\n`
    ),
    rule('MAIL_PASS', 'c.example.com', `pins = ["${Buffer.from('short').toString('base64')}"]\n`),
    rule('MAIL_PASS', 'd.example.com', `pins = ["${PIN}"]\nroots = "yes"\n`),
    rule('MAIL_PASS', 'e.example.com', 'roots = false\n'),
    rule('MAIL_PASS', 'f.example.com', 'anchors = "x"\n'),
    `[[proxy.rules]]\nsecret = "MAIL_PASS"\ndomain = "g.example.com"\npins = ["${PIN}"]\n`,
  ].join('\n');
  const { reply } = await ready(t, extra);
  assert.deepEqual(reply.files[0].warnings, [
    'proxy rule 5: at most 8 anchors and 8 pins',
    'proxy rule 6: an anchor must be base64 of a DER certificate of at most 8 KB',
    'proxy rule 7: a pin must be base64 of a 32-byte SHA-256 of a public key',
    'proxy rule 8: roots must be true or false',
    "proxy rule 9: a rule without anchors or pins can't refuse public roots",
    'proxy rule 10: anchors and pins must be lists of base64 strings',
    'proxy rule 11: port, position, anchors, pins and roots need a protocol',
  ]);
});

test('NEGATIVE who can set anchors: only an attested root-owned policy, never a non-root file or the agent port', async (t) => {
  const { page, placeholders, reply } = await ready(t, '', { uid: 1000 });
  assert.equal(reply.accepted, false);
  const { position, verified, handshakeAt, placeholders: _, ...target } = fields(placeholders);
  const none = await call(page, 'sessionAnchors', target);
  assert.deepEqual([none.anchors, none.pins], [[], []]);
  await page.evaluate(() => window.harness.agent());
  const agent = await page.evaluate(() => window.harness.ask('policy', { files: [] }));
  assert.equal(agent.error.code, 'EACCES');
  const anchors = await page.evaluate((f) => window.harness.ask('sessionAnchors', f), target);
  assert.equal(anchors.error.code, 'EACCES');
});
