import assert from 'node:assert/strict';
import { test } from 'node:test';
import { attest, CONFIG, POLICY } from './attest.mjs';
import { setup } from './setup.mjs';

const { embedder } = await setup();

const VALUES = {
  API_KEY: 'fake-session-api-0001',
  SMTP_PASS: 'fake-session-smtp-0002',
  PG_PASS: 'fake-session-pg-0003',
  DEAD: 'fake-session-dead-0004',
  SMTP_USER: 'fake-session-user-0007',
};
const STAMP = { pid: 70, ppid: 1, uid: 1000, gid: 1000, tag: 'cone', users: 'enforce' };

const RULES = `
[[proxy.rules]]
secret = "API_KEY"
domain = "api.example.com"
protocol = "http1"
port = 8443
header = "X-Api-Key"
methods = ["GET"]
paths = ["/v1/**"]

[[proxy.rules]]
secret = "SMTP_PASS"
domain = "smtp.example.com"
protocol = "smtp"
position = "auth-plain"
port = 587

[[proxy.rules]]
secret = "PG_PASS"
domain = "db.example.com"
protocol = "pg"
position = "password-cleartext"
port = 5432

[[proxy.rules]]
secret = "API_KEY"
domain = "api.openai.com"
protocol = "http1"
port = 443

[[proxy.rules]]
secret = "SMTP_PASS"
domain = "api.openai.com"
protocol = "smtp"
position = "auth-login"
port = 25

[[proxy.rules]]
secret = "API_KEY"
domain = "forward.example.com"

[[proxy.rules]]
secret = "DEAD"
domain = "dead.example.com"
protocol = "smtp"
position = "auth-plain"
port = 587

[[proxy.rules]]
secret = "SMTP_USER"
domain = "smtp.example.com"
protocol = "smtp"
position = "auth-plain"
port = 587
`;

function configText(placeholders) {
  const secrets = Object.entries(placeholders)
    .map(([name, placeholder]) => `${name} = { provider = "seven", value = "${placeholder}" }`)
    .join('\n');
  return `default_provider = "seven"\n\n[secrets]\n${secrets}\n${RULES}`;
}

async function ready(t) {
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
  const files = [
    attest(CONFIG, configText(placeholders)),
    attest(POLICY, '[exits]\nPG_PASS = ["proxy"]\n'),
  ];
  const reply = await page.evaluate((list) => window.harness.policy(list), files);
  assert.equal(reply.accepted, true);
  assert.deepEqual(reply.warnings, []);
  return { page, placeholders };
}

let counter = 0;
function smtp(placeholders, fields = {}) {
  counter += 1;
  return {
    stamp: STAMP,
    session: `smtp-session-${process.pid}-${counter}-0000`,
    host: 'smtp.example.com',
    port: 587,
    protocol: 'smtp',
    position: 'auth-plain',
    verified: true,
    handshakeAt: Date.now(),
    exit: 'page',
    placeholders: [placeholders.SMTP_PASS],
    ...fields,
  };
}

function ask(page, fields) {
  return page.evaluate((f) => window.harness.call('sessionMaterialize', f), fields);
}

async function refused(page, fields, message) {
  const reply = await ask(page, fields);
  assert.equal(reply.values, undefined);
  assert.equal(reply.error.code, 'EACCES');
  assert.match(reply.error.message, message);
  assert.ok(!JSON.stringify(reply).includes('fake-session'));
}

test('a kernel-verified session gets its rule secret at the rule position, audited without the value', async (t) => {
  const { page, placeholders } = await ready(t);
  const mail = await ask(page, smtp(placeholders));
  assert.deepEqual(mail, {
    v: 1,
    id: mail.id,
    op: 'sessionMaterialize',
    values: { [placeholders.SMTP_PASS]: VALUES.SMTP_PASS },
  });
  const pg = await ask(
    page,
    smtp(placeholders, {
      host: 'db.example.com',
      port: 5432,
      protocol: 'pg',
      position: 'password-cleartext',
      exit: 'proxy',
      placeholders: [placeholders.PG_PASS],
    })
  );
  assert.deepEqual(pg.values, { [placeholders.PG_PASS]: VALUES.PG_PASS });
  const http = await ask(
    page,
    smtp(placeholders, {
      host: 'API.example.com.',
      port: 8443,
      protocol: 'http1',
      position: 'header:x-api-key',
      placeholders: [placeholders.API_KEY],
      head: { method: 'GET', path: '/v1/models?limit=1' },
    })
  );
  assert.deepEqual(http.values, { [placeholders.API_KEY]: VALUES.API_KEY });
  const audit = (await page.evaluate(() => window.harness.call('audit'))).audit;
  const sessions = audit.filter((entry) => entry.type === 'session').reverse();
  assert.deepEqual(
    sessions.map(({ name, domain, port, protocol, position, rule, exit, uid, tag }) => [
      name,
      domain,
      port,
      protocol,
      position,
      rule,
      exit,
      uid,
      tag,
    ]),
    [
      ['SMTP_PASS', 'smtp.example.com', 587, 'smtp', 'auth-plain', 2, 'page', 1000, 'cone'],
      ['PG_PASS', 'db.example.com', 5432, 'pg', 'password-cleartext', 3, 'proxy', 1000, 'cone'],
      ['API_KEY', 'api.example.com', 8443, 'http1', 'header:x-api-key', 1, 'page', 1000, 'cone'],
    ]
  );
  assert.ok(!JSON.stringify(audit).includes('fake-session'));
});

test('one session request carries every placeholder found at its position, each by its own rule', async (t) => {
  const { page, placeholders } = await ready(t);
  const both = await ask(
    page,
    smtp(placeholders, { placeholders: [placeholders.SMTP_USER, placeholders.SMTP_PASS] })
  );
  assert.deepEqual(both.values, {
    [placeholders.SMTP_USER]: VALUES.SMTP_USER,
    [placeholders.SMTP_PASS]: VALUES.SMTP_PASS,
  });
  const audit = (await page.evaluate(() => window.harness.call('audit'))).audit;
  assert.deepEqual(
    audit
      .filter((entry) => entry.type === 'session')
      .map((entry) => [entry.name, entry.rule])
      .sort(),
    [
      ['SMTP_PASS', 2],
      ['SMTP_USER', 8],
    ]
  );
});

test('NEGATIVE second use: a second request for the same session gets nothing, in any vault frame', async (t) => {
  const { page, placeholders } = await ready(t);
  const first = smtp(placeholders);
  assert.equal(Object.keys((await ask(page, first)).values).length, 1);
  await refused(page, first, /^session refused: this session already had its request$/);
  await refused(page, { ...first, handshakeAt: Date.now() }, /already had its request/);
  await page.reload();
  await page.evaluate(() => window.harness.connect());
  await refused(page, { ...first, handshakeAt: Date.now() }, /already had its request/);
  const empty = smtp(placeholders, { placeholders: [placeholders.API_KEY] });
  await refused(page, empty, /no session rule lets API_KEY/);
  await refused(
    page,
    { ...empty, placeholders: [placeholders.SMTP_PASS] },
    /already had its request/
  );
});

test('NEGATIVE wrong host or certificate, and plaintext: a session the kernel did not verify gets nothing', async (t) => {
  const { page, placeholders } = await ready(t);
  await refused(
    page,
    smtp(placeholders, { verified: false }),
    /^session refused: the kernel didn't verify the session's host$/
  );
});

test('NEGATIVE wrong host: a session to a host its rule does not name gets nothing', async (t) => {
  const { page, placeholders } = await ready(t);
  await refused(
    page,
    smtp(placeholders, { host: 'smtp.evil.example' }),
    /^session refused: no session rule lets SMTP_PASS at smtp auth-plain on smtp.evil.example:587$/
  );
  await refused(
    page,
    smtp(placeholders, { port: 25 }),
    /no session rule lets SMTP_PASS at smtp auth-plain on smtp.example.com:25/
  );
});

test('NEGATIVE after the deadline: a session older than 60 s gets nothing', async (t) => {
  const { page, placeholders } = await ready(t);
  await refused(
    page,
    smtp(placeholders, { handshakeAt: Date.now() - 61_000 }),
    /past its 60 s deadline/
  );
  await refused(
    page,
    smtp(placeholders, { handshakeAt: Date.now() + 60_000 }),
    /past its 60 s deadline/
  );
});

test('NEGATIVE wrong position: a protocol, position, header, method or path the rule does not name gets nothing', async (t) => {
  const { page, placeholders } = await ready(t);
  await refused(
    page,
    smtp(placeholders, { position: 'auth-login' }),
    /no session rule lets SMTP_PASS at smtp auth-login/
  );
  await refused(
    page,
    smtp(placeholders, { protocol: 'pg', position: 'password-cleartext' }),
    /no session rule lets SMTP_PASS at pg password-cleartext/
  );
  const http = {
    host: 'api.example.com',
    port: 8443,
    protocol: 'http1',
    position: 'header:x-api-key',
    placeholders: [placeholders.API_KEY],
  };
  await refused(
    page,
    smtp(placeholders, {
      ...http,
      position: 'header:authorization',
      head: { method: 'GET', path: '/v1/x' },
    }),
    /no session rule lets API_KEY at http1 header:authorization on api.example.com:8443 for GET \/v1\/x/
  );
  await refused(
    page,
    smtp(placeholders, { ...http, head: { method: 'POST', path: '/v1/x' } }),
    /no session rule lets API_KEY at http1 header:x-api-key on api.example.com:8443 for POST \/v1\/x/
  );
  await refused(
    page,
    smtp(placeholders, { ...http, head: { method: 'GET', path: '/admin' } }),
    /no session rule lets API_KEY .* for GET \/admin/
  );
  await refused(
    page,
    smtp(placeholders, { ...http, head: { method: 'GET', path: '/v1/%2e%2e/admin' } }),
    /ambiguous path/
  );
  await refused(
    page,
    smtp(placeholders, {
      host: 'forward.example.com',
      port: 443,
      protocol: 'http1',
      position: 'header:authorization',
      placeholders: [placeholders.API_KEY],
      head: { method: 'GET', path: '/' },
    }),
    /no session rule lets API_KEY at http1 header:authorization on forward.example.com:443 for GET \//
  );
  await refused(
    page,
    smtp(placeholders, {
      host: 'db.example.com',
      port: 5432,
      protocol: 'pg',
      position: 'password-cleartext',
      placeholders: [placeholders.PG_PASS],
    }),
    /PG_PASS isn't allowed on page/
  );
});

test('NEGATIVE users not enforce: a session from a kernel without enforced users gets nothing', async (t) => {
  const { page, placeholders } = await ready(t);
  for (const users of [undefined, 'off', 'report']) {
    await refused(
      page,
      smtp(placeholders, { stamp: { ...STAMP, users } }),
      /^kernel users must be enforce$/
    );
  }
});

test('NEGATIVE non-secret record: only the live secret its rule names is handed out', async (t) => {
  const { page, placeholders } = await ready(t);
  const model = await page.evaluate(() =>
    window.harness.call('put', {
      name: 'OPENAI_KEY',
      value: 'fake-session-model-0005',
      kind: 'model',
      provider: 'openai',
    })
  );
  const mcp = await page.evaluate(() =>
    window.harness.call('seal', {
      name: 'DOCS_MCP',
      value: 'fake-session-mcp-0006',
      source: 'settings',
      kind: 'mcp',
    })
  );
  const one = (placeholder) => smtp(placeholders, { placeholders: [placeholder] });
  await refused(page, one(model.placeholder), /^session refused: OPENAI_KEY isn't a secret$/);
  await refused(page, one(mcp.placeholder), /^session refused: DOCS_MCP isn't a secret$/);
  await refused(page, one(placeholders.API_KEY), /no session rule lets API_KEY at smtp auth-plain/);
  await refused(page, one('fnox_proxy_ffffffffffffffffffffffff'), /a placeholder of no record/);
  await page.evaluate(() => window.harness.call('remove', { name: 'DEAD' }));
  await refused(
    page,
    smtp(placeholders, { host: 'dead.example.com', placeholders: [placeholders.DEAD] }),
    /^session refused: DEAD was removed$/
  );
  const mixed = await ask(
    page,
    smtp(placeholders, { placeholders: [model.placeholder, placeholders.SMTP_PASS] })
  );
  assert.deepEqual(mixed.values, { [placeholders.SMTP_PASS]: VALUES.SMTP_PASS });
  const audit = (await page.evaluate(() => window.harness.call('audit'))).audit;
  assert.deepEqual(
    audit.filter((entry) => entry.type === 'session').map((entry) => entry.name),
    ['SMTP_PASS']
  );
});

test('NEGATIVE §3.16 endpoint: a model or MCP endpoint never gets a session value, whatever the rule says', async (t) => {
  const { page, placeholders } = await ready(t);
  await refused(
    page,
    smtp(placeholders, {
      host: 'api.openai.com',
      port: 443,
      protocol: 'http1',
      position: 'header:authorization',
      placeholders: [placeholders.API_KEY],
      head: { method: 'POST', path: '/v1/chat/completions' },
    }),
    /api.openai.com is a model or MCP endpoint/
  );
  await refused(
    page,
    smtp(placeholders, { host: 'api.openai.com', port: 25, position: 'auth-login' }),
    /no session rule lets SMTP_PASS at smtp auth-login on api.openai.com:25/
  );
  const list = (await page.evaluate(() => window.harness.call('list'))).list;
  assert.deepEqual(
    list.refused.map(({ secret, rule, reason }) => [secret, rule.domain, rule.protocol, reason]),
    [
      [
        'SMTP_PASS',
        'api.openai.com',
        'smtp',
        'SMTP_PASS: api.openai.com is a model or MCP endpoint; the vault never injects there',
      ],
    ]
  );
});

test('NEGATIVE echoing server: a session value the server reflects is scrubbed before it reaches the agent', async (t) => {
  const { page, placeholders } = await ready(t);
  assert.equal(Object.keys((await ask(page, smtp(placeholders))).values).length, 1);
  await page.evaluate(() => window.harness.agent());
  const echoes = [
    `501 5.5.4 Syntax error: ${VALUES.SMTP_PASS}`,
    `535 ${btoa(VALUES.SMTP_PASS)}`,
    `ERROR: password ${Buffer.from(VALUES.SMTP_PASS).toString('hex')} rejected`,
  ];
  const reply = await page.evaluate((texts) => window.harness.ask('redact', { texts }), echoes);
  assert.equal(reply.texts[0], `501 5.5.4 Syntax error: ${placeholders.SMTP_PASS}`);
  assert.ok(reply.texts.every((text) => !text.includes('fake-session')));
  assert.ok(!reply.texts[1].includes(btoa(VALUES.SMTP_PASS)));
  assert.ok(!reply.texts[2].includes(Buffer.from(VALUES.SMTP_PASS).toString('hex')));
});

test('a session rule is never used by forward, and a forward rule never by a session', async (t) => {
  const { page, placeholders } = await ready(t);
  const forwarded = await page.evaluate((f) => window.harness.forward(f), {
    head: {
      method: 'GET',
      url: 'https://smtp.example.com/',
      headers: [['authorization', `Bearer ${placeholders.SMTP_PASS}`]],
    },
    owner: STAMP,
    exit: 'page',
    rawTraits: { manualRedirects: true },
  });
  assert.deepEqual(forwarded.reply.refused, {
    status: 403,
    reason: 'no rule in /etc/fnox/config.toml lets SMTP_PASS be used',
  });
  const list = (await page.evaluate(() => window.harness.call('list'))).list;
  const smtpView = list.secrets.find((secret) => secret.name === 'SMTP_PASS');
  assert.equal(smtpView.state, 'active');
  assert.deepEqual(smtpView.rules, [
    {
      domain: 'smtp.example.com',
      header: '',
      methods: [],
      paths: [],
      protocol: 'smtp',
      position: 'auth-plain',
      port: 587,
    },
  ]);
});
