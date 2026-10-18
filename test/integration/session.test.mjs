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
    rule: 2,
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
      rule: 3,
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
      rule: 1,
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

test('NEGATIVE second use: a second request for the same session gets nothing', async (t) => {
  const { page, placeholders } = await ready(t);
  const first = smtp(placeholders);
  assert.equal(Object.keys((await ask(page, first)).values).length, 1);
  await refused(page, first, /^session refused: this session already had its request$/);
  await refused(page, { ...first, handshakeAt: Date.now() }, /already had its request/);
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
    /rule 2 doesn't allow SMTP_PASS at smtp auth-plain on smtp.evil.example:587/
  );
  await refused(page, smtp(placeholders, { port: 25 }), /rule 2 doesn't allow SMTP_PASS/);
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
    /rule 2 doesn't allow SMTP_PASS at smtp auth-login/
  );
  await refused(
    page,
    smtp(placeholders, { protocol: 'pg', position: 'password-cleartext' }),
    /rule 2 doesn't allow/
  );
  const http = {
    rule: 1,
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
    /rule 1 doesn't allow API_KEY at http1 header:authorization/
  );
  await refused(
    page,
    smtp(placeholders, { ...http, head: { method: 'POST', path: '/v1/x' } }),
    /doesn't allow API_KEY for POST \/v1\/x/
  );
  await refused(
    page,
    smtp(placeholders, { ...http, head: { method: 'GET', path: '/admin' } }),
    /doesn't allow API_KEY for GET \/admin/
  );
  await refused(
    page,
    smtp(placeholders, { ...http, head: { method: 'GET', path: '/v1/%2e%2e/admin' } }),
    /ambiguous path/
  );
  await refused(
    page,
    smtp(placeholders, {
      rule: 6,
      host: 'forward.example.com',
      port: 443,
      protocol: 'http1',
      position: 'header:authorization',
      placeholders: [placeholders.API_KEY],
      head: { method: 'GET', path: '/' },
    }),
    /rule 6 doesn't allow API_KEY/
  );
  await refused(
    page,
    smtp(placeholders, {
      rule: 3,
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
  const other = await ask(
    page,
    smtp(placeholders, {
      placeholders: [
        model.placeholder,
        mcp.placeholder,
        placeholders.API_KEY,
        'fnox_proxy_ffffffffffffffffffffffff',
      ],
    })
  );
  assert.deepEqual(other.values, {});
  await page.evaluate(() => window.harness.call('remove', { name: 'DEAD' }));
  const dead = await ask(
    page,
    smtp(placeholders, { rule: 7, host: 'dead.example.com', placeholders: [placeholders.DEAD] })
  );
  assert.deepEqual(dead.values, {});
  const audit = (await page.evaluate(() => window.harness.call('audit'))).audit;
  assert.equal(audit.filter((entry) => entry.type === 'session').length, 0);
});

test('NEGATIVE §3.16 endpoint: a model or MCP endpoint never gets a session value, whatever the rule says', async (t) => {
  const { page, placeholders } = await ready(t);
  await refused(
    page,
    smtp(placeholders, {
      rule: 4,
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
    smtp(placeholders, { rule: 5, host: 'api.openai.com', port: 25, position: 'auth-login' }),
    /rule 5 of \/etc\/fnox\/config.toml isn't in effect/
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
