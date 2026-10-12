import assert from 'node:assert/strict';
import { test } from 'node:test';
import { setup } from './setup.mjs';

const { embedder } = await setup();

const PROCESS = 'sk-ant-PROCESSvalue/with+chars=';
const TYPED = 'ghp_TYPEDvalue"quote\\slash';

function forms(value) {
  const hex = [...new TextEncoder().encode(value)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return [value, btoa(value), encodeURIComponent(value), JSON.stringify(value).slice(1, -1), hex];
}

test('no op, event or reply ever carries a value', async (t) => {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.connect());
  await page.evaluate(
    (value) => window.harness.sealed({ v: 1, op: 'seal', name: 'PROC', value }),
    PROCESS
  );
  await page.evaluate((value) => window.harness.call('put', { name: 'TYPED', value }), TYPED);
  await page.until(() =>
    window.harness.events.some((e) => e.event === 'placeholders' && e.placeholders.length === 2)
  );
  await page.evaluate(async () => {
    const h = window.harness;
    for (const op of [
      'status',
      'placeholders',
      'list',
      'audit',
      'acknowledge',
      'policy',
      'fetch',
      'forward',
      'materializeConsume',
      'redact',
      'model',
    ]) {
      await h.call(op, { notice: 'x', text: 'PROC', name: 'PROC' });
    }
    const requests = [
      { op: 'list' },
      { op: 'placeholder', name: 'PROC' },
      { op: 'placeholder', name: 'TYPED' },
      { op: 'test', name: 'PROC', url: 'https://api.anthropic.com/v1/messages' },
      { op: 'seal', name: 'TYPED', value: 'agent-overwrite' },
      {
        op: 'materialize',
        names: ['PROC', 'TYPED'],
        path: '/usr/bin/env',
        argv: ['env'],
        cwd: '/',
      },
      { op: 'request', kind: 'value', name: 'PROC' },
      { op: 'status', id: 'req_0' },
    ];
    for (const req of requests) await h.sealed({ v: 1, ...req });
  });
  const seen = await page.evaluate(() => JSON.stringify(window.harness.seen));
  assert.ok(seen.includes('fnox_proxy_'));
  for (const value of [PROCESS, TYPED]) {
    for (const form of forms(value)) assert.ok(!seen.includes(form), `leaked ${form}`);
  }
  const list = await page.evaluate(async () => (await window.harness.call('list')).list);
  assert.deepEqual(
    list.secrets.map((s) => [s.name, s.source, s.state]),
    [
      ['PROC', 'process', 'inert'],
      ['TYPED', 'settings', 'inert'],
    ]
  );
  assert.deepEqual(
    list.audit.map((entry) => [entry.type, entry.name, entry.source]),
    [
      ['seal', 'TYPED', 'settings'],
      ['seal', 'PROC', 'process'],
    ]
  );
  assert.equal(list.auditMore, false);
});
