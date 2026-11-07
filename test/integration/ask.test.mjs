import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { attest, POLICY } from './attest.mjs';
import { browser } from './browser.mjs';
import { setup } from './setup.mjs';

const { chrome, embedder } = await setup();
const cdp = await browser(chrome);
after(() => cdp.close());

const as = (uid, tag = 'cone') => ({ pid: 70, ppid: 1, uid, gid: uid, tag, users: 'enforce' });

const requester = (kind = 'user') => ({
  kind,
  name: 'lars',
  where: 'Terminal 1',
  exe: '/usr/bin/fnox',
  argv: ['fnox', 'set', 'THE_NAME'],
  cwd: '/home/lars',
  tty: '/dev/pts/0',
  stdin: 'tty',
});

const ask = (name, fields = {}, kind = 'user') => ({
  v: 1,
  op: 'ask',
  name,
  requester: requester(kind),
  ...fields,
});

async function connected(t) {
  const page = await embedder(t);
  await page.evaluate(() => window.harness.connect());
  return page;
}

async function held(page, req, stamp) {
  const id = await page.evaluate((r, s) => window.harness.hold(r, s), req, stamp);
  const asked = await page.until(
    (call) => window.harness.events.find((e) => e.event === 'asked' && e.call === call),
    id
  );
  return { id, request: asked.request };
}

async function shown(page, request) {
  await page.evaluate((id) => window.harness.value(id), request);
  return cdp.target(/\/value\.html$/);
}

const reply = (page, id) => page.until((call) => window.harness.replies[call], id);

async function armed(frame, label) {
  return frame.until(
    (text) =>
      [...document.querySelectorAll('button')].some((b) => b.textContent === text && !b.disabled),
    label
  );
}

async function press(frame, label) {
  await armed(frame, label);
  await frame.evaluate((text) => {
    [...document.querySelectorAll('button')].find((b) => b.textContent === text).click();
  }, label);
}

async function type(frame, text) {
  await frame.until(() => document.querySelector('input') !== null);
  await frame.evaluate((value) => {
    const input = document.querySelector('input');
    input.focus();
    input.value = value;
    input.dispatchEvent(new Event('input'));
  }, text);
}

test('an ask for a name that holds a secret answers at once with its placeholder', async (t) => {
  const page = await connected(t);
  const sealed = await page.evaluate(
    (s) =>
      window.harness.sealed(
        { v: 1, op: 'seal', name: 'HELD_ALREADY', value: 'stored-value-01' },
        s
      ),
    as(2001)
  );
  const answer = await page.evaluate(
    (r, s) => window.harness.sealed(r, s),
    ask('HELD_ALREADY'),
    as(2001)
  );
  assert.deepEqual(answer, {
    v: 1,
    state: 'done',
    placeholder: sealed.placeholder,
    record: 'inert',
  });
  const status = await page.evaluate(() => window.harness.call('status'));
  assert.deepEqual(status.status.waiting, []);
  assert.equal(
    await page.evaluate(() => window.harness.events.some((e) => e.event === 'asked')),
    false
  );
});

test('an enter ask waits for the value typed in the frame while the port goes on', async (t) => {
  const page = await connected(t);
  const { id, request } = await held(
    page,
    ask('TYPED_TOKEN', { prompt: 'for the deploy' }),
    as(2002)
  );
  const status = await page.evaluate(() => window.harness.call('status'));
  const waiting = status.status.waiting.find((entry) => entry.id === request);
  assert.deepEqual(
    { ...waiting, createdAt: 0, expiresAt: waiting.expiresAt - waiting.createdAt },
    {
      id: request,
      kind: 'ask',
      name: 'TYPED_TOKEN',
      prompt: 'for the deploy',
      mode: 'enter',
      reveal: false,
      replace: false,
      requester: requester(),
      uid: 2002,
      tag: 'cone',
      createdAt: 0,
      expiresAt: 300000,
    }
  );
  const frame = await shown(page, request);
  assert.equal(await frame.evaluate(() => document.querySelector('input').type), 'password');
  await type(frame, 'typed-by-the-user-01');
  await press(frame, 'Save');
  const answer = await reply(page, id);
  assert.deepEqual(Object.keys(answer).sort(), ['placeholder', 'record', 'state', 'v']);
  assert.equal(answer.state, 'done');
  assert.match(answer.placeholder, /^fnox_proxy_[0-9a-f]{24}$/);
  const done = await page.until(() => window.harness.valueEvents.find((e) => e.event === 'done'));
  assert.deepEqual(done, {
    type: 'slicc-vault',
    v: 1,
    event: 'done',
    request,
    state: 'sealed',
    name: 'TYPED_TOKEN',
    placeholder: answer.placeholder,
    record: answer.record,
  });
  assert.equal(await frame.evaluate(() => document.querySelector('input')), null);
  const { audit } = await page.evaluate(() => window.harness.call('audit', { limit: 5 }));
  const entry = audit.find((e) => e.type === 'seal' && e.name === 'TYPED_TOKEN');
  assert.equal(entry.source, 'settings');
  assert.equal(entry.request, request);
  const seen = await page.evaluate(() => JSON.stringify(window.harness.seen));
  assert.ok(!seen.includes('typed-by-the-user-01'));
});

test('an enter ask with reveal hands back the value just typed and audits the reveal', async (t) => {
  const page = await connected(t);
  const { id, request } = await held(page, ask('TYPED_SHOWN', { reveal: true }), as(2003));
  const frame = await shown(page, request);
  await type(frame, 'typed-and-revealed-02');
  await press(frame, 'Save');
  const answer = await reply(page, id);
  assert.equal(answer.value, 'typed-and-revealed-02');
  assert.equal(answer.state, 'done');
  const { audit } = await page.evaluate(() => window.harness.call('audit', { limit: 5 }));
  const { seq, id: entryId, at, ...entry } = audit.find((e) => e.type === 'reveal');
  assert.ok(seq > 0 && entryId && at > 0);
  assert.deepEqual(entry, {
    type: 'reveal',
    name: 'TYPED_SHOWN',
    uid: 2003,
    tag: 'cone',
    exe: '/usr/bin/fnox',
    argv: 'fnox set THE_NAME',
    cwd: '/home/lars',
    requester: 'user',
    request,
  });
  assert.ok(audit.some((e) => e.type === 'seal' && e.request === request));
});

test('a reveal ask over a stored secret returns its value after Allow', async (t) => {
  const page = await connected(t);
  await page.evaluate(
    (s) =>
      window.harness.sealed({ v: 1, op: 'seal', name: 'TO_REVEAL', value: 'revealed-value-03' }, s),
    as(2004)
  );
  const { id, request } = await held(page, ask('TO_REVEAL', { reveal: true }), as(2004));
  const waiting = (await page.evaluate(() => window.harness.call('status'))).status.waiting;
  assert.equal(waiting.find((entry) => entry.id === request).mode, 'reveal');
  const frame = await shown(page, request);
  await armed(frame, 'Allow');
  const view = await frame.evaluate(() => ({
    text: document.querySelector('p').textContent,
    negative: document.querySelector('button').className.includes('spectrum-Button--negative'),
    input: document.querySelector('input'),
  }));
  assert.deepEqual(view, {
    text: '/usr/bin/fnox gets the plaintext of TO_REVEAL',
    negative: true,
    input: null,
  });
  await press(frame, 'Allow');
  const answer = await reply(page, id);
  assert.equal(answer.value, 'revealed-value-03');
  const done = await page.until(() => window.harness.valueEvents.find((e) => e.event === 'done'));
  assert.equal(done.state, 'allowed');
  const { audit } = await page.evaluate(() => window.harness.call('audit', { limit: 5 }));
  assert.ok(
    audit.some((e) => e.type === 'reveal' && e.name === 'TO_REVEAL' && e.request === request)
  );
});

test('replace asks for a new value over a stored secret and keeps its placeholder', async (t) => {
  const page = await connected(t);
  const before = await page.evaluate(
    (s) =>
      window.harness.sealed({ v: 1, op: 'seal', name: 'TO_REPLACE', value: 'old-value-04' }, s),
    as(2005)
  );
  const { id, request } = await held(page, ask('TO_REPLACE', { replace: true }), as(2005));
  const frame = await shown(page, request);
  await frame.until(
    () => document.querySelector('label')?.textContent === 'Replace the value of TO_REPLACE'
  );
  await type(frame, 'new-value-04-typed');
  await press(frame, 'Save');
  const answer = await reply(page, id);
  assert.equal(answer.placeholder, before.placeholder);
  const list = (await page.evaluate(() => window.harness.call('list'))).list;
  assert.equal(list.secrets.find((s) => s.name === 'TO_REPLACE').source, 'settings');
});

test('withdrawn and cancelled asks end the held reply and tell the frame', async (t) => {
  const page = await connected(t);
  const first = await held(page, ask('WITHDRAWN_ONE'), as(2006));
  const frame = await shown(page, first.request);
  await frame.until(() => document.querySelector('input') !== null);
  const withdrawn = await page.evaluate(
    (request) => window.harness.call('cancel', { request, reason: 'withdrawn' }),
    first.request
  );
  assert.equal(withdrawn.state, 'withdrawn');
  assert.deepEqual(await reply(page, first.id), { v: 1, state: 'withdrawn' });
  const gone = await page.until(() => window.harness.valueEvents.find((e) => e.event === 'gone'));
  assert.deepEqual(gone, {
    type: 'slicc-vault',
    v: 1,
    event: 'gone',
    request: first.request,
    state: 'withdrawn',
  });
  const order = await page.evaluate((request) => {
    const events = window.harness.events;
    const ended = events.findIndex((e) => e.event === 'cancelled' && e.request === request);
    const dropped = events.findIndex(
      (e, i) => i > ended && e.event === 'status' && !e.status.waiting.some((w) => w.id === request)
    );
    return { cancelled: events[ended], after: dropped > ended };
  }, first.request);
  assert.deepEqual(order.cancelled, {
    v: 1,
    event: 'cancelled',
    request: first.request,
    kind: 'ask',
    state: 'withdrawn',
  });
  assert.equal(order.after, true);
  const second = await held(page, ask('CANCELLED_ONE'), as(2006));
  const cancelled = await page.evaluate(
    (request) => window.harness.call('cancel', { request }),
    second.request
  );
  assert.equal(cancelled.state, 'cancelled');
  assert.deepEqual(await reply(page, second.id), { v: 1, state: 'cancelled' });
});

test('a uid gets one ask at a time, and a page op cannot answer one', async (t) => {
  const page = await connected(t);
  const { request } = await held(page, ask('ONE_AT_A_TIME'), as(2007));
  const again = await page.evaluate(
    (r, s) => window.harness.sealed(r, s),
    ask('SECOND_ONE'),
    as(2007)
  );
  assert.equal(again.error.code, 'EAGAIN');
  const put = await page.evaluate(
    (id) =>
      window.harness.call('put', {
        name: 'ONE_AT_A_TIME',
        value: 'page-chosen-value',
        request: id,
      }),
    request
  );
  assert.equal(put.error.code, 'EINVAL');
  const answered = await page.evaluate(
    (id) => window.harness.call('answer', { request: id, state: 'done', exit: 0 }),
    request
  );
  assert.equal(answered.error.code, 'EINVAL');
  await page.evaluate((id) => window.harness.call('cancel', { request: id }), request);
});

test('a malformed ask is EINVAL', async (t) => {
  const page = await connected(t);
  const replies = await page.evaluate(
    async (base, s) => {
      const run = (fields) => window.harness.sealed({ ...base, ...fields }, s);
      return {
        name: await run({ name: '1BAD' }),
        reveal: await run({ reveal: 'yes' }),
        replace: await run({ replace: 1 }),
        prompt: await run({ prompt: 'x'.repeat(201) }),
        requester: await run({ requester: undefined }),
        kind: await run({ requester: { ...base.requester, kind: 'root' } }),
        exe: await run({ requester: { ...base.requester, exe: 'fnox' } }),
        argv: await run({ requester: { ...base.requester, argv: [1] } }),
        stdin: await run({ requester: { ...base.requester, stdin: 'socket' } }),
        tty: await run({ requester: { ...base.requester, tty: 3 } }),
        who: await run({ requester: { ...base.requester, name: 7 } }),
      };
    },
    ask('MALFORMED'),
    as(2008)
  );
  for (const [key, answer] of Object.entries(replies))
    assert.equal(answer.error?.code, 'EINVAL', key);
});

test('Save waits 500 ms after the request shows, and the frame reports size, focus and Esc', async (t) => {
  const page = await connected(t);
  const { request } = await held(page, ask('GUARDED'), as(2009));
  await page.evaluate(() =>
    window.harness.frame('/value.html', false).then((f) => {
      f.id = 'value';
    })
  );
  await page.until(() => window.harness.valueEvents.some((e) => e.event === 'ready'));
  const frame = await cdp.target(/\/value\.html$/);
  await frame.evaluate(() => {
    window.guarded = new Promise((resolve) => {
      const seen = new MutationObserver(() => {
        const input = document.querySelector('input');
        const save = document.querySelector('button');
        if (!input || !save) return;
        seen.disconnect();
        const shownAt = performance.now();
        input.value = 'long-enough-value';
        input.dispatchEvent(new Event('input'));
        const poll = () =>
          save.disabled ? requestAnimationFrame(poll) : resolve(performance.now() - shownAt);
        poll();
      });
      seen.observe(document.body, { childList: true, subtree: true });
    });
  });
  await page.evaluate((id) => window.harness.value(id, { theme: 'dark' }), request);
  const waited = await frame.evaluate(() => window.guarded);
  assert.ok(waited >= 450, `Save was enabled after ${waited} ms`);
  const size = await page.until(() =>
    window.harness.valueEvents.find((e) => e.event === 'size' && e.height > 0)
  );
  assert.equal(size.inset, 2);
  assert.match(await frame.evaluate(() => document.body.className), /spectrum--dark/);
  await page.evaluate(() =>
    document
      .getElementById('value')
      .contentWindow.postMessage({ type: 'slicc-vault', v: 1, op: 'focus' }, window.harness.vault)
  );
  await frame.until(() => document.activeElement?.tagName === 'INPUT');
  const key = (code, modifiers = 0) =>
    ['rawKeyDown', 'keyUp'].map((type) =>
      frame.send('Input.dispatchKeyEvent', {
        type,
        key: code,
        code,
        modifiers,
        windowsVirtualKeyCode: code === 'Tab' ? 9 : 27,
      })
    );
  await Promise.all(key('Tab', 8));
  await Promise.all(key('Escape'));
  const moves = await page.until(() => {
    const found = window.harness.valueEvents.filter(
      (e) => e.event === 'focus' || e.event === 'escape'
    );
    return found.length === 2 && found.map((e) => e.direction ?? e.event);
  });
  assert.deepEqual(moves, ['previous', 'escape']);
  await page.evaluate((id) => window.harness.call('cancel', { request: id }), request);
});

test('the frame refuses a request it does not hold', async (t) => {
  const page = await connected(t);
  await page.evaluate(() => window.harness.value('req_000000000000000000000000'));
  const error = await page.until(() => window.harness.valueEvents.find((e) => e.event === 'error'));
  assert.deepEqual(error, {
    type: 'slicc-vault',
    v: 1,
    event: 'error',
    code: 'ENOENT',
    message: 'no such request',
  });
});

test('[reveal] agent = false refuses reveals to the agent before any dialog', async (t) => {
  const page = await connected(t);
  await page.evaluate(
    (s) =>
      window.harness.sealed(
        { v: 1, op: 'seal', name: 'NOT_FOR_AGENT', value: 'agent-must-not-see' },
        s
      ),
    as(2010)
  );
  const set = (text) =>
    page.evaluate((file) => window.harness.policy([file]), attest(POLICY, text));
  const result = await set('[reveal]\nagent = false\ncolour = "blue"\n');
  assert.deepEqual(result.files[0].warnings, ['[reveal] colour is not a setting']);
  const refused = await page.evaluate(
    (r, s) => window.harness.sealed(r, s),
    ask('NOT_FOR_AGENT', { reveal: true }, 'agent'),
    as(2010)
  );
  assert.equal(refused.error.code, 'EACCES');
  assert.match(refused.error.message, /\[reveal\] agent = false/);
  const typed = await page.evaluate(
    (r, s) => window.harness.sealed(r, s),
    ask('NEW_FOR_AGENT', { reveal: true }, 'agent'),
    as(2010)
  );
  assert.equal(typed.error.code, 'EACCES');
  const user = await held(page, ask('NOT_FOR_AGENT', { reveal: true }), as(2010));
  await page.evaluate((id) => window.harness.call('cancel', { request: id }), user.request);
  const { audit } = await page.evaluate(() => window.harness.call('audit', { limit: 10 }));
  const policy = audit.find((e) => e.type === 'policy');
  assert.deepEqual(policy.changes, [{ kind: 'reveal', field: 'agent', from: true, to: false }]);
  await set('[reveal]\nagent = true\n');
});
