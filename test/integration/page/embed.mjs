const params = new URLSearchParams(location.search);
const vault = params.get('vault');
const seen = [];
const events = [];
const egress = {
  requests: [],
  answer: null,
  delay: 0,
  manual: false,
  held: [],
  release(answer) {
    egress.held.shift()?.postMessage(answer);
  },
};
const twins = [];
const twinEvents = [];
const buttonEvents = [];
let port = null;
let core = null;
let next = 1;
const waiting = new Map();

function record(source, data) {
  seen.push({ source, data: JSON.stringify(data ?? null) });
}

addEventListener('message', (event) => {
  record(`window:${event.origin}`, event.data);
  if (event.data?.type === 'slicc-vault' && event.data.event) buttonEvents.push(event.data);
  const button = document.getElementById('button');
  if (event.data?.event === 'size' && button && event.source === button.contentWindow) {
    button.width = String(event.data.width);
    button.height = String(event.data.height);
  }
});

function frame(path, hidden) {
  const iframe = document.createElement('iframe');
  iframe.src = `${vault}${path}`;
  if (hidden) iframe.hidden = true;
  document.body.append(iframe);
  return new Promise((resolve) =>
    iframe.addEventListener('load', () => resolve(iframe), { once: true })
  );
}

function egressed(event) {
  egress.requests.push(event.data.request);
  if (egress.manual) return egress.held.push(event.ports[0]);
  const answer = egress.answer ?? { error: 'no answer configured' };
  setTimeout(() => event.ports[0].postMessage(answer), egress.delay);
}

async function twin(same = false, deaf = false, hello = { sudoGid: 27 }) {
  const iframe = same ? core : await frame('/', true);
  const channel = new MessageChannel();
  const other = channel.port1;
  const welcome = new Promise((resolve) => {
    other.onmessage = (event) => {
      const data = event.data;
      if (data.op === 'welcome' || data.op === 'refused') return resolve(data);
      if (data.event === 'egress') return deaf ? null : egressed(event);
      if (data.event) return twinEvents.push(data);
      waiting.get(data.id)?.(data);
      waiting.delete(data.id);
    };
  });
  twins.push(other);
  iframe.contentWindow.postMessage({ type: 'slicc-vault', v: 1, op: 'hello', ...hello }, vault, [
    channel.port2,
  ]);
  return welcome;
}

async function connect(path = '/') {
  const iframe = await frame(path, true);
  core = iframe;
  const channel = new MessageChannel();
  port = channel.port1;
  const welcome = new Promise((resolve) => {
    port.onmessage = (event) => {
      record('port', event.data);
      const data = event.data;
      if (data.op === 'welcome' || data.op === 'refused') return resolve(data);
      if (data.event === 'egress') egressed(event);
      if (data.event) return events.push(data);
      waiting.get(data.id)?.(data);
      waiting.delete(data.id);
    };
  });
  iframe.contentWindow.postMessage({ type: 'slicc-vault', v: 1, op: 'hello', sudoGid: 27 }, vault, [
    channel.port2,
  ]);
  return Promise.race([welcome, new Promise((resolve) => setTimeout(() => resolve(null), 3000))]);
}

function call(op, fields = {}, transfer = [], via = null) {
  const id = next++;
  return new Promise((resolve) => {
    waiting.set(id, resolve);
    (via ?? port).postMessage({ v: 1, id, op, ...fields }, transfer);
  });
}

async function forward(fields, response = null) {
  const channel = new MessageChannel();
  const parts = [];
  const done = new Promise((resolve) => {
    channel.port1.onmessage = (event) => {
      const data = event.data;
      parts.push(
        data.op === 'body' ? { op: 'body', text: new TextDecoder().decode(data.chunk) } : data
      );
      if (data.op === 'end' || data.op === 'error') resolve();
    };
  });
  const reply = await call('forward', fields, [channel.port2]);
  if (!response || !reply.head) return { reply, parts };
  channel.port1.postMessage({ op: 'response', ...response.head });
  for (const chunk of response.chunks) {
    if (typeof chunk !== 'string') {
      channel.port1.postMessage({ op: 'body', chunk });
      continue;
    }
    const bytes = new TextEncoder().encode(chunk);
    channel.port1.postMessage({ op: 'body', chunk: bytes }, [bytes.buffer]);
  }
  if (response.wait) await new Promise((resolve) => setTimeout(resolve, response.wait));
  channel.port1.postMessage(
    response.error ? { op: 'error', message: response.error } : { op: 'end' }
  );
  if (response.late) {
    const bytes = new TextEncoder().encode(response.late);
    channel.port1.postMessage({ op: 'body', chunk: bytes }, [bytes.buffer]);
  }
  await done;
  if (response.late) await new Promise((resolve) => setTimeout(resolve, 100));
  return { reply, parts };
}

async function stream(fields, steps) {
  const channel = new MessageChannel();
  const parts = [];
  const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  channel.port1.onmessage = (event) => {
    const data = event.data;
    parts.push(
      data.op === 'body' ? { op: 'body', text: new TextDecoder().decode(data.chunk) } : data
    );
  };
  const reply = await call('forward', fields, [channel.port2]);
  if (!reply.head) return { reply, parts };
  for (const step of steps) {
    if (step.call) await call(step.call, step.fields, [], step.twin ? twins[0] : null);
    else if (step.pause) await pause(step.pause);
    else if (step.text !== undefined) {
      const bytes = new TextEncoder().encode(step.text);
      channel.port1.postMessage({ op: 'body', chunk: bytes }, [bytes.buffer]);
    } else channel.port1.postMessage(step);
    await pause(20);
  }
  await pause(100);
  return { reply, parts };
}

async function open(fields) {
  const channel = new MessageChannel();
  const parts = [];
  channel.port1.onmessage = (event) => {
    const data = event.data;
    parts.push(
      data.op === 'body' ? { op: 'body', text: new TextDecoder().decode(data.chunk) } : data
    );
  };
  const reply = await call('forward', fields, [channel.port2]);
  window.harness.opened = { port: channel.port1, parts };
  return reply;
}

function post(step) {
  const { port } = window.harness.opened;
  if (step.text === undefined) return port.postMessage(step);
  const bytes = new TextEncoder().encode(step.text);
  port.postMessage({ op: 'body', chunk: bytes }, [bytes.buffer]);
}

let agentPort = null;
const agentWaiting = new Map();

async function agent() {
  const iframe = document.querySelector('iframe[hidden]');
  const channel = new MessageChannel();
  agentPort = channel.port1;
  const welcome = new Promise((resolve) => {
    agentPort.onmessage = (event) => {
      record('agent', event.data);
      if (event.data.op === 'welcome') return resolve(event.data);
      agentWaiting.get(event.data.id)?.(event.data);
      agentWaiting.delete(event.data.id);
    };
  });
  iframe.contentWindow.postMessage(
    { type: 'slicc-vault', v: 1, op: 'hello', role: 'agent' },
    vault,
    [channel.port2]
  );
  return welcome;
}

function ask(op, fields = {}) {
  const id = next++;
  return new Promise((resolve) => {
    agentWaiting.set(id, resolve);
    agentPort.postMessage({ v: 1, id, op, ...fields });
  });
}

const stamp = { pid: 42, ppid: 1, uid: 1000, gid: 1000, tag: 'cone', users: 'enforce' };

async function sealed(req, as = stamp) {
  return (await call('sealed', { req, stamp: as })).reply;
}

async function button(config) {
  const iframe = await frame('/button.html', false);
  iframe.id = 'button';
  iframe.style.border = '0';
  iframe.contentWindow.postMessage(
    { type: 'slicc-vault', v: 1, op: 'button', button: config },
    vault
  );
  return true;
}

function configure(config) {
  document
    .getElementById('button')
    .contentWindow.postMessage({ type: 'slicc-vault', v: 1, op: 'button', button: config }, vault);
}

function policy(files) {
  const decoded = files.map((file) =>
    typeof file.bytes === 'string'
      ? { ...file, bytes: Uint8Array.from(atob(file.bytes), (char) => char.charCodeAt(0)) }
      : file
  );
  return call('policy', { files: decoded });
}

window.harness = {
  egress,
  twin,
  twins,
  twinEvents,
  policy,
  forward,
  stream,
  open,
  post,
  agent,
  ask,
  vault,
  seen,
  events,
  buttonEvents,
  connect,
  call,
  sealed,
  stamp,
  button,
  configure,
  frame,
};
document.title = 'ready';
