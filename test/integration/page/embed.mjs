const params = new URLSearchParams(location.search);
const vault = params.get('vault');
const seen = [];
const events = [];
const egress = { requests: [], answer: null, delay: 0 };
const twins = [];
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
  const answer = egress.answer ?? { error: 'no answer configured' };
  setTimeout(() => event.ports[0].postMessage(answer), egress.delay);
}

async function twin(same = false) {
  const iframe = same ? core : await frame('/', true);
  const channel = new MessageChannel();
  const other = channel.port1;
  const welcome = new Promise((resolve) => {
    other.onmessage = (event) => {
      const data = event.data;
      if (data.op === 'welcome' || data.op === 'refused') return resolve(data);
      if (data.event === 'egress') return egressed(event);
      if (data.event) return;
      waiting.get(data.id)?.(data);
      waiting.delete(data.id);
    };
  });
  twins.push(other);
  iframe.contentWindow.postMessage({ type: 'slicc-vault', v: 1, op: 'hello', sudoGid: 27 }, vault, [
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
    const bytes = new TextEncoder().encode(chunk);
    channel.port1.postMessage({ op: 'body', chunk: bytes }, [bytes.buffer]);
  }
  channel.port1.postMessage(
    response.error ? { op: 'error', message: response.error } : { op: 'end' }
  );
  await done;
  return { reply, parts };
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

const stamp = { pid: 42, ppid: 1, uid: 1000, gid: 1000, tag: 'cone' };

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
  policy,
  forward,
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
