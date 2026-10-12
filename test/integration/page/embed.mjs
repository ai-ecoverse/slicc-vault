const params = new URLSearchParams(location.search);
const vault = params.get('vault');
const seen = [];
const events = [];
const buttonEvents = [];
let port = null;
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

async function connect(path = '/') {
  const iframe = await frame(path, true);
  const channel = new MessageChannel();
  port = channel.port1;
  const welcome = new Promise((resolve) => {
    port.onmessage = (event) => {
      record('port', event.data);
      const data = event.data;
      if (data.op === 'welcome' || data.op === 'refused') return resolve(data);
      if (data.event) return events.push(data);
      waiting.get(data.id)?.(data);
      waiting.delete(data.id);
    };
  });
  iframe.contentWindow.postMessage({ type: 'slicc-vault', v: 1, op: 'hello' }, vault, [
    channel.port2,
  ]);
  return Promise.race([welcome, new Promise((resolve) => setTimeout(() => resolve(null), 3000))]);
}

function call(op, fields = {}) {
  const id = next++;
  return new Promise((resolve) => {
    waiting.set(id, resolve);
    port.postMessage({ v: 1, id, op, ...fields });
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

window.harness = {
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
