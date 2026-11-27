const params = new URLSearchParams(location.search);
const vault = params.get('vault');
const frames = [];
const bus = [];

addEventListener('message', (event) => {
  bus.push({ origin: event.origin, data: event.data });
});

function load(src, style) {
  const iframe = document.createElement('iframe');
  iframe.src = src;
  iframe.style.cssText = style;
  document.body.append(iframe);
  return new Promise((resolve) =>
    iframe.addEventListener('load', () => resolve(iframe), { once: true })
  );
}

async function mount(options = {}) {
  const style =
    options.style ??
    'width: 420px; height: 72px; border: 0; display: inline-block; margin: 4px; vertical-align: top;';
  const iframe = await load(`${vault}/scrub.html`, style);
  if (options.id) iframe.id = options.id;
  const channel = new MessageChannel();
  const replies = [];
  const waiting = new Map();
  channel.port1.onmessage = (event) => {
    replies.push(event.data);
    const id = event.data?.id;
    if (id !== undefined && waiting.has(id)) {
      waiting.get(id)(event.data);
      waiting.delete(id);
    }
  };
  const welcome = new Promise((resolve) => {
    const prior = channel.port1.onmessage;
    channel.port1.onmessage = (event) => {
      prior(event);
      if (event.data?.op === 'welcome') resolve(event.data);
    };
  });
  const hello =
    options.hello === undefined
      ? { type: 'slicc-vault', v: 1, op: 'scrub', config: options.config }
      : options.hello;
  const target = options.targetOrigin ?? vault;
  const ports = options.ports === undefined ? [channel.port2] : options.ports;
  if (hello !== null) iframe.contentWindow.postMessage(hello, target, ports);
  else channel.port2.close();
  const entry = { iframe, port: channel.port1, replies, waiting, welcome: null };
  frames.push(entry);
  if (options.wait === false) return entry;
  entry.welcome = await Promise.race([
    welcome,
    new Promise((resolve) => setTimeout(() => resolve(null), options.timeout ?? 2000)),
  ]);
  return entry;
}

function awaitId(entry, id, ms = 20000) {
  return new Promise((resolve, reject) => {
    const found = entry.replies.find((row) => row && row.id === id && row.op !== 'welcome');
    if (found) return resolve(found);
    const timer = setTimeout(() => {
      entry.waiting.delete(id);
      reject(new Error(`no reply for ${id}`));
    }, ms);
    entry.waiting.set(id, (data) => {
      clearTimeout(timer);
      resolve(data);
    });
  });
}

function post(entry, fields) {
  entry.port.postMessage({ v: 1, ...fields });
}

function call(entry, fields) {
  const id = fields.id;
  post(entry, fields);
  return awaitId(entry, id);
}

async function mounts(count, options = {}) {
  const out = [];
  for (let i = 0; i < count; i++) out.push(await mount({ ...options, id: `scrub-${i}` }));
  return out;
}

window.harness = {
  vault,
  frames,
  bus,
  mount,
  mounts,
  call,
  post,
  awaitId,
  load,
};
document.title = 'ready';
