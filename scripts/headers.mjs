import { writeFile } from 'node:fs/promises';

export const CONTENT_TYPES = {
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json',
  '.wasm': 'application/wasm',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
};

export const PRODUCTION_EMBEDDERS = ['https://seven.sliccy.ai', 'https://www.sliccy.ai'];

export const CONFIG_EMBEDDERS = ['https://seven.sliccy.ai'];

const DIRECTIVES = [
  "default-src 'none'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self' https: http://localhost:* http://127.0.0.1:*",
  "worker-src 'self'",
  "manifest-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
];

export const CLASSES = [
  {
    name: 'documents',
    paths: ['/', '/index.html', '/button.html', '/value.html', '/popup.html'],
    extension: '.html',
  },
  { name: 'scripts', extensions: ['.js'], extension: '.js' },
  { name: 'css', extensions: ['.css'], extension: '.css' },
  { name: 'fonts', extensions: ['.woff2'], extension: '.woff2' },
  { name: 'wasm', extensions: ['.wasm'], extension: '.wasm' },
  { name: 'config.json', paths: ['/config.json'], extension: '.json' },
  { name: 'embedders.json', paths: ['/embedders.json'], extension: '.json' },
];

export function frameAncestors(embedders) {
  return embedders.join(' ') || "'none'";
}

export function contentSecurityPolicy(embedders) {
  return [...DIRECTIVES, `frame-ancestors ${frameAncestors(embedders)}`].join('; ');
}

export function vaultHeaders(embedders) {
  return {
    'content-security-policy': contentSecurityPolicy(embedders),
    'cross-origin-embedder-policy': 'require-corp',
    'cross-origin-resource-policy': 'same-site',
    'cross-origin-opener-policy': 'same-origin',
    'origin-agent-cluster': '?1',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'cache-control': 'no-cache',
  };
}

export const pageHeaders = {
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-embedder-policy': 'require-corp',
  'cross-origin-resource-policy': 'same-origin',
  'cache-control': 'no-cache',
};

export function contentType(extension) {
  return CONTENT_TYPES[extension] ?? 'application/octet-stream';
}

export function servedHeaders(embedders, extension) {
  const headers = vaultHeaders(embedders);
  if (extension === '.html') headers['cache-control'] = 'no-store';
  if (extension) headers['content-type'] = contentType(extension);
  return headers;
}

export function siteVersion(override, packaged) {
  return override ?? packaged;
}

export function siteConfig(version) {
  return { version, embedders: [...CONFIG_EMBEDDERS] };
}

export function headersDocument() {
  const classes = {};
  for (const spec of CLASSES) {
    classes[spec.name] = {
      ...(spec.paths ? { paths: spec.paths } : {}),
      ...(spec.extensions ? { extensions: spec.extensions } : {}),
      headers: servedHeaders(PRODUCTION_EMBEDDERS, spec.extension),
    };
  }
  return {
    classes,
    contentTypes: {
      '.wasm': CONTENT_TYPES['.wasm'],
      '.woff2': CONTENT_TYPES['.woff2'],
      '.js': CONTENT_TYPES['.js'],
      '.css': CONTENT_TYPES['.css'],
      '.json': CONTENT_TYPES['.json'],
      '.html': CONTENT_TYPES['.html'],
    },
    frameAncestors: {
      shape:
        "space-separated embedder sources, each an http:// or https:// host with an optional :port or :*; an empty list is 'none'",
      production: [...PRODUCTION_EMBEDDERS],
    },
    embedders: { embedders: [...PRODUCTION_EMBEDDERS] },
    config: { version: '<version>', embedders: [...CONFIG_EMBEDDERS] },
    productionOnly: {
      'strict-transport-security': 'max-age=31536000',
      etag: "the stored object's httpEtag; absent on /embedders.json",
      'x-sliccy-ai-version': 'the worker version id',
    },
  };
}

export async function writeHeaders(file) {
  await writeFile(file, `${JSON.stringify(headersDocument(), null, 2)}\n`);
}
