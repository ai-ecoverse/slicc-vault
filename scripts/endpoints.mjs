import { readdirSync, readFileSync, writeFileSync } from 'node:fs';

const data = new URL('../node_modules/@earendil-works/pi-ai/dist/providers/data/', import.meta.url);
const out = new URL('../src/endpoints.json', import.meta.url);

const EXTRA = [
  ['https://bedrock-runtime.*.amazonaws.com', 'amazon-bedrock'],
  ['https://bedrock-runtime-fips.*.amazonaws.com', 'amazon-bedrock'],
  ['https://*.openai.azure.com', 'azure'],
  ['https://*.services.ai.azure.com', 'azure'],
  ['https://adobe-llm-proxy.paolo-moz.workers.dev', null],
];

function add(found, url, provider) {
  const providers = found.get(url) ?? new Set();
  if (provider) providers.add(provider);
  found.set(url, providers);
}

function walk(value, found) {
  if (Array.isArray(value)) for (const item of value) walk(item, found);
  else if (value && typeof value === 'object') {
    if (typeof value.baseUrl === 'string' && value.baseUrl) {
      add(found, value.baseUrl, typeof value.provider === 'string' ? value.provider : null);
    }
    for (const [key, item] of Object.entries(value)) if (key !== 'baseUrl') walk(item, found);
  }
}

function pattern(url) {
  const templated = url.replace(/\{[^}]+\}/g, '*');
  const match = /^https:\/\/([^/]+)(\/.*)?$/.exec(templated);
  if (!match) throw new Error(`not an https base URL: ${url}`);
  const path = (match[2] ?? '').replace(/\/+$/, '');
  return { host: match[1].toLowerCase(), path };
}

const found = new Map();
for (const [url, provider] of EXTRA) add(found, url, provider);
for (const file of readdirSync(data).filter((name) => name.endsWith('.json'))) {
  walk(JSON.parse(readFileSync(new URL(file, data), 'utf8')), found);
}
const merged = new Map();
for (const [url, providers] of found) {
  const p = pattern(url);
  const key = `${p.host}${p.path}`;
  const known = merged.get(key) ?? { ...p, providers: new Set() };
  for (const provider of providers) known.providers.add(provider);
  merged.set(key, known);
}
const unique = [...merged.values()]
  .map((p) => ({ host: p.host, path: p.path, providers: [...p.providers].sort() }))
  .sort((a, b) => `${a.host}${a.path}`.localeCompare(`${b.host}${b.path}`));
writeFileSync(out, `${JSON.stringify(unique, null, 2)}\n`);
