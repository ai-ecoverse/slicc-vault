import { readdirSync, readFileSync, writeFileSync } from 'node:fs';

const data = new URL('../node_modules/@earendil-works/pi-ai/dist/providers/data/', import.meta.url);
const out = new URL('../src/endpoints.json', import.meta.url);

const EXTRA = [
  ['https://aiplatform.googleapis.com', 'google-vertex'],
  ['https://{AZURE_OPENAI_RESOURCE_NAME}.cognitiveservices.azure.com/openai', 'azure'],
  ['https://opencode.ai/zen', null],
  ['https://api.kimi.com/coding', null],
  ['https://bedrock-runtime.{region}.amazonaws.com', 'amazon-bedrock'],
  ['https://bedrock-runtime-fips.{region}.amazonaws.com', 'amazon-bedrock'],
  ['https://{AZURE_OPENAI_RESOURCE_NAME}.openai.azure.com', 'azure'],
  ['https://{AZURE_OPENAI_RESOURCE_NAME}.services.ai.azure.com', 'azure'],
  ['https://adobe-llm-proxy.paolo-moz.workers.dev', 'adobe'],
  ['https://cli-chat-proxy.grok.com/v1/billing', 'xai', { exact: true, methods: ['GET'] }],
];

function add(found, url, provider, only = {}) {
  const key = JSON.stringify([url, only.exact === true, only.methods ?? null]);
  const known = found.get(key) ?? { url, only, providers: new Set() };
  if (provider) known.providers.add(provider);
  found.set(key, known);
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
  const vars = [...url.matchAll(/\{([^}]+)\}/g)].map((found) => found[1]);
  const templated = url.replace(/\{[^}]+\}/g, '*');
  const match = /^https:\/\/([^/]+)(\/.*)?$/.exec(templated);
  if (!match) throw new Error(`not an https base URL: ${url}`);
  const path = (match[2] ?? '').replace(/\/+$/, '');
  return { host: match[1].toLowerCase(), path, vars };
}

const found = new Map();
for (const [url, provider, only] of EXTRA) add(found, url, provider, only);
for (const file of readdirSync(data).filter((name) => name.endsWith('.json'))) {
  walk(JSON.parse(readFileSync(new URL(file, data), 'utf8')), found);
}
const merged = new Map();
for (const { url, only, providers } of found.values()) {
  const p = { ...pattern(url), ...only };
  const key = JSON.stringify([p.host, p.path, p.exact === true, p.methods ?? null]);
  const known = merged.get(key) ?? { ...p, providers: new Set() };
  if (p.vars.length) known.vars = p.vars;
  for (const provider of providers) known.providers.add(provider);
  merged.set(key, known);
}
const unique = [...merged.values()]
  .map((p) => ({
    host: p.host,
    path: p.path,
    providers: [...p.providers].sort(),
    ...(p.vars.length ? { vars: p.vars } : {}),
    ...(p.exact ? { exact: true } : {}),
    ...(p.methods ? { methods: p.methods } : {}),
  }))
  .sort((a, b) => `${a.host}${a.path}`.localeCompare(`${b.host}${b.path}`));
writeFileSync(out, `${JSON.stringify(unique, null, 2)}\n`);
