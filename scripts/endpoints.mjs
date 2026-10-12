import { readdirSync, readFileSync, writeFileSync } from 'node:fs';

const data = new URL('../node_modules/@earendil-works/pi-ai/dist/providers/data/', import.meta.url);
const out = new URL('../src/endpoints.json', import.meta.url);

const EXTRA = [
  'https://bedrock-runtime.*.amazonaws.com',
  'https://bedrock-runtime-fips.*.amazonaws.com',
  'https://*.openai.azure.com',
  'https://*.services.ai.azure.com',
  'https://adobe-llm-proxy.paolo-moz.workers.dev',
];

function walk(value, found) {
  if (Array.isArray(value)) for (const item of value) walk(item, found);
  else if (value && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) {
      if (key === 'baseUrl' && typeof item === 'string' && item) found.add(item);
      else walk(item, found);
    }
  }
}

function pattern(url) {
  const templated = url.replace(/\{[^}]+\}/g, '*');
  const match = /^https:\/\/([^/]+)(\/.*)?$/.exec(templated);
  if (!match) throw new Error(`not an https base URL: ${url}`);
  const path = (match[2] ?? '').replace(/\/+$/, '');
  return { host: match[1].toLowerCase(), path };
}

const found = new Set(EXTRA);
for (const file of readdirSync(data).filter((name) => name.endsWith('.json'))) {
  walk(JSON.parse(readFileSync(new URL(file, data), 'utf8')), found);
}
const patterns = [...found].map(pattern);
const unique = [...new Map(patterns.map((p) => [`${p.host}${p.path}`, p])).values()].sort((a, b) =>
  `${a.host}${a.path}`.localeCompare(`${b.host}${b.path}`)
);
writeFileSync(out, `${JSON.stringify(unique, null, 2)}\n`);
