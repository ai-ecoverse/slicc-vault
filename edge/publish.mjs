import { readdirSync, readFileSync, realpathSync } from 'node:fs';
import { join, relative } from 'node:path';
import { argv, env, stdout } from 'node:process';
import { fileURLToPath } from 'node:url';

export const ROUTE = 'https://seven.sliccy.ai/api/publish';
export const AUDIENCE = 'https://sliccy.ai';
const root = fileURLToPath(new URL('../dist/site/', import.meta.url));
const served = new Set(['embedders.json']);

export function files(dir = root) {
  return readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => relative(dir, join(entry.parentPath, entry.name)).split('\\').join('/'))
    .filter((file) => !served.has(file))
    .sort();
}

export async function oidc(fetcher = fetch) {
  const url = new URL(env.ACTIONS_ID_TOKEN_REQUEST_URL);
  url.searchParams.set('audience', AUDIENCE);
  const response = await fetcher(url, {
    headers: { authorization: `Bearer ${env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}` },
  });
  if (!response.ok) throw new Error(`GitHub's OIDC token: ${response.status}`);
  return (await response.json()).value;
}

function encoded(file) {
  return file.split('/').map(encodeURIComponent).join('/');
}

export async function publish({ fetcher = fetch, token, dir = root, parallel = 8 } = {}) {
  const authorization = `Bearer ${token ?? (await oidc(fetcher))}`;
  const call = async (path, init = {}) => {
    const response = await fetcher(`${ROUTE}/${path}`, {
      ...init,
      headers: { authorization, ...init.headers },
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(`${path}: ${response.status} ${body.error ?? ''}`.trim());
    return body;
  };
  const { files: before = [] } = await call('manifest');
  const current = files(dir);
  const queue = [...current];
  const put = async () => {
    for (let file = queue.shift(); file; file = queue.shift()) {
      const bytes = readFileSync(join(dir, file));
      await call(`files/${encoded(file)}`, {
        method: 'PUT',
        headers: { 'content-length': String(bytes.length) },
        body: bytes,
      });
    }
  };
  await Promise.all(Array.from({ length: parallel }, put));
  for (const file of before.filter((file) => !current.includes(file))) {
    await call(`files/${encoded(file)}`, { method: 'DELETE' });
  }
  const done = await call('manifest', { method: 'PUT', body: JSON.stringify({ files: current }) });
  return done.url ?? '';
}

export function isMain(script = argv[1], self = fileURLToPath(import.meta.url)) {
  return Boolean(script) && realpathSync(script) === realpathSync(self);
}

if (isMain()) {
  const url = await publish();
  stdout.write(`publish: PASS ${url} ${env.GITHUB_SHA ?? 'local'}\n`);
}
