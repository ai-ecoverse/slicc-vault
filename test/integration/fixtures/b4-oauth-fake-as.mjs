import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';

const here = fileURLToPath(new URL('.', import.meta.url));
const port = Number(process.argv[2] ?? 0);
const casesFile = process.argv[3] ?? `${here}b4-oauth-refresh-cases.json`;
const { cases } = JSON.parse(readFileSync(casesFile, 'utf8'));
const byId = new Map(cases.filter((c) => c.setup?.response).map((c) => [c.id, c.setup.response]));
const MARK = 'TOKMARK7f3a';
const live = new Set([`${MARK}-rt1`]);
let rotate = true;
const log = [];

const server = createServer((req, res) => {
  let raw = '';
  req.on('data', (chunk) => (raw += chunk));
  req.on('end', () => {
    const url = new URL(req.url, 'http://fake-as');
    log.push({ method: req.method, path: url.pathname, body: raw });
    const canned =
      url.pathname.startsWith('/case/') && byId.get(decodeURIComponent(url.pathname.slice(6)));
    if (canned) {
      res.writeHead(canned.status, canned.headers ?? { 'content-type': 'application/json' });
      return res.end(canned.body);
    }
    if (url.pathname === '/rotation/mode') {
      rotate = url.searchParams.get('rotate') !== 'false';
      live.clear();
      for (const t of (url.searchParams.get('live') ?? '').split(',').filter(Boolean)) live.add(t);
      res.writeHead(204);
      return res.end();
    }
    if (url.pathname === '/log') {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify(log));
    }
    if (url.pathname === '/token' && req.method === 'POST') {
      const form = new URLSearchParams(raw);
      res.setHeader('content-type', 'application/json');
      if (form.get('grant_type') !== 'refresh_token') {
        res.writeHead(400);
        return res.end(JSON.stringify({ error: 'unsupported_grant_type' }));
      }
      const rt = form.get('refresh_token');
      if (!live.has(rt)) {
        res.writeHead(400);
        return res.end(
          JSON.stringify({ error: 'invalid_grant', error_description: 'refresh token reused' })
        );
      }
      live.delete(rt);
      const n = Number(rt.split('-rt')[1] ?? 1) + 1;
      if (!rotate)
        return res.end(
          JSON.stringify({ access_token: `${MARK}-at${n}`, expires_in: 60, token_type: 'Bearer' })
        );
      live.add(`${MARK}-rt${n}`);
      return res.end(
        JSON.stringify({
          access_token: `${MARK}-at${n}`,
          refresh_token: `${MARK}-rt${n}`,
          expires_in: 60,
          token_type: 'Bearer',
        })
      );
    }
    res.writeHead(404);
    res.end();
  });
});
server.listen(port, '127.0.0.1', () => {
  process.stdout.write(`fake-as on http://127.0.0.1:${server.address().port}\n`);
});
