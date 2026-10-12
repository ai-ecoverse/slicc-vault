import { cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { env } from 'node:process';
import { build } from 'esbuild';

const out = new URL('./dist/site/', import.meta.url);
const manifest = JSON.parse(await readFile(new URL('./package.json', import.meta.url), 'utf8'));

await rm(out, { recursive: true, force: true });
await mkdir(out, { recursive: true });
await build({
  entryPoints: {
    frame: 'src/entry/frame.ts',
    button: 'src/entry/button.ts',
    popup: 'src/entry/popup.ts',
    vault: 'src/vault.css',
  },
  outdir: out.pathname,
  bundle: true,
  format: 'esm',
  platform: 'browser',
  target: 'es2024',
  minify: true,
  sourcemap: 'linked',
  legalComments: 'linked',
  external: ['/fonts/*'],
  logLevel: 'warning',
});
await cp(new URL('./src/html/', import.meta.url), out, { recursive: true });
await cp(new URL('./src/fonts/', import.meta.url), new URL('fonts/', out), { recursive: true });
const config = {
  version: env.VAULT_VERSION ?? manifest.version,
  embedders: ['https://seven.sliccy.ai'],
};
await writeFile(new URL('config.json', out), `${JSON.stringify(config, null, 2)}\n`);
