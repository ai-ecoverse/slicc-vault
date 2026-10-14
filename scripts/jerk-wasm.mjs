import { readFileSync, writeFileSync } from 'node:fs';

const wasm = new URL(
  '../node_modules/@ai-ecoverse/jerk-oauth/jerk_oauth_wasm_bg.wasm',
  import.meta.url
);
const out = new URL('../src/jerk-wasm.json', import.meta.url);
writeFileSync(out, `${JSON.stringify({ wasm: readFileSync(wasm).toString('base64url') })}\n`);
