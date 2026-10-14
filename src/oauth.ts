import { initSync, parseRefreshResponse, refreshTokenRequestBytes } from '@ai-ecoverse/jerk-oauth';
import { unbase64url, utf8 } from './bytes.ts';
import data from './jerk-wasm.json' with { type: 'json' };

let loaded = false;

function load(): void {
  if (loaded) return;
  initSync({ module: unbase64url(data.wasm) });
  loaded = true;
}

export interface RefreshParams {
  token_url: string;
  client_id: string;
  refresh_token: string;
  scope?: string;
  resource?: string;
}

export interface Parsed {
  accessToken: string;
  refreshToken?: string;
  expiresAt?: number;
}

export function request(params: RefreshParams, seen?: (bytes: Uint8Array) => void) {
  load();
  const bytes = utf8(JSON.stringify(params));
  try {
    return refreshTokenRequestBytes(bytes) as { url: string; body: string };
  } finally {
    seen?.(bytes);
    bytes.fill(0);
  }
}

export function parse(body: string, nowSecs: number): Parsed {
  load();
  return parseRefreshResponse(body, nowSecs) as Parsed;
}
