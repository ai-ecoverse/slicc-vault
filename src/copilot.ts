import { text } from './bytes.ts';
import { COPILOT, COPILOT_TOKEN_URL } from './providers.ts';
import type { VaultRecord } from './records.ts';
import type { EgressRequest, EgressResponse } from './refresh.ts';

export const COPILOT_HEADERS: readonly [string, string][] = [
  ['editor-version', 'vscode/1.107.0'],
  ['editor-plugin-version', 'copilot-chat/0.35.0'],
  ['copilot-integration-id', 'vscode-chat'],
];

export const COPILOT_MARGIN = 5 * 60;

export function exchanges(record: VaultRecord, grant: VaultRecord): boolean {
  return (
    !record.kernelOAuth &&
    record.source === `oauth:${COPILOT}` &&
    grant.oauth?.tokenUrl === COPILOT_TOKEN_URL
  );
}

export function exchangeRequest(token: string): EgressRequest {
  return {
    method: 'GET',
    url: COPILOT_TOKEN_URL,
    headers: [
      ['authorization', `Bearer ${token}`],
      ['accept', 'application/json'],
      ...COPILOT_HEADERS,
    ],
    body: '',
  };
}

const failure = (response: EgressResponse, error: string): EgressResponse => ({
  status: 400,
  headers: response.headers,
  body: JSON.stringify({ error }),
});

export function exchanged(response: EgressResponse, nowSecs: number): EgressResponse {
  if (response.status === 401) return failure(response, 'invalid_grant');
  if (response.status < 200 || response.status > 299) return response;
  let parsed: { token?: unknown; expires_at?: unknown } | null = null;
  try {
    parsed = JSON.parse(typeof response.body === 'string' ? response.body : text(response.body));
  } catch {}
  const token = parsed?.token;
  const at = parsed?.expires_at;
  if (typeof token !== 'string' || !Number.isSafeInteger(at))
    return failure(response, 'invalid_copilot_token');
  return {
    status: 200,
    headers: response.headers,
    body: JSON.stringify({
      access_token: token,
      token_type: 'Bearer',
      expires_in: Math.max(0, (at as number) - nowSecs - COPILOT_MARGIN),
    }),
  };
}
