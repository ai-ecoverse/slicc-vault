import type { OAuthConfig } from './records.ts';

export const COPILOT = 'github-copilot';
export const COPILOT_TOKEN_URL = 'https://api.github.com/copilot_internal/v2/token';

export const SIGN_INS: Readonly<Record<string, OAuthConfig>> = {
  xai: {
    tokenUrl: 'https://auth.x.ai/oauth2/token',
    clientId: 'b1a00492-073a-47ea-816f-4c329264a828',
    bearer: 'default',
  },
  'kimi-coding': {
    tokenUrl: 'https://auth.kimi.com/api/oauth/token',
    clientId: '17e5f671-d194-4dfb-9706-5516cb48c098',
    bearer: 'default',
  },
  'openai-codex': {
    tokenUrl: 'https://auth.openai.com/oauth/token',
    clientId: 'app_EMoamEEZ73f0CkXaXp7hrann',
    bearer: 'default',
  },
  [COPILOT]: {
    tokenUrl: COPILOT_TOKEN_URL,
    clientId: 'Iv1.b507a08c87ecfe98',
    bearer: 'default',
  },
};

export function signIn(provider: string): OAuthConfig | null {
  return Object.hasOwn(SIGN_INS, provider) ? { ...SIGN_INS[provider] } : null;
}
