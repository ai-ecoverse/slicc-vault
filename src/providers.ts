import type { OAuthConfig } from './records.ts';

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
};

export function signIn(provider: string): OAuthConfig | null {
  return Object.hasOwn(SIGN_INS, provider) ? { ...SIGN_INS[provider] } : null;
}
