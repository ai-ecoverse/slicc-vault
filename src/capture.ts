import { type Config, load } from './config.ts';

export const HANDLE = 'slicc-vault';

const ORIGIN = /^https?:\/\/[a-z0-9.-]+(?::\d+)?$/;

interface CaptureHandleConfig {
  handle: string;
  exposeOrigin: boolean;
  permittedOrigins: string[];
}

type Media = { setCaptureHandleConfig?: (config: CaptureHandleConfig) => void };

export function permitted(config: Config): string[] {
  return config.embedders.filter((source) => ORIGIN.test(source));
}

export async function announce(
  win: Window = window,
  config: () => Promise<Config> = load
): Promise<void> {
  const media = win.navigator.mediaDevices as Media | undefined;
  if (win.top !== win || typeof media?.setCaptureHandleConfig !== 'function') return;
  const permittedOrigins = permitted(await config());
  media.setCaptureHandleConfig({ handle: HANDLE, exposeOrigin: true, permittedOrigins });
}
