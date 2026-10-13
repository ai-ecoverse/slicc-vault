import { Server } from './api.ts';
import { purge } from './records.ts';
import { sweep } from './requests.ts';
import { start } from './vault.ts';

export const SWEEP = 60 * 1000;

export async function boot(win: Window = window): Promise<Server | null> {
  if (win.parent === win) return null;
  const queued: MessageEvent[] = [];
  let server: Server | null = null;
  const parent = win.parent;
  const ancestor = win.location.ancestorOrigins?.[0];
  const receive = (event: MessageEvent) => {
    if (ancestor && ancestor !== 'null' && event.origin !== ancestor) return;
    if (server) server.accept(event, parent);
    else queued.push(event);
  };
  win.addEventListener('message', receive);
  const vault = await start();
  server = new Server(vault);
  for (const event of queued.splice(0)) server.accept(event, parent);
  const now = vault.now();
  await Promise.all([purge(vault.db, now), sweep(vault.db, now)]);
  const running = server;
  setInterval(() => void running.sweep(), SWEEP);
  return server;
}
