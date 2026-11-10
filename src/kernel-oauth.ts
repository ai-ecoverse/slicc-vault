import type { Scrubber } from '@ai-ecoverse/slicc-scrub';
import { hex, random } from './bytes.ts';
import type {
  KernelOAuthConfig,
  KernelOAuthIdentity,
  KernelOAuthStatus,
  Stamp,
} from './contract.ts';
import { request, transact } from './db.ts';
import { Refused } from './errors.ts';
import { keyGuard, OAuthBudget, oauthError, oauthValues } from './oauth-control.ts';
import {
  checkName,
  checkValue,
  type KernelOwnership,
  type MutationGuard,
  ownsGrant,
  RESTORABLE,
  records,
  remove,
  type SealInput,
  sameRecord,
  scrubIn,
  sealAll,
  type VaultRecord,
} from './records.ts';
import { checkOAuth } from './refresh.ts';
import { checkStamp, MAX_REQUEST, mayManage, parse, size } from './sealed.ts';
import type { Vault } from './vault.ts';

type Fields = Record<string, unknown>;
const IDENTITY = ['v', 'op', 'name', 'provider', 'account'];
const GRANT = [...IDENTITY, 'accessToken', 'refreshToken', 'tokenType', 'expiresAt', 'oauth'];
const RESERVED = ['auth', 'clientSecret', 'client_secret', 'fields'];
const MAX_LIFETIME = 315360000000;
const CONTROL = /[\x00-\x1f\x7f-\x9f]/;

function keys(fields: Fields, allowed: string[]): void {
  if (RESERVED.some((key) => Object.hasOwn(fields, key))) throw new Refused('ENOTSUP', '');
  if (Object.keys(fields).some((key) => !allowed.includes(key))) throw new Refused('EINVAL', '');
}

function identity(fields: Fields): KernelOAuthIdentity {
  const name = checkName(fields.name);
  const { provider, account } = fields;
  if (typeof provider !== 'string' || !/^[a-z0-9][a-z0-9-]{0,127}$/.test(provider)) {
    throw new Refused('EINVAL', '');
  }
  if (typeof account !== 'string' || !account || account.length > 256 || CONTROL.test(account)) {
    throw new Refused('EINVAL', '');
  }
  return { name, provider, account };
}

function config(value: unknown): KernelOAuthConfig {
  const fields = parse(value);
  keys(fields, ['tokenUrl', 'clientId', 'authMethod', 'scope', 'resource']);
  if (typeof fields.authMethod !== 'string') throw new Refused('EINVAL', '');
  if (fields.authMethod !== 'none') throw new Refused('ENOTSUP', '');
  const raw = fields.tokenUrl;
  if (typeof raw !== 'string' || /[\s\\#]/.test(raw)) throw new Refused('EINVAL', '');
  const path = raw.replace(/^[a-z]+:\/\/[^/]+/i, '').split('?')[0];
  if (/(?:^|\/)\.{1,2}(?:\/|$)|%2e|%2f|%5c|%25/i.test(path)) throw new Refused('EINVAL', '');
  const checked = checkOAuth(fields);
  if (
    [checked.clientId, checked.scope ?? '', checked.resource ?? ''].some((s) => CONTROL.test(s))
  ) {
    throw new Refused('EINVAL', '');
  }
  return {
    tokenUrl: checked.tokenUrl,
    clientId: checked.clientId,
    authMethod: 'none',
    ...(checked.scope === undefined ? {} : { scope: checked.scope }),
    ...(checked.resource === undefined ? {} : { resource: new URL(checked.resource).href }),
  };
}

function matching(record: VaultRecord, id: KernelOAuthIdentity): void {
  const owner = record.kernelOAuth;
  if (
    owner &&
    (owner.provider !== id.provider || owner.account !== id.account || owner.name !== id.name)
  ) {
    throw new Refused('EEXIST', '');
  }
}

function live(record: VaultRecord | undefined, now: number): VaultRecord | undefined {
  return record?.removedAt !== undefined && now - record.removedAt > RESTORABLE
    ? undefined
    : record;
}

function selected(held: VaultRecord[], id: KernelOAuthIdentity, now: number): VaultRecord {
  const record = live(
    held.find((r) => r.kind === 'secret' && r.name === id.name),
    now
  );
  if (!record?.kernelOAuth) throw new Refused('ENOENT', '');
  matching(record, id);
  return record;
}

function manage(vault: Vault, ns: string, stamp: Stamp, record?: VaultRecord): void {
  if (!mayManage(stamp, vault.sudoGids.get(ns) ?? null)) throw new Refused('EACCES', '');
  if (record?.kernelOAuth && stamp.uid !== 0 && record.kernelOAuth.uid !== stamp.uid) {
    throw new Refused('EEXIST', '');
  }
  if (record && !record.kernelOAuth && record.source !== 'process' && stamp.uid !== 0) {
    throw new Refused('EEXIST', '');
  }
}

function immutable(before: KernelOwnership, oauth: KernelOAuthConfig): void {
  const { scope: _old, ...old } = before.oauth;
  const { scope: _new, ...next } = oauth;
  if (JSON.stringify(old) !== JSON.stringify(next)) throw new Refused('EEXIST', '');
}

function hasValue(scrubber: Scrubber, value: string): boolean {
  return scrubber.text(value).hits.some((hit) => hit.form !== 'fragment');
}

function revisions(
  ns: string,
  entries: [string, string, VaultRecord | undefined][]
): MutationGuard['validate'] {
  return async (tx) => {
    const store = tx.objectStore('records');
    for (const [kind, name, seen] of entries) {
      const current = (await request(store.get([ns, kind, name]))) as VaultRecord | undefined;
      if (!sameRecord(seen, current)) throw new Refused('EAGAIN', '');
    }
  };
}

async function status(
  vault: Vault,
  ns: string,
  id: KernelOAuthIdentity,
  budget: OAuthBudget
): Promise<KernelOAuthStatus> {
  const held = await records(vault.db, ns);
  const record = selected(held, id, vault.now());
  const grant = held.find((r) => r.kind === 'grant' && r.name === record.refresh);
  const valid = ownsGrant(record, grant) && grant?.removedAt === undefined && !grant?.dead;
  const refreshable = record.removedAt === undefined && valid;
  const locked = vault.keyring.locked;
  const scrubber = await vault.scrubbers.get(ns);
  let expiresAt = record.expiresAt ?? null;
  if (expiresAt !== null && (!scrubber || hasValue(scrubber, String(expiresAt)))) {
    if (!locked) throw new Refused('EACCES', '');
    expiresAt = null;
  }
  await transact(vault.db, ['records', 'meta'], 'readonly', async (tx) => {
    await revisions(ns, [
      ['secret', id.name, record],
      ...(grant ? [['grant', grant.name, grant] as [string, string, VaultRecord]] : []),
    ])!(tx);
    const version = await scrubIn(tx, ns);
    if (locked && (!scrubber || version !== scrubber.version)) expiresAt = null;
    else if (scrubber && version !== scrubber.version) throw new Refused('EAGAIN', '');
    budget.check();
  });
  return {
    v: 1,
    placeholder: record.placeholder,
    state: locked
      ? 'locked'
      : record.removedAt !== undefined
        ? 'removed'
        : record.refresh && !valid
          ? 'reauth-required'
          : record.expiresAt === undefined || record.expiresAt > vault.now()
            ? 'ready'
            : refreshable
              ? 'refreshing'
              : 'expired',
    expiresAt,
    refreshable,
  };
}

function bearer(value: unknown): void {
  if (value !== undefined && typeof value !== 'string') throw new Refused('EINVAL', '');
  if (typeof value === 'string' && !/^bearer$/i.test(value)) throw new Refused('ENOTSUP', '');
}

async function grant(
  vault: Vault,
  ns: string,
  fields: Fields,
  stamp: Stamp,
  id: KernelOAuthIdentity,
  budget: OAuthBudget
): Promise<void> {
  const held = await (budget.admitted ?? records(vault.db, ns));
  const seen = held.find((r) => r.kind === 'secret' && r.name === id.name);
  const record = live(seen, vault.now());
  manage(vault, ns, stamp, record);
  if (record) matching(record, id);
  const oauth = config(fields.oauth);
  if (record?.kernelOAuth) immutable(record.kernelOAuth, oauth);
  bearer(fields.tokenType);
  const access = checkValue(fields.accessToken);
  const refresh = fields.refreshToken === undefined ? undefined : checkValue(fields.refreshToken);
  const expiresAt = fields.expiresAt;
  if (
    expiresAt !== undefined &&
    (typeof expiresAt !== 'number' ||
      !Number.isSafeInteger(expiresAt) ||
      expiresAt < 0 ||
      expiresAt - vault.now() > MAX_LIFETIME)
  ) {
    throw new Refused('EINVAL', '');
  }
  const check = keyGuard(vault.keyring, budget);
  const scrubber = (await vault.scrubbers.get(ns)) as Scrubber;
  check();
  const metadata = [
    'oauth:kernel',
    ...Object.values(id),
    ...Object.values(oauth),
    String(stamp.uid),
    ...(expiresAt === undefined ? [] : [String(expiresAt)]),
  ];
  const tokenId = record?.kernelOAuth?.id ?? hex(random(12));
  const owner: KernelOwnership = {
    ...id,
    uid: record?.kernelOAuth?.uid ?? stamp.uid,
    id: tokenId,
    oauth,
  };
  const previous = record?.refresh
    ? held.find((r) => r.kind === 'grant' && r.name === record.refresh)
    : undefined;
  const own = record && ownsGrant(record, previous);
  const grantName = own ? previous!.name : `KERNEL_OAUTH_${hex(random(12))}`;
  const collision = held.find((r) => r.kind === 'grant' && r.name === grantName);
  if (collision && !own) throw new Refused('EEXIST', '');
  metadata.push(grantName, tokenId);
  const incoming = oauthValues([access, ...(refresh === undefined ? [] : [refresh])], metadata);
  if (metadata.some((s) => hasValue(scrubber, s))) throw new Refused('EINVAL', '');
  const tag = stamp.tag === null ? null : incoming.text(scrubber.text(stamp.tag).text).text;
  const common = {
    ns,
    source: 'oauth:kernel' as const,
    uid: stamp.uid,
    tag,
    now: vault.now(),
    kernelOAuth: owner,
  };
  const inputs: SealInput[] = [
    {
      ...common,
      kind: 'secret',
      name: id.name,
      value: access,
      ...(expiresAt === undefined ? {} : { expiresAt: expiresAt as number }),
      ...(refresh === undefined ? {} : { refresh: grantName }),
      ...(own ? { claim: { grant: grantName, retire: refresh === undefined } } : {}),
    },
  ];
  if (refresh !== undefined)
    inputs.push({ ...common, kind: 'grant', name: grantName, value: refresh, oauth });
  const validate = revisions(ns, [
    ['secret', id.name, seen],
    ['grant', grantName, collision],
  ]);
  await sealAll(vault.db, vault.keyring.use(), inputs, {
    check,
    async validate(tx) {
      await validate!(tx);
      if ((await scrubIn(tx, ns)) !== scrubber.version) throw new Refused('EAGAIN', '');
    },
  });
  await vault.changed(ns, ['secrets', 'audit']);
}

function refreshable(result: KernelOAuthStatus): void {
  if (result.state === 'locked') throw new Refused('EACCES', '', 'vault-locked');
  if (result.state === 'removed') throw new Refused('EACCES', '');
  if (result.state === 'reauth-required') throw new Refused('EACCES', '', 'oauth-reauth-required');
  if (!result.refreshable) throw new Refused('ENOTSUP', '');
}

async function refresh(
  vault: Vault,
  ns: string,
  id: KernelOAuthIdentity,
  budget: OAuthBudget
): Promise<void> {
  refreshable(await status(vault, ns, id, budget));
  const admitted = (await budget.admitted)?.find((r) => r.kind === 'secret' && r.name === id.name);
  if (admitted) {
    const current = selected(await records(vault.db, ns), id, vault.now());
    if (!sameRecord(admitted, current)) return;
  }
  await vault.refresher.refresh(ns, id.name, 'secret', budget);
}

export async function kernelOAuth(
  vault: Vault,
  ns: string,
  req: unknown,
  stamp: unknown,
  marker: unknown,
  budget = new OAuthBudget()
): Promise<Fields> {
  try {
    budget.check();
    if (size(req) > MAX_REQUEST) throw new Refused('EINVAL', '');
    const fields = parse(req);
    if (fields.v !== 1) throw new Refused('EINVAL', '');
    const caller = checkStamp(stamp);
    if (fields.op === 'capabilities') {
      keys(fields, ['v', 'op']);
      return { v: 1, capabilities: marker === 1 ? { kernelOAuth: 1 } : {} };
    }
    keys(fields, fields.op === 'oauthGrant' ? GRANT : IDENTITY);
    if (marker !== 1) throw new Refused('ENOTSUP', '');
    const id = identity(fields);
    if (fields.op === 'oauthGrant') await grant(vault, ns, fields, caller, id, budget);
    else if (fields.op === 'oauthRemove') {
      const held = await records(vault.db, ns);
      const record = selected(held, id, vault.now());
      manage(vault, ns, caller, record);
      await remove(vault.db, ns, id.name, vault.now(), 'secret', {
        check: () => budget.check(),
        validate: revisions(ns, [['secret', id.name, record]]),
      });
      await vault.changed(ns, ['secrets', 'audit']);
      budget.check();
      return { v: 1, removed: true };
    } else if (fields.op === 'oauthRefresh') {
      if (caller.users !== 'enforce') throw new Refused('EACCES', '');
      await refresh(vault, ns, id, budget);
    } else if (fields.op !== 'oauthStatus') throw new Refused('EINVAL', '');
    const result = await status(vault, ns, id, budget);
    if (fields.op === 'oauthRefresh') refreshable(result);
    return { ...result };
  } catch (error) {
    return oauthError(error);
  }
}
