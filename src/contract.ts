export type Protocol = 1;
export type MessageType = 'slicc-vault';
export type EpochMs = number;
export type DeviceId = string;

export type RecordKind = 'secret' | 'grant' | 'model' | 'mcp';
export type RecordState = 'active' | 'inert' | 'removed';
export type RecordSource =
  | 'settings'
  | 'process'
  | `jerk:${string}@${DeviceId}`
  | `oauth:${string}`
  | `import:${string}`;
export type LockMode = 'auto' | 'passkey' | 'passphrase';
export type RequestKind = 'value' | 'oauth' | 'jerk-seal' | 'jerk' | 'unseal';
export type RequestState = 'pending' | 'done' | 'cancelled' | 'expired';
export type ErrorCode =
  | 'EINVAL'
  | 'ENOENT'
  | 'EACCES'
  | 'EEXIST'
  | 'EAGAIN'
  | 'ETIMEDOUT'
  | 'ENOTCONN'
  | 'ENOTSUP';
export type ExitName = 'page' | 'proxy' | 'tailscale' | `device:${DeviceId}`;
export type ExecMode = false | 'any' | 'argv' | 'shell';
export type Role = 'page' | 'agent';

export interface Stamp {
  pid: number;
  ppid: number;
  uid: number;
  gid: number;
  tag: string | null;
  users?: string;
  groups?: number[];
}

export interface VaultError {
  code: ErrorCode;
  message: string;
}

export type SessionProtocol = 'http1' | 'smtp' | 'pg';
export type SessionPosition = 'auth-plain' | 'auth-login' | 'password-cleartext' | 'scram-sha-256';

export interface ScramExchange {
  clientFirstBare: string;
  serverFirst: string;
  clientFinalBare: string;
  proof: string;
}

export type SessionTarget =
  | {
      protocol: 'http1';
      position: `header:${string}`;
      placeholders: string[];
      head: { method: string; path: string };
      scram?: never;
    }
  | {
      protocol: 'smtp';
      position: 'auth-plain' | 'auth-login';
      placeholders: string[];
      head?: never;
      scram?: never;
    }
  | {
      protocol: 'pg';
      position: 'password-cleartext';
      placeholders: string[];
      head?: never;
      scram?: never;
    }
  | {
      protocol: 'pg';
      position: 'scram-sha-256';
      scram: ScramExchange;
      placeholders?: never;
      head?: never;
    };

export interface Rule {
  domain: string;
  header: string;
  methods: string[];
  paths: string[];
  protocol?: SessionProtocol;
  position?: SessionPosition;
  port?: number;
  anchors?: string[];
  pins?: string[];
  roots?: boolean;
}

export interface RefusedRule {
  secret: string;
  rule: Rule;
  reason: string;
}

export interface SecretView {
  name: string;
  kind: RecordKind;
  placeholder: string;
  state: RecordState;
  source: RecordSource;
  sourceDevice: DeviceId | null;
  provider?: string;
  account?: string;
  server?: string;
  url?: string;
  pinned?: true;
  settings?: Record<string, string>;
  domains: string[];
  rules: Rule[];
  exits?: ExitName[];
  exec: ExecMode;
  execArgv?: string[][];
  createdAt: EpochMs;
  usedAt?: EpochMs;
  expiresAt?: EpochMs;
  removedAt?: EpochMs;
}

export interface PendingRequest {
  id: string;
  kind: RequestKind;
  name?: string;
  provider?: string;
  prompt?: string;
  uid: number;
  tag: string | null;
  createdAt: EpochMs;
  expiresAt: EpochMs;
}

export interface ScrubState {
  needed: boolean;
  version: number;
  ready: boolean;
}

export interface VaultStatus {
  version: string;
  protocol: Protocol;
  origin: string;
  locked: boolean;
  lock: LockMode;
  scrub: ScrubState;
  waiting: PendingRequest[];
  exportedAt: EpochMs | null;
  backupReminder: BackupReminder;
  policy: PolicyFileState[];
}

export type BackupReminder = 'due' | 'dismissed' | null;

export type Availability = 'connecting' | 'waiting' | 'locked' | 'ready';

export type PolicyFile = '/etc/fnox/config.toml' | '/etc/slicc/secrets-policy.toml';

export type PolicyChange =
  | { kind: 'rule'; secret: string; rule: Rule; change: 'added' | 'removed' }
  | { kind: 'exec'; secret: string; from: ExecMode; to: ExecMode }
  | { kind: 'exits'; secret: string; from: ExitName[] | null; to: ExitName[] | null }
  | { kind: 'limits'; field: string; from: number; to: number };

interface AuditBase {
  seq: number;
  id: string;
  at: EpochMs;
  name: string;
  uid: number | null;
  tag: string | null;
}

export interface ForwardEntry extends AuditBase {
  type: 'forward';
  domain: string;
  method: string;
  path: string;
  rule: Rule;
  exit: ExitName;
}

export interface SessionEntry extends AuditBase {
  type: 'session';
  session: string;
  domain: string;
  port: number;
  protocol: SessionProtocol;
  position: string;
  rule: number;
  verifiedBy?: 'roots' | 'anchored';
  anchor?: string;
  exit: ExitName;
}

export interface McpEntry extends AuditBase {
  type: 'mcp';
  server: string;
  domain: string;
  method: string;
  path: string;
  exit: ExitName;
}

export interface RevealEntry extends AuditBase {
  type: 'materialize';
  exec: ExecMode;
  path: string;
  argv: string;
  argvSha256: string;
  cwd: string;
  pid: number;
  ppid: number;
  ticket: string;
  consumed: boolean;
}

export interface SealEntry extends AuditBase {
  type: 'seal';
  source: RecordSource;
  rotated: boolean;
}

export interface RemoveEntry extends AuditBase {
  type: 'remove' | 'restore';
  grant?: string;
}

export interface PolicyEntry {
  type: 'policy';
  seq: number;
  id: string;
  at: EpochMs;
  uid: null;
  tag: null;
  file: PolicyFile;
  sha256: string;
  accepted: boolean;
  changes: PolicyChange[];
  warning?: string;
}

export interface EndpointsEntry {
  type: 'endpoints';
  seq: number;
  id: string;
  at: EpochMs;
  uid: null;
  tag: null;
  purged?: { provider: string; host: string }[];
  adopted?: { server: string; host: string }[];
  pinned?: { name: string; server: string; host: string };
  unpinned?: { name: string; server: string; host: string };
}

export type AuditEntry =
  | EndpointsEntry
  | ForwardEntry
  | SessionEntry
  | McpEntry
  | RevealEntry
  | SealEntry
  | RemoveEntry
  | RefreshEntry
  | PolicyEntry;

export interface RefreshEntry extends AuditBase {
  type: 'refresh';
  grant: string;
}

export interface RequestHead {
  method: string;
  url: string;
  headers: [string, string][];
}

export interface RawTraits {
  manualRedirects?: boolean;
  encodedBodies?: boolean;
}

export type ForwardResult =
  | { head: RequestHead; body?: Uint8Array }
  | { refused: { status: number; reason: string } };

export type ResponsePart =
  | {
      op: 'response';
      status: number;
      statusText: string;
      url: string;
      redirected?: boolean;
      headers: [string, string][];
    }
  | { op: 'body'; chunk: Uint8Array }
  | { op: 'end' }
  | { op: 'error'; message: string };

export interface McpServerEntry {
  server: string;
  url: string;
  names?: string[];
  tokenUrl?: string;
}

export interface RecordBinding {
  provider?: string;
  server?: string;
  settings?: Record<string, string>;
}

export interface ModelEndpoint {
  provider: string;
  url: string;
}

export interface OutgoingRequest {
  method: string;
  url: string;
  headers: [string, string][];
  body?: string | Uint8Array;
}

export interface AgentRecord {
  kind: 'model' | 'mcp';
  name: string;
  placeholder: string;
  state: 'ready' | 'expired' | 'refreshing';
  provider?: string;
  server?: string;
  expiresAt?: EpochMs;
  settings?: Record<string, string>;
}

export interface ScrubHit {
  name: string;
  form: string;
  count: number;
}

export interface AuditPage {
  audit: AuditEntry[];
  more: boolean;
  next?: number;
}

export interface ExitPolicyView {
  file: '/etc/slicc/secrets-policy.toml';
  sha256: string | null;
  restricted: { name: string; exits: ExitName[] }[];
}

export interface Attestation {
  path: string;
  bytes: Uint8Array;
  uid: number;
  gid: number;
  mode: number;
  ino: number;
  mtimeMs: EpochMs;
  sha256: string;
  users: string;
  onRootFs: boolean;
  parents: { path: string; uid: number; gid: number; mode: number }[];
}

export interface PolicyFileState {
  path: string;
  sha256: string | null;
  accepted: boolean;
  warnings: string[];
}

export interface PolicyResult {
  accepted: boolean;
  files: PolicyFileState[];
  rules: (Rule & { secret: string })[];
  warnings: string[];
}

export interface VaultList {
  secrets: SecretView[];
  refused: RefusedRule[];
  audit: AuditEntry[];
  auditMore: boolean;
  exits: ExitPolicyView;
}

export interface SealResult {
  name: string;
  placeholder: string;
  state: RecordState;
}

export type ImportKind = 'bundle' | 'keepass' | 'six';

export interface ImportCandidate {
  name: string;
  kind: RecordKind;
  exists: boolean;
  suggestedRules?: string;
  refused?: string;
}

export type ImportResult =
  | { stage: 'pick'; candidates: ImportCandidate[] }
  | {
      stage: 'done';
      imported: SealResult[];
      skipped: string[];
      reasons?: Record<string, string>;
      outcomes?: ImportOutcome[];
    };

export interface ImportOutcome {
  name: string;
  kind?: RecordKind;
  imported: boolean;
  reason?: string;
}

export type PopupIntent = { kind: 'unlock' } | { kind: 'protect' };

export type PopupState = 'opened' | 'done' | 'cancelled' | 'closed' | 'blocked';

export interface ButtonConfig {
  intent: PopupIntent | 'auto';
  label?: string;
  size?: 's' | 'm' | 'l';
  variant?: 'accent' | 'primary' | 'secondary';
  treatment?: 'fill' | 'outline';
  quiet?: boolean;
  scale?: 'medium' | 'large';
  theme?: 'light' | 'dark';
  dir?: 'ltr' | 'rtl';
  lang?: string;
  disabled?: boolean;
}

export type SealedRequest = { v: Protocol; op: string } & Record<string, unknown>;
export type SealedReply = { v: Protocol } & Record<string, unknown>;

export type Op =
  | { op: 'sealed'; req: SealedRequest; stamp: Stamp }
  | { op: 'status' }
  | { op: 'placeholders' }
  | { op: 'list' }
  | { op: 'audit'; before?: number; limit?: number }
  | ({
      op: 'put';
      name: string;
      value: string;
      kind?: 'secret' | 'model' | 'mcp';
      request?: string;
    } & RecordBinding)
  | { op: 'cancel'; request: string }
  | { op: 'remove'; name: string; kind?: RecordKind }
  | { op: 'restore'; name: string; kind?: RecordKind }
  | ({
      op: 'seal';
      name: string;
      value: string;
      source: RecordSource;
      kind?: RecordKind;
      expiresAt?: EpochMs;
      refresh?: string;
      oauth?: OAuthConfig;
      request?: string;
      jerk?: JerkResult;
    } & RecordBinding)
  | { op: 'refresh'; name: string }
  | ({ op: 'answer'; request: string; state: 'progress' | 'done' } & RequestAnswer)
  | {
      op: 'import';
      kind: ImportKind;
      bytes: Uint8Array;
      password?: string;
      pick?: (string | { name: string; kind: RecordKind })[];
    }
  | { op: 'export'; passphrase: string }
  | { op: 'lock' }
  | { op: 'dismissBackupReminder' }
  | { op: 'policy'; files: Attestation[] }
  | {
      op: 'endpoints';
      model?: (string | { name: string; url: string })[];
      mcp?: (string | McpServerEntry)[];
      remove?: {
        model?: (string | { name: string; url: string })[];
        mcp?: { server: string; url: string }[];
      };
      unpin?: string[];
    }
  | {
      op: 'forward';
      head: RequestHead;
      body?: Uint8Array | string;
      owner: Stamp;
      exit: ExitName;
      rawTraits: RawTraits;
    }
  | {
      op: 'materializeConsume';
      ticket: string;
      stamp: Stamp;
      path: string;
      resolved: string;
      argv: string[];
      cwd: string;
      interpreters: string[];
      trusted: boolean;
    }
  | ({
      op: 'sessionMaterialize';
      stamp: Stamp;
      session: string;
      host: string;
      port: number;
      verified: boolean;
      handshakeAt: EpochMs;
      exit: ExitName;
    } & SessionTarget &
      ({ verifiedBy?: 'roots'; anchor?: never } | { verifiedBy: 'anchored'; anchor: string }))
  | {
      op: 'sessionAnchors';
      stamp: Stamp;
      session: string;
      host: string;
      port: number;
      protocol: SessionProtocol;
      exit: ExitName;
    };

export type AgentOp =
  | { op: 'redact'; texts: (string | Uint8Array)[] }
  | { op: 'redactStream'; stream: string }
  | { op: 'push'; stream: string; chunk: Uint8Array }
  | { op: 'idle'; stream: string }
  | { op: 'end'; stream: string }
  | { op: 'drop'; stream: string }
  | { op: 'endpoints'; model?: (string | ModelEndpoint)[]; mcp?: (string | McpServerEntry)[] }
  | { op: 'model'; provider?: string; request: OutgoingRequest }
  | { op: 'mcp'; server: string; request: OutgoingRequest }
  | { op: 'records' }
  | {
      op: 'grant';
      server: string;
      response: string | Uint8Array;
      oauth: OAuthConfig;
      name?: string;
    }
  | { op: 'refresh'; server: string; name?: string }
  | { op: 'refresh'; provider: string; name?: string };

export type AgentReply =
  | { op: 'redact'; texts: (string | Uint8Array)[]; hits: ScrubHit[]; version: number }
  | { op: 'redactStream'; stream: string; idleMs: number; version: number }
  | { op: 'push' | 'idle'; chunk: Uint8Array }
  | { op: 'end'; chunk: Uint8Array; hits: ScrubHit[] }
  | { op: 'drop' }
  | { op: 'endpoints'; ok: true }
  | { op: 'model' | 'mcp'; request: OutgoingRequest; hits: ScrubHit[]; version: number }
  | { op: 'records'; records: AgentRecord[] }
  | {
      op: 'grant';
      response: string | Uint8Array;
      records: { kind: RecordKind; name: string; placeholder: string }[];
      expiresAt?: EpochMs;
    }
  | { op: 'refresh'; state: 'refreshed' | 'requested'; expiresAt?: EpochMs };

export type OpReply =
  | { op: 'sealed'; reply: SealedReply }
  | { op: 'status'; status: VaultStatus }
  | { op: 'placeholders'; placeholders: string[]; scrub: ScrubState }
  | { op: 'list'; list: VaultList }
  | ({ op: 'audit' } & AuditPage)
  | ({ op: 'put' | 'seal' | 'remove' | 'restore' } & SealResult)
  | { op: 'cancel'; state: RequestState }
  | ({ op: 'import' } & ImportResult)
  | { op: 'export'; bundle: Uint8Array; count: number }
  | { op: 'lock' }
  | { op: 'dismissBackupReminder'; backupReminder: BackupReminder }
  | ({ op: 'policy' } & PolicyResult)
  | { op: 'endpoints'; ok: true }
  | { op: 'refresh'; state: 'refreshed' | 'requested'; expiresAt?: EpochMs }
  | { op: 'answer'; state: RequestState }
  | ({ op: 'forward' } & ForwardResult)
  | {
      op: 'materializeConsume';
      values: Record<string, string>;
      placeholders: Record<string, string>;
    }
  | { op: 'sessionMaterialize'; values: Record<string, string> }
  | { op: 'sessionAnchors'; anchors: string[]; pins: string[] };

export type Request = Op & { v: Protocol; id: number };

export type Reply =
  | (OpReply & { v: Protocol; id: number })
  | { v: Protocol; id: number; error: VaultError };

export type ChangedPart = 'secrets' | 'audit' | 'exits';

export type VaultEvent =
  | { v: Protocol; event: 'status'; status: VaultStatus }
  | { v: Protocol; event: 'placeholders'; placeholders: string[]; scrub: ScrubState }
  | { v: Protocol; event: 'changed'; parts: ChangedPart[] }
  | { v: Protocol; event: 'refresh'; name: string; source: RecordSource; expiresAt: EpochMs }
  | { v: Protocol; event: 'egress'; request: EgressRequest }
  | { v: Protocol; event: 'cancelled'; request: string; kind: RequestKind };

export interface JerkRow {
  provider: string;
  name?: string;
  env: string[];
  device?: string;
  signedIn?: boolean;
  user?: string;
  scopes?: string[];
}

export interface RequestAnswer {
  progress?: string;
  exit?: number;
  user?: string;
  scopes?: string[];
  message?: string;
  rows?: JerkRow[];
  placeholder?: string;
}

export interface EgressRequest {
  method: string;
  url: string;
  headers: [string, string][];
  body: string;
}

export type EgressAnswer =
  | { status: number; headers: [string, string][]; body: Uint8Array | string }
  | { error: string };

export interface OAuthConfig {
  tokenUrl: string;
  clientId: string;
  scope?: string;
  resource?: string;
}

export interface JerkResult {
  exit: number;
  user?: string;
  scopes?: string[];
  expires_at?: string;
}

export interface Hello {
  type: MessageType;
  v: Protocol;
  op: 'hello';
  role?: Role;
  sudoGid?: number;
}

export type Greeting =
  | { v: Protocol; op: 'welcome'; role: Role; status: VaultStatus }
  | { v: Protocol; op: 'refused'; error: VaultError };

export type ButtonMessage =
  | { type: MessageType; v: Protocol; op: 'button'; button: ButtonConfig }
  | { type: MessageType; v: Protocol; op: 'focus' };

export type ButtonEvent = { type: MessageType; v: Protocol } & (
  | { event: 'ready' }
  | { event: 'size'; width: number; height: number; inset: number }
  | { event: 'label'; label: string }
  | { event: 'focus'; direction: 'next' | 'previous' }
  | { event: 'popup'; intent: PopupIntent; state: PopupState }
);
