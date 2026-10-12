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
export type RequestKind = 'value' | 'oauth' | 'jerk-seal';
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
}

export interface VaultError {
  code: ErrorCode;
  message: string;
}

export interface Rule {
  domain: string;
  header: string;
  methods: string[];
  paths: string[];
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
}

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
}

export interface PolicyEntry {
  type: 'policy';
  seq: number;
  id: string;
  at: EpochMs;
  file: PolicyFile;
  sha256: string;
  accepted: boolean;
  changes: PolicyChange[];
  warning?: string;
}

export type AuditEntry = ForwardEntry | RevealEntry | SealEntry | RemoveEntry | PolicyEntry;

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
  exists: boolean;
  suggestedRules?: string;
}

export type ImportResult =
  | { stage: 'pick'; candidates: ImportCandidate[] }
  | { stage: 'done'; imported: SealResult[]; skipped: string[] };

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
  | { op: 'put'; name: string; value: string; request?: string }
  | { op: 'cancel'; request: string }
  | { op: 'remove'; name: string; kind?: RecordKind }
  | { op: 'restore'; name: string; kind?: RecordKind }
  | {
      op: 'seal';
      name: string;
      value: string;
      source: RecordSource;
      kind?: RecordKind;
      expiresAt?: EpochMs;
      refresh?: string;
    }
  | { op: 'import'; kind: ImportKind; bytes: Uint8Array; password?: string; pick?: string[] }
  | { op: 'export'; passphrase: string }
  | { op: 'lock' };

export type OpReply =
  | { op: 'sealed'; reply: SealedReply }
  | { op: 'status'; status: VaultStatus }
  | { op: 'placeholders'; placeholders: string[]; scrub: ScrubState }
  | { op: 'list'; list: VaultList }
  | ({ op: 'audit' } & AuditPage)
  | ({ op: 'put' | 'seal' | 'remove' | 'restore' } & SealResult)
  | { op: 'cancel'; state: RequestState }
  | ({ op: 'import' } & ImportResult)
  | { op: 'export'; bundle: Uint8Array }
  | { op: 'lock' };

export type Request = Op & { v: Protocol; id: number };

export type Reply =
  | (OpReply & { v: Protocol; id: number })
  | { v: Protocol; id: number; error: VaultError };

export type ChangedPart = 'secrets' | 'audit' | 'exits';

export type VaultEvent =
  | { v: Protocol; event: 'status'; status: VaultStatus }
  | { v: Protocol; event: 'placeholders'; placeholders: string[]; scrub: ScrubState }
  | { v: Protocol; event: 'changed'; parts: ChangedPart[] };

export interface Hello {
  type: MessageType;
  v: Protocol;
  op: 'hello';
  role?: Role;
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
