// types.ts — the vocabulary shared by every consumer of the gate.
//
// Deliberately dependency-free and runtime-free: this file is imported by the
// standalone app, by VIOLINET OS, and by the tests, so it must not drag in
// Electron, SQLite, or Node built-ins.

/** What kind of side effect is being proposed. */
export type RequestKind = 'shell' | 'write' | 'network' | 'elevate';

/**
 * Who is asking. Identity is a string the host assigns, never something the
 * requester supplies about itself -- a rule that trusts a self-declared name
 * is a rule any caller can satisfy by lying.
 */
export interface Originator {
  /** Stable id, e.g. `violet-os:agent-tools` or `claude-code:session`. */
  id: string;
  /** Human label for the dialog and the audit log. */
  label: string;
}

export interface GateRequest {
  id: string;
  kind: RequestKind;
  /** The exact command text / path that would be acted on. Never truncated here. */
  command: string;
  cwd: string;
  originator: Originator;
  requestedAt: string;
  /** Optional one-line human summary; falls back to `command`. */
  summary?: string;
}

/** Why a request can never be auto-approved, regardless of configured rules. */
export type HardReason =
  | 'destructive-filesystem'
  | 'credential-access'
  | 'security-posture'
  | 'network-exfiltration'
  | 'privileged-elevation'
  | 'outside-workspace'
  | 'unparseable';

export interface Verdict {
  /** True when at least one hard reason applies; rules are skipped entirely. */
  hardBlocked: boolean;
  reasons: HardReason[];
  /** Human-readable detail per reason, for the dialog and the audit row. */
  notes: string[];
}

/**
 * A standing auto-approve rule.
 *
 * There is no wildcard originator and no wildcard command on purpose: the
 * failure mode this whole feature exists to prevent is a broad allow matching
 * more than its author pictured.
 */
export interface Rule {
  id: string;
  enabled: boolean;
  /** Must equal `Originator.id` exactly. */
  originatorId: string;
  kind: RequestKind;
  /**
   * Literal command prefixes. A request matches when its command starts with
   * one of these AND contains no shell chaining (see `classify.ts`).
   */
  prefixes: string[];
  createdAt: string;
  /** Incremented on every auto-approve, so scope creep is visible in the UI. */
  matchCount: number;
  note?: string;
}

/** How a request was settled. */
export type Resolution =
  | { type: 'approved'; by: 'local-dialog' | 'keyword'; }
  | { type: 'approved-by-device'; deviceId: string }
  | { type: 'approved-by-rule'; ruleId: string }
  | { type: 'denied'; by: 'local-dialog' | 'device'; deviceId?: string }
  | { type: 'timeout' }
  | { type: 'no-approver' };

export interface AuditRow {
  requestId: string;
  kind: RequestKind;
  command: string;
  cwd: string;
  originatorId: string;
  originatorLabel: string;
  requestedAt: string;
  settledAt: string;
  resolution: Resolution;
  hardReasons: HardReason[];
}

/** Append-only. Implemented over SQLite in the app, in memory in tests. */
export interface AuditSink {
  append(row: AuditRow): void;
}

/** Where rules are read from. Read-only to the gate; edited through the UI. */
export interface RuleStore {
  list(): Rule[];
  recordMatch(ruleId: string): void;
}

/** A paired approving device. Private key never leaves the device. */
export interface PairedDevice {
  id: string;
  label: string;
  /** SPKI DER, base64. Ed25519. */
  publicKey: string;
  pairedAt: string;
  revokedAt?: string;
  /** Web Push endpoint URL, set once the device subscribes. No keys needed: pushes carry no payload. */
  pushEndpoint?: string;
}
