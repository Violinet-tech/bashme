// store.ts — rules, paired devices, and the audit log.
//
// Written against a two-method interface rather than a driver so the same code
// runs on violet-dev's existing better-sqlite3 handle and on node:sqlite in the
// standalone app. VIOLINET OS must NOT open a second database file: two writers
// on one WAL is a corruption story, and the audit log is the one table that
// must not lose rows.

import type { AuditRow, HardReason, PairedDevice, Resolution, Rule, RequestKind } from './types.ts';
import { generateVapidKeys, type VapidKeys } from './push.ts';

/** The subset of better-sqlite3 / node:sqlite both drivers agree on. */
export interface Db {
  exec(sql: string): unknown;
  prepare(sql: string): {
    run(...params: unknown[]): unknown;
    all(...params: unknown[]): unknown[];
  };
}

export const SCHEMA = `
  CREATE TABLE IF NOT EXISTS bashme_rules (
    id TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 1,
    originator_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    prefixes_json TEXT NOT NULL,
    note TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    match_count INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS bashme_devices (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    public_key TEXT NOT NULL,
    paired_at TEXT NOT NULL DEFAULT (datetime('now')),
    revoked_at TEXT
  );

  -- Append-only. There is deliberately no UPDATE or DELETE path in this file:
  -- "what did I actually let run last week" is only answerable if nothing can
  -- quietly rewrite the answer.
  CREATE TABLE IF NOT EXISTS bashme_audit (
    request_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    command TEXT NOT NULL,
    cwd TEXT NOT NULL,
    originator_id TEXT NOT NULL,
    originator_label TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    settled_at TEXT NOT NULL,
    resolution_json TEXT NOT NULL,
    hard_reasons_json TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS bashme_audit_settled ON bashme_audit(settled_at DESC);

  CREATE TABLE IF NOT EXISTS bashme_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );

  -- Local programs allowed to submit requests to the standalone app.
  --
  -- The token is stored as a SHA-256 hash, like a password, because this table
  -- sits in a file on disk next to the audit log: a readable token would let
  -- anyone who can read the database impersonate a trusted originator, and
  -- originator identity is exactly what standing rules key on.
  CREATE TABLE IF NOT EXISTS bashme_clients (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    token_sha256 TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    revoked_at TEXT,
    last_seen TEXT
  );
`;

export function migrate(db: Db): void {
  // WAL so a reader does not block the writer. The standalone app holds this
  // database open for its whole run while other processes read it, and under
  // the default rollback journal that combination produces SQLITE_BUSY rather
  // than a wait. Idempotent, and VIOLINET OS already sets it on the handle it
  // passes in.
  try {
    db.exec('PRAGMA journal_mode = WAL;');
  } catch {
    /* an in-memory database cannot use WAL, and does not need to */
  }
  db.exec(SCHEMA);
  // Added after the table already existed in the field, so it is a migration
  // rather than part of SCHEMA. Failing means the column is already there.
  try {
    db.exec('ALTER TABLE bashme_devices ADD COLUMN push_endpoint TEXT;');
  } catch {
    /* column already exists */
  }
}

interface RuleRow {
  id: string;
  enabled: number;
  originator_id: string;
  kind: string;
  prefixes_json: string;
  note: string | null;
  created_at: string;
  match_count: number;
}

export class SqliteStore {
  #db: Db;

  constructor(db: Db) {
    this.#db = db;
    migrate(db);
  }

  // --- rules ---------------------------------------------------------------

  listRules(): Rule[] {
    const rows = this.#db
      .prepare('SELECT * FROM bashme_rules ORDER BY created_at DESC')
      .all() as RuleRow[];
    return rows.map((r) => ({
      id: r.id,
      enabled: r.enabled === 1,
      originatorId: r.originator_id,
      kind: r.kind as RequestKind,
      prefixes: JSON.parse(r.prefixes_json) as string[],
      createdAt: r.created_at,
      matchCount: r.match_count,
      ...(r.note ? { note: r.note } : {}),
    }));
  }

  upsertRule(rule: Rule): void {
    this.#db
      .prepare(
        `INSERT INTO bashme_rules (id, enabled, originator_id, kind, prefixes_json, note, created_at, match_count)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
           enabled = excluded.enabled,
           originator_id = excluded.originator_id,
           kind = excluded.kind,
           prefixes_json = excluded.prefixes_json,
           note = excluded.note`,
      )
      .run(
        rule.id,
        rule.enabled ? 1 : 0,
        rule.originatorId,
        rule.kind,
        JSON.stringify(rule.prefixes),
        rule.note ?? null,
        rule.createdAt,
        rule.matchCount,
      );
  }

  setRuleEnabled(id: string, enabled: boolean): void {
    this.#db.prepare('UPDATE bashme_rules SET enabled = ? WHERE id = ?').run(enabled ? 1 : 0, id);
  }

  deleteRule(id: string): void {
    this.#db.prepare('DELETE FROM bashme_rules WHERE id = ?').run(id);
  }

  recordMatch(id: string): void {
    this.#db.prepare('UPDATE bashme_rules SET match_count = match_count + 1 WHERE id = ?').run(id);
  }

  // --- devices -------------------------------------------------------------

  listDevices(): PairedDevice[] {
    const rows = this.#db.prepare('SELECT * FROM bashme_devices').all() as Array<{
      id: string;
      label: string;
      public_key: string;
      paired_at: string;
      revoked_at: string | null;
      push_endpoint: string | null;
    }>;
    return rows.map((r) => ({
      id: r.id,
      label: r.label,
      publicKey: r.public_key,
      pairedAt: r.paired_at,
      ...(r.revoked_at ? { revokedAt: r.revoked_at } : {}),
      ...(r.push_endpoint ? { pushEndpoint: r.push_endpoint } : {}),
    }));
  }

  /** Called once a device's service worker subscribes to Web Push. */
  setPushEndpoint(deviceId: string, endpoint: string): void {
    this.#db.prepare('UPDATE bashme_devices SET push_endpoint = ? WHERE id = ?').run(endpoint, deviceId);
  }

  /** Same VAPID identity for every device, generated once and kept in settings. */
  vapidKeys(): VapidKeys {
    const row = this.#db
      .prepare("SELECT value FROM bashme_settings WHERE key = 'vapidKeys'")
      .all()[0] as { value: string } | undefined;
    if (row) return JSON.parse(row.value) as VapidKeys;
    const fresh = generateVapidKeys();
    this.#db
      .prepare("INSERT INTO bashme_settings (key, value) VALUES ('vapidKeys', ?)")
      .run(JSON.stringify(fresh));
    return fresh;
  }

  pairDevice(device: PairedDevice): void {
    this.#db
      .prepare('INSERT OR REPLACE INTO bashme_devices (id, label, public_key, paired_at) VALUES (?, ?, ?, ?)')
      .run(device.id, device.label, device.publicKey, device.pairedAt);
  }

  /**
   * Revocation is a tombstone, not a delete.
   *
   * Audit rows name a device id; deleting the row would leave "approved by
   * device d1" unresolvable, which is exactly the entry someone reviewing a
   * compromise would most want to read.
   */
  revokeDevice(id: string): void {
    this.#db
      .prepare('UPDATE bashme_devices SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL')
      .run(new Date().toISOString(), id);
  }

  /**
   * Originators that have actually asked for something, newest first.
   *
   * A rule names exactly one originator and matches on it exactly, so an
   * originator typed by hand with a typo is a rule that silently never fires --
   * the worst failure a security control can have, because it looks configured.
   * Offering the ones seen in the audit log means the id in a rule is one that
   * has demonstrably reached the gate.
   */
  listOriginators(): Array<{ id: string; label: string }> {
    const rows = this.#db
      .prepare(
        `SELECT originator_id, originator_label, MAX(settled_at) AS seen
           FROM bashme_audit GROUP BY originator_id ORDER BY seen DESC`,
      )
      .all() as Array<{ originator_id: string; originator_label: string }>;
    return rows.map((r) => ({ id: r.originator_id, label: r.originator_label }));
  }

  // --- clients -------------------------------------------------------------

  listClients(): Array<{
    id: string;
    label: string;
    createdAt: string;
    revokedAt?: string;
    lastSeen?: string;
  }> {
    const rows = this.#db
      .prepare('SELECT id, label, created_at, revoked_at, last_seen FROM bashme_clients ORDER BY created_at DESC')
      .all() as Array<{
      id: string;
      label: string;
      created_at: string;
      revoked_at: string | null;
      last_seen: string | null;
    }>;
    return rows.map((r) => ({
      id: r.id,
      label: r.label,
      createdAt: r.created_at,
      ...(r.revoked_at ? { revokedAt: r.revoked_at } : {}),
      ...(r.last_seen ? { lastSeen: r.last_seen } : {}),
    }));
  }

  /** Enrol a client. The caller shows the plaintext token once; only the hash is kept. */
  addClient(client: { id: string; label: string; tokenSha256: string }): void {
    this.#db
      .prepare('INSERT INTO bashme_clients (id, label, token_sha256, created_at) VALUES (?, ?, ?, ?)')
      .run(client.id, client.label, client.tokenSha256, new Date().toISOString());
  }

  /**
   * Resolve a presented token to a live client, or null.
   *
   * Looks up by hash rather than scanning, and a revoked client resolves to
   * null rather than to a client with a flag the caller might forget to check.
   */
  clientByTokenHash(tokenSha256: string): { id: string; label: string } | null {
    const row = this.#db
      .prepare('SELECT id, label FROM bashme_clients WHERE token_sha256 = ? AND revoked_at IS NULL')
      .all(tokenSha256)[0] as { id: string; label: string } | undefined;
    return row ?? null;
  }

  touchClient(id: string): void {
    this.#db.prepare('UPDATE bashme_clients SET last_seen = ? WHERE id = ?').run(new Date().toISOString(), id);
  }

  /** Tombstoned, not deleted — audit rows name the client id. */
  revokeClient(id: string): void {
    this.#db
      .prepare('UPDATE bashme_clients SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL')
      .run(new Date().toISOString(), id);
  }

  // --- settings ------------------------------------------------------------

  /**
   * The persisted half of GateConfig.
   *
   * `workspaceRoot` is deliberately NOT stored: it is the host's containment
   * boundary, and a boundary a stale database row could move is not a boundary.
   * The host passes it in on every construction.
   */
  readToggles(): { enabled: boolean; rulesEnabled: boolean; devicesEnabled: boolean } {
    const rows = this.#db.prepare('SELECT key, value FROM bashme_settings').all() as Array<{
      key: string;
      value: string;
    }>;
    const map = new Map(rows.map((r) => [r.key, r.value]));
    // Absent means off. A feature that grants standing approval must be opted
    // into, never defaulted into.
    const read = (k: string): boolean => map.get(k) === '1';
    return {
      enabled: read('enabled'),
      rulesEnabled: read('rulesEnabled'),
      devicesEnabled: read('devicesEnabled'),
    };
  }

  writeToggle(key: 'enabled' | 'rulesEnabled' | 'devicesEnabled', value: boolean): void {
    this.#db
      .prepare('INSERT INTO bashme_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
      .run(key, value ? '1' : '0');
  }

  // --- audit ---------------------------------------------------------------

  appendAudit(row: AuditRow): void {
    this.#db
      .prepare(
        `INSERT OR IGNORE INTO bashme_audit
         (request_id, kind, command, cwd, originator_id, originator_label,
          requested_at, settled_at, resolution_json, hard_reasons_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        row.requestId,
        row.kind,
        row.command,
        row.cwd,
        row.originatorId,
        row.originatorLabel,
        row.requestedAt,
        row.settledAt,
        JSON.stringify(row.resolution),
        JSON.stringify(row.hardReasons),
      );
  }

  recentAudit(limit = 200): AuditRow[] {
    const rows = this.#db
      .prepare('SELECT * FROM bashme_audit ORDER BY settled_at DESC LIMIT ?')
      .all(Math.max(1, Math.min(1000, limit))) as Array<Record<string, string>>;
    return rows.map((r) => ({
      requestId: r.request_id as string,
      kind: r.kind as RequestKind,
      command: r.command as string,
      cwd: r.cwd as string,
      originatorId: r.originator_id as string,
      originatorLabel: r.originator_label as string,
      requestedAt: r.requested_at as string,
      settledAt: r.settled_at as string,
      resolution: JSON.parse(r.resolution_json as string) as Resolution,
      hardReasons: JSON.parse(r.hard_reasons_json as string) as HardReason[],
    }));
  }
}
