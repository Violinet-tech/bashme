// Runs against node:sqlite. The same SqliteStore is used in VIOLINET OS on a
// better-sqlite3 handle -- this test exists to prove the `Db` interface really
// is the intersection of the two drivers, not just a shape that compiles.

import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { SqliteStore } from './store.ts';
import type { Db } from './store.ts';
import { Gate } from './gate.ts';
import type { AuditRow, GateRequest, Rule } from './types.ts';

function freshStore(): SqliteStore {
  return new SqliteStore(new DatabaseSync(':memory:') as unknown as Db);
}

const rule: Rule = {
  id: 'r1',
  enabled: true,
  originatorId: 'violet-os:agent-tools',
  kind: 'shell',
  prefixes: ['npm run build', 'npm test'],
  createdAt: new Date().toISOString(),
  matchCount: 0,
  note: 'routine build',
};

test('rules round-trip, including the prefix list', () => {
  const s = freshStore();
  s.upsertRule(rule);
  const [got] = s.listRules();
  assert.deepEqual(got?.prefixes, ['npm run build', 'npm test']);
  assert.equal(got?.enabled, true);
  assert.equal(got?.note, 'routine build');
});

test('match counts increment so scope creep is visible', () => {
  const s = freshStore();
  s.upsertRule(rule);
  s.recordMatch('r1');
  s.recordMatch('r1');
  assert.equal(s.listRules()[0]?.matchCount, 2);
});

test('upsert preserves the accumulated match count', () => {
  const s = freshStore();
  s.upsertRule(rule);
  s.recordMatch('r1');
  s.upsertRule({ ...rule, prefixes: ['npm run build'] });
  assert.equal(s.listRules()[0]?.matchCount, 1);
});

test('toggling and deleting a rule works', () => {
  const s = freshStore();
  s.upsertRule(rule);
  s.setRuleEnabled('r1', false);
  assert.equal(s.listRules()[0]?.enabled, false);
  s.deleteRule('r1');
  assert.equal(s.listRules().length, 0);
});

test('revoking a device tombstones it rather than deleting it', () => {
  const s = freshStore();
  s.pairDevice({ id: 'd1', label: 'Phone', publicKey: 'AAAA', pairedAt: new Date().toISOString() });
  s.revokeDevice('d1');
  const [d] = s.listDevices();
  assert.equal(d?.id, 'd1', 'the row must survive so audit rows naming it stay readable');
  assert.ok(d?.revokedAt);
});

function auditRow(over: Partial<AuditRow> = {}): AuditRow {
  return {
    requestId: 'q1',
    kind: 'shell',
    command: 'npm run build',
    cwd: 'C:\\work\\project',
    originatorId: 'violet-os:agent-tools',
    originatorLabel: 'Agent tools',
    requestedAt: new Date().toISOString(),
    settledAt: new Date().toISOString(),
    resolution: { type: 'approved-by-rule', ruleId: 'r1' },
    hardReasons: [],
    ...over,
  };
}

test('audit rows round-trip their resolution and reasons', () => {
  const s = freshStore();
  s.appendAudit(auditRow({ hardReasons: ['destructive-filesystem'], resolution: { type: 'timeout' } }));
  const [row] = s.recentAudit();
  assert.deepEqual(row?.resolution, { type: 'timeout' });
  assert.deepEqual(row?.hardReasons, ['destructive-filesystem']);
});

test('the audit log never overwrites an existing request id', () => {
  const s = freshStore();
  s.appendAudit(auditRow({ command: 'original' }));
  s.appendAudit(auditRow({ command: 'rewritten' }));
  const rows = s.recentAudit();
  assert.equal(rows.length, 1);
  assert.equal(rows[0]?.command, 'original');
});

test('recentAudit clamps an absurd limit instead of trusting it', () => {
  const s = freshStore();
  s.appendAudit(auditRow());
  assert.equal(s.recentAudit(10_000_000).length, 1);
  assert.equal(s.recentAudit(-5).length, 1);
});

// Everything above runs on :memory:. The app runs on a file, and `#writeAudit`
// deliberately swallows exceptions so the audit log can never block a decision
// — which also means a write that fails on disk fails INVISIBLY. These two go
// through a real file so that failure mode cannot hide.

test('a real file-backed store persists audit rows across connections', () => {
  const dir = mkdtempSync(join(tmpdir(), 'bashme-'));
  const path = join(dir, 'test.db');
  const dbA = new DatabaseSync(path);
  const dbB = new DatabaseSync(path);
  try {
    new SqliteStore(dbA as unknown as Db).appendAudit(auditRow({ requestId: 'persisted' }));
    assert.equal(new SqliteStore(dbB as unknown as Db).recentAudit()[0]?.requestId, 'persisted');
  } finally {
    // Windows refuses to delete a file SQLite still has open, so both handles
    // close before the directory goes.
    dbA.close();
    dbB.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a gate on a file-backed store audits a timeout', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'bashme-'));
  const path = join(dir, 'test.db');
  const db = new DatabaseSync(path);
  try {
    const store = new SqliteStore(db as unknown as Db);
    const gate = new Gate(
      {
        enabled: true,
        rulesEnabled: false,
        devicesEnabled: false,
        workspaceRoot: process.platform === 'win32' ? 'C:\\work' : '/work',
        timeoutMs: 60,
      },
      {
        audit: { append: (r) => store.appendAudit(r) },
        rules: { list: () => [], recordMatch: () => {} },
        present: () => {},
      },
    );

    const req: GateRequest = {
      id: 'timed-out',
      kind: 'shell',
      command: 'npm run build',
      cwd: process.platform === 'win32' ? 'C:\\work' : '/work',
      originator: { id: 'client:cli', label: 'CLI' },
      requestedAt: new Date().toISOString(),
    };
    assert.equal(await gate.request(req), false);
    assert.equal(store.recentAudit()[0]?.resolution.type, 'timeout', 'the timeout must reach disk');
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
