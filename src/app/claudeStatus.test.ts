// claudeStatus.test.ts — reads a fake claude-code-sessions tree.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, utimesSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { readClaudeStatus } from './claudeStatus.ts';

const NOW = Date.UTC(2026, 9, 8, 12, 0, 0);

function chat(dir: string, id: string, over: Record<string, unknown>, mtimeMs = NOW - 1000) {
  const file = join(dir, `${id}.json`);
  writeFileSync(
    file,
    JSON.stringify({ sessionId: id, title: id, model: 'claude-x', lastActivityAt: NOW - 600_000, isArchived: false, ...over }),
  );
  utimesSync(file, mtimeMs / 1000, mtimeMs / 1000);
}

test('reads titles and states, skips archived chats, and never returns message text', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'bashme-claude-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const org = join(root, 'acct', 'org');
  mkdirSync(org, { recursive: true });

  chat(org, 'local_working', { title: 'Building', lastActivityAt: NOW - 10_000 });
  chat(org, 'local_blocked', {
    title: 'Needs a decision',
    postTurnSummary: { status_category: 'blocked', status_detail: 'Okay to go?' },
    lastActivityAt: NOW - 300_000,
  });
  chat(org, 'local_done', { title: 'Finished', postTurnSummary: { status_category: 'completed', status_detail: 'did a thing' } });
  chat(org, 'local_archived', { title: 'Old', isArchived: true });
  chat(org, 'local_stale', { title: 'Ancient' }, NOW - 30 * 86_400_000);
  // A field the reader has no business passing on.
  chat(org, 'local_secret', { title: 'Secret holder', promptAppendSnapshot: { append: 'PRIVATE PROMPT' } });

  const snap = await readClaudeStatus({ sessionsDir: root, now: () => NOW, isAppRunning: async () => true });
  const titles = snap.chats.map((c) => c.title);

  assert.equal(snap.app.running, true);
  assert.ok(titles.includes('Building') && titles.includes('Needs a decision') && titles.includes('Finished'));
  assert.ok(!titles.includes('Old'), 'archived chats are skipped');
  assert.ok(!titles.includes('Ancient'), 'chats untouched for a week are skipped');
  assert.equal(snap.chats[0]!.title, 'Building', 'the working chat is first');
  assert.equal(snap.chats[0]!.state, 'working');
  const blocked = snap.chats.find((c) => c.title === 'Needs a decision')!;
  assert.equal(blocked.state, 'needs-you');
  assert.equal(blocked.detail, 'Okay to go?');
  assert.equal(snap.chats.find((c) => c.title === 'Finished')!.detail, '', 'only a waiting chat carries a detail');
  assert.doesNotMatch(JSON.stringify(snap), /PRIVATE PROMPT/);
});

test('a chat whose transcript is still being written is working even if its last message is old', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'bashme-claude-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const org = join(root, 'sessions', 'acct', 'org');
  const project = join(root, 'projects', 'F--code');
  mkdirSync(org, { recursive: true });
  mkdirSync(project, { recursive: true });

  chat(org, 'local_long', { title: 'Long run', cliSessionId: 'cli-1', lastActivityAt: NOW - 600_000 });
  const transcript = join(project, 'cli-1.jsonl');
  writeFileSync(transcript, '{"private":"never read"}');
  utimesSync(transcript, (NOW - 5_000) / 1000, (NOW - 5_000) / 1000);

  const snap = await readClaudeStatus({
    sessionsDir: join(root, 'sessions'),
    transcriptsDir: join(root, 'projects'),
    now: () => NOW,
    isAppRunning: async () => true,
  });
  assert.equal(snap.chats[0]!.state, 'working');
  assert.doesNotMatch(JSON.stringify(snap), /never read/);
});

test('a missing sessions folder is an empty list, not an error', async () => {
  const snap = await readClaudeStatus({
    sessionsDir: join(tmpdir(), 'bashme-does-not-exist'),
    now: () => NOW,
    isAppRunning: async () => false,
  });
  assert.deepEqual(snap.chats, []);
  assert.equal(snap.app.running, false);
});
