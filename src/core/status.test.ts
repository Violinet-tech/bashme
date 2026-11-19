// status.test.ts — the phone status snapshot: what survives sanitising, and how a
// chat's bookkeeping becomes a state.

import test from 'node:test';
import assert from 'node:assert/strict';

import { MAX_CHATS, WORKING_WINDOW_SECONDS, chatState, sanitizeStatus } from './status.ts';

test('sanitizeStatus keeps only the known fields and caps what it keeps', () => {
  const out = sanitizeStatus({
    app: { name: 'Claude', running: true, path: 'C:\\x' },
    chats: [
      { id: 'a', title: 'T'.repeat(500), state: 'done', detail: 'D'.repeat(500), ageSeconds: 12.6, model: 'm', cwd: 'C:\\y' },
    ],
    extra: 'dropped',
  });
  assert.equal(out.app.running, true);
  assert.equal('path' in out.app, false);
  assert.equal(out.chats[0]!.title.length, 80);
  assert.equal(out.chats[0]!.detail.length, 100);
  assert.equal(out.chats[0]!.ageSeconds, 13);
  assert.equal('cwd' in out.chats[0]!, false);
  assert.equal('extra' in out, false);
});

test('sanitizeStatus survives garbage and bounds the list', () => {
  assert.deepEqual(sanitizeStatus(null).chats, []);
  assert.equal(sanitizeStatus('nope').app.running, false);
  const many = Array.from({ length: 40 }, (_, i) => ({ id: `c${i}`, title: 'x', state: 'working', ageSeconds: i }));
  assert.equal(sanitizeStatus({ chats: many }).chats.length, MAX_CHATS);
  const out = sanitizeStatus({ chats: [{ title: 'no id' }, { id: 'ok', state: 'bogus', ageSeconds: -4 }] });
  assert.equal(out.chats.length, 1, 'a row with no id is skipped');
  assert.equal(out.chats[0]!.state, 'idle', 'an unknown state becomes idle');
  assert.equal(out.chats[0]!.ageSeconds, 0, 'a negative age is not trusted');
});

test('a chat that moved in the last minute is working, whatever its last label said', () => {
  assert.equal(chatState('completed', WORKING_WINDOW_SECONDS), 'working');
  assert.equal(chatState('blocked', 5), 'working');
});

test('older chats follow the apps own label', () => {
  const old = WORKING_WINDOW_SECONDS + 1;
  assert.equal(chatState('blocked', old), 'needs-you');
  assert.equal(chatState('review_ready', old), 'review');
  assert.equal(chatState('completed', old), 'done');
  assert.equal(chatState(null, old), 'idle');
  assert.equal(chatState('something-new', old), 'idle');
});
