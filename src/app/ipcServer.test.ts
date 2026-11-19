// The local IPC surface is the one place an untrusted program on this machine
// touches the gate, so the properties tested here are the ones that matter:
// an unenrolled caller is refused before a request exists, and a caller cannot
// choose the originator that rules key on.

import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { DatabaseSync } from 'node:sqlite';

import { startIpcServer, hashToken, mintToken } from './ipcServer.ts';
import { Gate, SqliteStore } from '../core/index.ts';
import type { Db, GateRequest } from '../core/index.ts';

const ROOT = process.platform === 'win32' ? 'C:\\work' : '/work';

let seq = 0;
function testPath(): string {
  seq++;
  return process.platform === 'win32'
    ? `\\\\.\\pipe\\bashme-test-${process.pid}-${seq}`
    : `/tmp/bashme-test-${process.pid}-${seq}.sock`;
}

interface Harness {
  path: string;
  store: SqliteStore;
  seen: GateRequest[];
  close(): void;
}

function harness(answer: boolean): Harness {
  const store = new SqliteStore(new DatabaseSync(':memory:') as unknown as Db);
  const seen: GateRequest[] = [];
  const gate = new Gate(
    { enabled: true, rulesEnabled: false, devicesEnabled: false, workspaceRoot: ROOT, timeoutMs: 400 },
    {
      audit: { append: (r) => store.appendAudit(r) },
      rules: { list: () => [], recordMatch: () => {} },
      present: (p) => {
        seen.push(p.request);
        // Answer on the next tick, as a human would, via the real token path.
        setTimeout(() => gate.respondLocal(p.request.id, answer, p.confirmToken), 1);
      },
    },
  );
  const path = testPath();
  const server = startIpcServer({ gate: () => gate, store: () => store }, path);
  return { path, store, seen, close: () => server.close() };
}

function ask(path: string, payload: unknown): Promise<{ approved?: boolean; reason?: string }> {
  return new Promise((resolve) => {
    const socket = net.createConnection(path);
    let buf = '';
    const done = (v: { approved?: boolean; reason?: string }): void => {
      socket.destroy();
      resolve(v);
    };
    socket.on('error', (e) => done({ reason: `socket error: ${e.message}` }));
    socket.on('connect', () => socket.write(JSON.stringify(payload) + '\n'));
    socket.on('data', (c) => {
      buf += c.toString('utf8');
      const nl = buf.indexOf('\n');
      if (nl >= 0) {
        try {
          done(JSON.parse(buf.slice(0, nl)));
        } catch {
          done({ reason: 'unparseable' });
        }
      }
    });
    socket.on('close', () => done({ reason: 'closed' }));
  });
}

/** Give the server a moment to bind before the first connect. */
const listening = (): Promise<void> => new Promise((r) => setTimeout(r, 50));

test('a request with no token never reaches the gate', async () => {
  const h = harness(true);
  await listening();
  const res = await ask(h.path, { command: 'npm run build' });
  assert.equal(res.approved, false);
  assert.equal(h.seen.length, 0, 'nothing should have been presented to a human');
  h.close();
});

test('an unenrolled token is refused, and does not say why', async () => {
  const h = harness(true);
  await listening();
  const res = await ask(h.path, { token: mintToken(), command: 'npm run build' });
  assert.equal(res.approved, false);
  assert.equal(res.reason, 'not enrolled');
  assert.equal(h.seen.length, 0);
  h.close();
});

test('an enrolled token reaches the gate and can be approved', async () => {
  const h = harness(true);
  const token = mintToken();
  h.store.addClient({ id: 'client:cli', label: 'CLI', tokenSha256: hashToken(token) });
  await listening();
  const res = await ask(h.path, { token, command: 'npm run build', cwd: ROOT });
  assert.equal(res.approved, true);
  assert.equal(h.seen.length, 1);
  h.close();
});

test('a denial comes back as a denial', async () => {
  const h = harness(false);
  const token = mintToken();
  h.store.addClient({ id: 'client:cli', label: 'CLI', tokenSha256: hashToken(token) });
  await listening();
  assert.equal((await ask(h.path, { token, command: 'rm -rf /', cwd: ROOT })).approved, false);
  h.close();
});

test('the caller cannot choose its own originator', async () => {
  // The whole point: rules key on originator id, so a caller that could name
  // one would be able to satisfy a rule written for something else.
  const h = harness(true);
  const token = mintToken();
  h.store.addClient({ id: 'client:cli', label: 'CLI', tokenSha256: hashToken(token) });
  await listening();
  await ask(h.path, {
    token,
    command: 'npm run build',
    cwd: ROOT,
    originator: { id: 'violet-os:agent-tools', label: 'Agent tools' },
  });
  assert.equal(h.seen[0]?.originator.id, 'client:cli', 'identity must come from the token');
  h.close();
});

test('a revoked client is refused', async () => {
  const h = harness(true);
  const token = mintToken();
  h.store.addClient({ id: 'client:cli', label: 'CLI', tokenSha256: hashToken(token) });
  h.store.revokeClient('client:cli');
  await listening();
  const res = await ask(h.path, { token, command: 'npm run build' });
  assert.equal(res.approved, false);
  assert.equal(h.seen.length, 0);
  h.close();
});

test('an empty command is refused', async () => {
  const h = harness(true);
  const token = mintToken();
  h.store.addClient({ id: 'client:cli', label: 'CLI', tokenSha256: hashToken(token) });
  await listening();
  assert.equal((await ask(h.path, { token, command: '   ' })).approved, false);
  assert.equal(h.seen.length, 0);
  h.close();
});

test('malformed JSON is refused rather than crashing the server', async () => {
  const h = harness(true);
  await listening();
  const res = await new Promise<{ approved?: boolean }>((resolve) => {
    const s = net.createConnection(h.path);
    let buf = '';
    s.on('connect', () => s.write('{not json\n'));
    s.on('data', (c) => {
      buf += c.toString('utf8');
      if (buf.includes('\n')) {
        s.destroy();
        resolve(JSON.parse(buf.slice(0, buf.indexOf('\n'))));
      }
    });
    s.on('error', () => resolve({}));
  });
  assert.equal(res.approved, false);

  // The server must still be alive for the next caller.
  const token = mintToken();
  h.store.addClient({ id: 'client:cli', label: 'CLI', tokenSha256: hashToken(token) });
  assert.equal((await ask(h.path, { token, command: 'npm run build', cwd: ROOT })).approved, true);
  h.close();
});

test('an oversized frame is refused rather than buffered', async () => {
  const h = harness(true);
  await listening();
  const res = await new Promise<{ approved?: boolean; reason?: string }>((resolve) => {
    const s = net.createConnection(h.path);
    let buf = '';
    s.on('connect', () => s.write('x'.repeat(70 * 1024)));
    s.on('data', (c) => {
      buf += c.toString('utf8');
      if (buf.includes('\n')) {
        s.destroy();
        resolve(JSON.parse(buf.slice(0, buf.indexOf('\n'))));
      }
    });
    s.on('error', () => resolve({ reason: 'error' }));
    s.on('close', () => resolve({ reason: 'closed' }));
  });
  assert.notEqual(res.approved, true);
  h.close();
});

test('hashToken is stable and mintToken is not guessable-length', () => {
  assert.equal(hashToken('abc'), hashToken('abc'));
  assert.notEqual(hashToken('abc'), hashToken('abd'));
  assert.ok(mintToken().length >= 40);
  assert.notEqual(mintToken(), mintToken());
});
