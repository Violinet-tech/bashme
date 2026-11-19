// ipcServer.ts — how a program on this machine asks the standalone app.
//
// A named pipe (Windows) or unix socket (everywhere else). NOT a network
// socket: nothing here binds a TCP port, which is the constraint violet-dev's
// SECURITY.md pre-commits any bashme surface to. A cross-device approver still
// has to come through an outbound transport in core/channel.ts.
//
// WHAT AUTHENTICATES A CALLER IS THE TOKEN, NOT THE PIPE.
// Node exposes no way to set a DACL on a Windows named pipe, so the pipe's
// own permissions are not something this code can claim anything about. Every
// caller therefore presents a token that was enrolled through the UI, and an
// unknown token is refused before a request object is ever constructed --
// otherwise any local process could raise dialogs at will, and a person worn
// down by dialogs approves the wrong one.
//
// Tokens are compared by hash, in constant time, and never echoed back.

import net from 'node:net';
import crypto from 'node:crypto';
import { randomUUID } from 'node:crypto';
import { unlinkSync, existsSync, chmodSync } from 'node:fs';
import type { Gate, RequestKind, SqliteStore } from '../core/index.ts';

/** Refuse anything larger rather than buffering it. A request is a command line. */
const MAX_FRAME_BYTES = 64 * 1024;
/** A caller that connects and says nothing is dropped. */
const IDLE_MS = 30_000;

export function socketPath(): string {
  if (process.platform === 'win32') {
    // Per-user so two accounts on one machine do not share a gate.
    const who = crypto
      .createHash('sha256')
      .update(process.env.USERNAME ?? 'user')
      .digest('hex')
      .slice(0, 12);
    return `\\\\.\\pipe\\bashme-${who}`;
  }
  return `${process.env.HOME ?? '/tmp'}/.bashme.sock`;
}

export function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token, 'utf8').digest('hex');
}

/** A new client token. Shown once, then only its hash is stored. */
export function mintToken(): string {
  return crypto.randomBytes(32).toString('base64url');
}

const VALID_KINDS: RequestKind[] = ['shell', 'write', 'network', 'elevate'];

interface Incoming {
  token?: unknown;
  kind?: unknown;
  command?: unknown;
  cwd?: unknown;
  summary?: unknown;
}

export interface IpcServerHandle {
  close(): void;
  path: string;
}

export function startIpcServer(
  deps: { gate(): Gate; store(): SqliteStore },
  /** Overridden by tests so a test run cannot collide with a live app's pipe. */
  pathOverride?: string,
): IpcServerHandle {
  const path = pathOverride ?? socketPath();

  // A stale socket file from a crashed run would make listen() fail. Only
  // unlink on posix: a Windows named pipe is not a filesystem entry.
  if (process.platform !== 'win32' && existsSync(path)) {
    try {
      unlinkSync(path);
    } catch {
      /* if it is still held by a live server, listen() below reports it properly */
    }
  }

  const server = net.createServer((socket) => {
    let buffer = '';
    let done = false;

    const reply = (payload: { approved: boolean; reason?: string }): void => {
      if (done) return;
      done = true;
      try {
        socket.end(JSON.stringify(payload) + '\n');
      } catch {
        /* caller vanished; the gate decision is already recorded either way */
      }
    };

    socket.setTimeout(IDLE_MS, () => {
      reply({ approved: false, reason: 'timed out before sending a request' });
      socket.destroy();
    });

    socket.on('error', () => socket.destroy());

    socket.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
      if (buffer.length > MAX_FRAME_BYTES) {
        reply({ approved: false, reason: 'request too large' });
        socket.destroy();
        return;
      }
      const newline = buffer.indexOf('\n');
      if (newline < 0) return;

      const line = buffer.slice(0, newline);
      buffer = '';

      let msg: Incoming;
      try {
        msg = JSON.parse(line) as Incoming;
      } catch {
        reply({ approved: false, reason: 'malformed request' });
        return;
      }

      void handle(msg).then(reply, () =>
        // Never let an internal failure read as an approval.
        reply({ approved: false, reason: 'internal error' }),
      );
    });

    async function handle(msg: Incoming): Promise<{ approved: boolean; reason?: string }> {
      const token = typeof msg.token === 'string' ? msg.token : '';
      if (!token) return { approved: false, reason: 'no token' };

      const client = deps.store().clientByTokenHash(hashToken(token));
      if (!client) {
        // Deliberately not "unknown token" vs "revoked token": both are the
        // same answer to a caller, and the difference is only useful to someone
        // probing for a valid one.
        return { approved: false, reason: 'not enrolled' };
      }

      const kind = VALID_KINDS.includes(msg.kind as RequestKind)
        ? (msg.kind as RequestKind)
        : 'shell';
      const command = typeof msg.command === 'string' ? msg.command : '';
      const cwd = typeof msg.cwd === 'string' && msg.cwd ? msg.cwd : process.cwd();
      if (!command.trim()) return { approved: false, reason: 'no command' };

      deps.store().touchClient(client.id);

      const approved = await deps.gate().request({
        id: randomUUID(),
        kind,
        command,
        cwd,
        // Identity comes from the enrolled token, never from the message. A
        // caller that could name its own originator could name one a rule
        // trusts, which would make every rule forgeable.
        originator: { id: client.id, label: client.label },
        requestedAt: new Date().toISOString(),
        ...(typeof msg.summary === 'string' && msg.summary ? { summary: msg.summary } : {}),
      });

      return { approved };
    }
  });

  server.listen(path, () => {
    if (process.platform !== 'win32') {
      try {
        chmodSync(path, 0o600); // user only; the token is still the real check
      } catch {
        /* best effort */
      }
    }
  });

  return {
    path,
    close: () => {
      try {
        server.close();
      } catch {
        /* shutting down */
      }
    },
  };
}
