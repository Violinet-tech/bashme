#!/usr/bin/env node
// bashme — ask the running bashme app for permission, from a script.
//
//   BASHME_TOKEN=... bashme ask -- npm run build
//   BASHME_TOKEN=... bashme ask --kind write -- ./out/report.txt
//
// Exit 0 = approved, 1 = denied, 2 = could not ask. A caller should treat
// anything other than 0 as "do not proceed": "could not ask" is not a softer
// denial, it means nobody was there to say yes.
//
// The token comes from the environment, not from a flag, because a flag is
// visible in the process list to every other user on the machine.

import net from 'node:net';
import crypto from 'node:crypto';
import process from 'node:process';
import { writeFileSync, chmodSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';

function socketPath() {
  if (process.platform === 'win32') {
    const who = crypto
      .createHash('sha256')
      .update(process.env.USERNAME ?? 'user')
      .digest('hex')
      .slice(0, 12);
    return `\\\\.\\pipe\\bashme-${who}`;
  }
  return `${process.env.HOME ?? '/tmp'}/.bashme.sock`;
}

function usage(code) {
  process.stderr.write(
    [
      'usage:',
      '  bashme ask [--kind shell|write|network|elevate] [--cwd DIR] -- COMMAND...',
      '      Requires BASHME_TOKEN, issued by the bashme app under Clients.',
      '      Exit 0 approved, 1 denied, 2 could not ask.',
      '',
      '  bashme device keygen [--out FILE]',
      '      Make an approving-device identity. Prints the public key to paste',
      '      into the app, and the fingerprint to compare against what it shows.',
      '',
    ].join('\n'),
  );
  process.exit(code);
}

const argv = process.argv.slice(2);

if (argv[0] === 'device' && argv[1] === 'keygen') {
  let out = join(process.env.HOME ?? process.env.USERPROFILE ?? '.', '.bashme', 'device.key');
  for (let a = 2; a < argv.length; a++) {
    if (argv[a] === '--out') out = argv[++a] ?? out;
    else usage(2);
  }

  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const der = publicKey.export({ format: 'der', type: 'spki' });
  const fingerprint = (
    crypto.createHash('sha256').update(der).digest('hex').slice(0, 16).toUpperCase().match(/.{1,4}/g) ?? []
  ).join(' ');

  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600 });
  try {
    chmodSync(out, 0o600); // no-op on Windows, where ACLs are not chmod
  } catch {
    /* best effort */
  }

  process.stdout.write(
    [
      `private key written to ${out} (keep it on this device, never paste it)`,
      '',
      'public key — paste this into the app:',
      der.toString('base64'),
      '',
      `fingerprint — must match what the app shows: ${fingerprint}`,
      '',
    ].join('\n'),
  );
  process.exit(0);
}

if (argv[0] !== 'ask') usage(argv.length ? 2 : 0);

let kind = 'shell';
let cwd = process.cwd();
let i = 1;
for (; i < argv.length; i++) {
  if (argv[i] === '--') {
    i++;
    break;
  }
  if (argv[i] === '--kind') kind = argv[++i] ?? 'shell';
  else if (argv[i] === '--cwd') cwd = argv[++i] ?? cwd;
  else usage(2);
}

const command = argv.slice(i).join(' ').trim();
if (!command) usage(2);

const callerToken = process.env.BASHME_TOKEN?.trim();
if (!callerToken) {
  process.stderr.write('bashme: BASHME_TOKEN is not set. Enrol this program in the app first.\n');
  process.exit(2);
}

const path = socketPath();
const socket = net.createConnection(path);
let buffer = '';
let settled = false;

// Deny-on-anything-unexpected. Every path out of here that is not an explicit
// {approved:true} exits non-zero.
function finish(code, message) {
  if (settled) return;
  settled = true;
  if (message) process.stderr.write(`bashme: ${message}\n`);
  socket.destroy();
  process.exit(code);
}

socket.setTimeout(5 * 60 * 1000, () => finish(2, 'timed out waiting for an answer'));

socket.on('error', (err) => {
  const hint =
    err.code === 'ENOENT' || err.code === 'ECONNREFUSED'
      ? 'the bashme app does not appear to be running'
      : err.message;
  finish(2, hint);
});

socket.on('connect', () => {
  socket.write(JSON.stringify({ token: callerToken, kind, command, cwd }) + '\n');
});

socket.on('data', (chunk) => {
  buffer += chunk.toString('utf8');
  const newline = buffer.indexOf('\n');
  if (newline < 0) return;
  let res;
  try {
    res = JSON.parse(buffer.slice(0, newline));
  } catch {
    finish(2, 'malformed reply');
    return;
  }
  if (res.approved === true) finish(0);
  else finish(1, res.reason || 'denied');
});

socket.on('close', () => finish(2, 'connection closed before an answer'));
