// relay.test.ts — the PC half of relay mode, against a mailbox that behaves
// like the deployed worker.
//
// The stand-in here is plain node:http rather than the real Cloudflare Worker
// because what needs testing is the protocol: that the bytes on the wire are
// sealed, that an enrolment code is one-use, that a forged or replayed answer
// changes nothing. Those are properties of this file, not of the forwarder.
// The worker itself is checked against its own API separately.
//
// Note what the fake relay asserts on the way through: every body it receives
// must be undecryptable without the key. A regression that posted a request in
// the clear would still pass every functional test in here, so the transport
// is measured, not trusted.

import test from 'node:test';
import assert from 'node:assert/strict';
import nodeCrypto from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { ActionService } from './actions.ts';
import { RelayTransport, newRelaySession } from './relay.ts';
import type { PresentedRequest } from './gate.ts';

interface FakeRelay {
  origin: string;
  /** Everything that ever passed through, so a test can inspect the wire. */
  seen: { box: string; body: Buffer }[];
  post(box: string, body: Uint8Array): Promise<void>;
  drain(box: string): Promise<Buffer[]>;
  close(): Promise<void>;
}

async function fakeRelay(): Promise<FakeRelay> {
  const boxes = new Map<string, Buffer[]>();
  const seen: { box: string; body: Buffer }[] = [];

  const server: Server = createServer((req, res) => {
    const parts = (req.url ?? '').split('?')[0]!.split('/').filter(Boolean);
    const box = parts[2] ?? '';
    const reply = (body: unknown) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    };

    if (req.method === 'POST') {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        const body = Buffer.concat(chunks);
        seen.push({ box, body });
        const queue = boxes.get(box) ?? [];
        queue.push(body);
        boxes.set(box, queue);
        reply({ ok: true });
      });
      return;
    }

    const queue = boxes.get(box) ?? [];
    boxes.set(box, []);
    reply({ messages: queue.map((b) => b.toString('base64')) });
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;

  return {
    origin: `http://127.0.0.1:${port}`,
    seen,
    async post(box, body) {
      await fetch(`http://127.0.0.1:${port}/s/x/${box}`, { method: 'POST', body });
    },
    async drain(box) {
      const res = (await fetch(`http://127.0.0.1:${port}/s/x/${box}`).then((r) => r.json())) as {
        messages: string[];
      };
      return res.messages.map((m) => Buffer.from(m, 'base64'));
    },
    // closeAllConnections first: the transport polls on a keep-alive socket,
    // and server.close() waits for open connections, so without this the
    // teardown hangs forever instead of failing.
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

/** The phone's side of the envelope, so the test can speak the same protocol. */
async function phoneKey(keyText: string) {
  return crypto.subtle.importKey(
    'raw',
    Buffer.from(keyText.replace(/-/g, '+').replace(/_/g, '/'), 'base64'),
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function seal(key: Awaited<ReturnType<typeof phoneKey>>, message: unknown): Promise<Uint8Array> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(message))),
  );
  const out = new Uint8Array(12 + sealed.length);
  out.set(iv, 0);
  out.set(sealed, 12);
  return out;
}

async function open(key: Awaited<ReturnType<typeof phoneKey>>, raw: Buffer): Promise<Record<string, unknown>> {
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: raw.subarray(0, 12) },
    key,
    raw.subarray(12),
  );
  return JSON.parse(new TextDecoder().decode(plain)) as Record<string, unknown>;
}

function presented(id: string): PresentedRequest {
  return {
    request: {
      id,
      kind: 'shell',
      command: 'rm -rf ./build',
      cwd: 'C:/work',
      summary: null,
      originator: { id: 'cli', label: 'Claude Code' },
      receivedAt: new Date().toISOString(),
    },
    verdict: { decision: 'ask', hardBlocked: true, reasons: ['destructive-filesystem'] },
    confirmToken: 'token',
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    nonce: 'nonce-1',
    hash: 'hash-1',
  } as unknown as PresentedRequest;
}

// The transport polls on a timer, so a test that posts into the PC's mailbox
// has to wait for a turn of it. The interval is shortened rather than the wait
// lengthened, so the suite does not spend real seconds sleeping.
const POLL_MS = 25;
const settle = (ms = POLL_MS * 6) => new Promise((r) => setTimeout(r, ms));

test('a pushed request reaches the phone, sealed', async (t) => {
  const relay = await fakeRelay();

  const session = newRelaySession(relay.origin);
  const transport = new RelayTransport({ pairDevice: () => ({ ok: true, id: 'device-1' }), vapidPublicKey: () => 'vk', setPushEndpoint: () => {} });
  t.after(() => {
    transport.stop();
    return relay.close();
  });
  await transport.start(session, { pollIntervalMs: POLL_MS });

  transport.push(presented('req-1'));
  await settle();

  const inbox = await relay.drain('phone');
  assert.equal(inbox.length, 1);

  // The relay saw bytes it cannot read. Checked directly, because a transport
  // that stopped encrypting would pass every other assertion in this file.
  const wire = inbox[0]!;
  assert.doesNotMatch(wire.toString('utf8'), /rm -rf/);
  assert.throws(() => JSON.parse(wire.toString('utf8')));

  const key = await phoneKey(session.key);
  const message = await open(key, wire);
  assert.equal(message.t, 'request');
  const request = message.request as Record<string, unknown>;
  assert.equal(request.command, 'rm -rf ./build');
  assert.equal(request.hash, 'hash-1');
  assert.equal(request.nonce, 'nonce-1');
  assert.equal(request.hardBlocked, true);
  // The confirm token is the LOCAL dialog's reply credential. It has no
  // business on a wire, encrypted or not.
  assert.equal(request.confirmToken, undefined);
});

test('pairing needs the live code, and spends it', async (t) => {
  const relay = await fakeRelay();

  const paired: string[] = [];
  const transport = new RelayTransport({
    pairDevice: (label) => {
      paired.push(label);
      return { ok: true, id: `device-${paired.length}` };
    },
    vapidPublicKey: () => 'vk',
    setPushEndpoint: () => {},
  });
  t.after(() => {
    transport.stop();
    return relay.close();
  });

  const session = newRelaySession(relay.origin);
  await transport.start(session, { pollIntervalMs: POLL_MS });
  const key = await phoneKey(session.key);
  const { code } = transport.openEnrollment();

  await relay.post('pc', await seal(key, { rid: 'a', t: 'enroll', body: { code: '000000', label: 'Wrong', publicKey: 'k' } }));
  await settle();
  const refusal = await open(key, (await relay.drain('phone'))[0]!);
  assert.equal(refusal.ok, false);
  assert.equal(paired.length, 0);

  await relay.post('pc', await seal(key, { rid: 'b', t: 'enroll', body: { code, label: 'Pixel', publicKey: 'k' } }));
  await settle();
  const accepted = await open(key, (await relay.drain('phone'))[0]!);
  assert.equal(accepted.ok, true);
  assert.equal(accepted.deviceId, 'device-1');
  assert.deepEqual(paired, ['Pixel']);

  // One use. Replaying the same code must not pair a second device.
  await relay.post('pc', await seal(key, { rid: 'c', t: 'enroll', body: { code, label: 'Second', publicKey: 'k' } }));
  await settle();
  assert.deepEqual(paired, ['Pixel']);
  assert.equal(transport.status().enrollCode, null);
});

test('an answer is forwarded once, and only for a live request', async (t) => {
  const relay = await fakeRelay();

  const answers: unknown[] = [];
  const transport = new RelayTransport({ pairDevice: () => ({ ok: true, id: 'd' }), vapidPublicKey: () => 'vk', setPushEndpoint: () => {} });
  t.after(() => {
    transport.stop();
    return relay.close();
  });
  transport.onAnswer((a) => answers.push(a));

  const session = newRelaySession(relay.origin);
  await transport.start(session, { pollIntervalMs: POLL_MS });
  const key = await phoneKey(session.key);

  // Nothing pending: an answer for a request this machine never asked about
  // is discarded rather than handed to the gate.
  await relay.post('pc', await seal(key, { t: 'answer', body: { requestId: 'ghost', deviceId: 'd', decision: 'approve', signature: 's' } }));
  await settle();
  assert.deepEqual(answers, []);

  transport.push(presented('req-1'));
  await settle();
  await relay.post('pc', await seal(key, { t: 'answer', body: { requestId: 'req-1', deviceId: 'd', decision: 'approve', signature: 'sig' } }));
  await settle();
  assert.equal(answers.length, 1);
  assert.deepEqual(answers[0], {
    requestId: 'req-1',
    deviceId: 'd',
    decision: 'approve',
    signatureBase64: 'sig',
  });

  // Replayed. The relay reads before it deletes, so a duplicate delivery is
  // expected rather than suspicious -- and must still settle only once.
  await relay.post('pc', await seal(key, { t: 'answer', body: { requestId: 'req-1', deviceId: 'd', decision: 'deny', signature: 'sig' } }));
  await settle();
  assert.equal(answers.length, 1);
});

test('a message the key does not open is ignored, not crashed on', async (t) => {
  const relay = await fakeRelay();

  const answers: unknown[] = [];
  const transport = new RelayTransport({ pairDevice: () => ({ ok: true, id: 'd' }), vapidPublicKey: () => 'vk', setPushEndpoint: () => {} });
  t.after(() => {
    transport.stop();
    return relay.close();
  });
  transport.onAnswer((a) => answers.push(a));

  const session = newRelaySession(relay.origin);
  await transport.start(session, { pollIntervalMs: POLL_MS });
  transport.push(presented('req-1'));
  await settle();

  // A hostile relay writing its own traffic into the PC's mailbox: plaintext
  // JSON, and a body sealed under a different key.
  const other = await phoneKey(newRelaySession(relay.origin).key);
  await relay.post('pc', new TextEncoder().encode(JSON.stringify({ t: 'answer', body: { requestId: 'req-1', decision: 'approve' } })));
  await relay.post('pc', await seal(other, { t: 'answer', body: { requestId: 'req-1', deviceId: 'd', decision: 'approve', signature: 'x' } }));
  await settle();

  assert.deepEqual(answers, []);
  assert.equal(transport.isAvailable(), true);
});

test('the pairing URL keeps the key out of everything a server would see', async (t) => {
  const relay = await fakeRelay();

  const transport = new RelayTransport({ pairDevice: () => ({ ok: true, id: 'd' }), vapidPublicKey: () => 'vk', setPushEndpoint: () => {} });
  t.after(() => {
    transport.stop();
    return relay.close();
  });
  const session = newRelaySession(relay.origin);
  await transport.start(session, { pollIntervalMs: POLL_MS });
  transport.openEnrollment();

  const url = new URL(transport.status().pairingUrl!);
  assert.equal(url.search, '', 'a query string is sent to the server; the key must not be in one');
  assert.equal(url.pathname, '/p');

  const fragment = new URLSearchParams(url.hash.slice(1));
  assert.equal(fragment.get('s'), session.sessionId);
  assert.equal(fragment.get('k'), session.key);
  assert.match(fragment.get('c') ?? '', /^[0-9]{6}$/);

  // The session id is the mailbox name and is not secret; the key is.
  assert.doesNotMatch(url.pathname, new RegExp(session.key.slice(0, 8)));
});

test('stopping ends the polling and the enrolment window', async (t) => {
  const relay = await fakeRelay();
  t.after(() => relay.close());

  const transport = new RelayTransport({ pairDevice: () => ({ ok: true, id: 'd' }), vapidPublicKey: () => 'vk', setPushEndpoint: () => {} });
  await transport.start(newRelaySession(relay.origin), { pollIntervalMs: POLL_MS });
  transport.openEnrollment();
  assert.equal(transport.isAvailable(), true);

  transport.stop();
  assert.equal(transport.isAvailable(), false);
  assert.equal(transport.status().enrollCode, null);
  assert.equal(transport.status().pairingUrl, null);
});

test('a relay that is not there fails the start rather than looking fine', async () => {
  const transport = new RelayTransport({ pairDevice: () => ({ ok: true, id: 'd' }), vapidPublicKey: () => 'vk', setPushEndpoint: () => {} });
  // Port 1 on loopback refuses immediately. A transport that swallowed this
  // would report running, push into nothing, and deny everything on timeout.
  await assert.rejects(() => transport.start(newRelaySession('http://127.0.0.1:1')));
  assert.equal(transport.isAvailable(), false);
});

test('an action asked for by the phone runs, and the wire never carries the command', async (t) => {
  const relay = await fakeRelay();

  const signer = nodeCrypto.generateKeyPairSync('ed25519');
  const publicKey = signer.publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
  const ran: string[] = [];
  const actions = new ActionService(
    {
      devices: () => [{ id: 'device-1', label: 'Pixel', publicKey, pairedAt: new Date().toISOString() }],
      run: async (a) => {
        ran.push(a.id);
        return { ok: true, output: 'SUCCESS: task queued' };
      },
    },
    [{ id: 'netfix', label: 'Fix the network', command: 'schtasks /run /tn VioletNetFix' }],
  );

  const transport = new RelayTransport({
    pairDevice: () => ({ ok: true, id: 'device-1' }), vapidPublicKey: () => 'vk', setPushEndpoint: () => {},
    actions,
  });
  t.after(() => {
    transport.stop();
    return relay.close();
  });

  const session = newRelaySession(relay.origin);
  await transport.start(session, { pollIntervalMs: POLL_MS });
  const key = await phoneKey(session.key);

  // 1. The phone asks what it may run.
  await relay.post('pc', await seal(key, { rid: 'list', t: 'actions?' }));
  await settle();
  const offer = await open(key, (await relay.drain('phone'))[0]!);
  const offered = offer.actions as Array<Record<string, unknown>>;
  assert.equal(offered.length, 1);
  assert.equal(offered[0]!.label, 'Fix the network');
  assert.equal(offered[0]!.command, undefined, 'the phone is told a label, never a command');

  // 2. It signs the id against the nonce the PC issued.
  const nonce = String(offer.nonce);
  const signature = nodeCrypto
    .sign(null, Buffer.from(`action|netfix|${nonce}`), signer.privateKey)
    .toString('base64');
  await relay.post(
    'pc',
    await seal(key, { rid: 'go', t: 'action', body: { actionId: 'netfix', deviceId: 'device-1', nonce, signature } }),
  );
  await settle();

  const result = await open(key, (await relay.drain('phone'))[0]!);
  assert.equal(result.ok, true);
  assert.deepEqual(ran, ['netfix']);

  // 3. Nothing a relay operator saw named the command.
  const seen = relay.seen.map((m) => m.body.toString('utf8')).join('');
  assert.doesNotMatch(seen, /schtasks/);
  assert.doesNotMatch(seen, /VioletNetFix/);
});

test('status? returns a sanitised snapshot, and the relay only ever sees sealed bytes', async (t) => {
  const relay = await fakeRelay();
  const transport = new RelayTransport({
    pairDevice: () => ({ ok: true, id: 'device-1' }), vapidPublicKey: () => 'vk', setPushEndpoint: () => {},
    // Extra and hostile fields: none of them may reach the phone.
    status: () => ({
      app: { name: 'Claude', running: true, path: 'C:\\secret\\Claude.exe' },
      chats: [
        { id: 'c1', title: 'Fix the build', state: 'working', ageSeconds: 5, model: 'm', cwd: 'C:\\private', transcript: 'do not leak' },
      ],
    }),
  });
  t.after(() => {
    transport.stop();
    return relay.close();
  });

  const session = newRelaySession(relay.origin);
  await transport.start(session, { pollIntervalMs: POLL_MS });
  const key = await phoneKey(session.key);

  await relay.post('pc', await seal(key, { rid: 's1', t: 'status?' }));
  await settle();
  const reply = await open(key, (await relay.drain('phone'))[0]!);
  const status = reply.status as { app: Record<string, unknown>; chats: Array<Record<string, unknown>> };
  assert.equal(reply.ok, true);
  assert.equal(status.app.running, true);
  assert.equal(status.app.path, undefined, 'unknown fields are dropped');
  assert.equal(status.chats[0]!.title, 'Fix the build');
  assert.equal(status.chats[0]!.cwd, undefined);
  assert.equal(status.chats[0]!.transcript, undefined);

  const plain = relay.seen.map((m) => m.body.toString('utf8')).join('');
  assert.doesNotMatch(plain, /Fix the build/);
});

test('status? with no provider is indistinguishable from nothing to show', async (t) => {
  const relay = await fakeRelay();
  const transport = new RelayTransport({
    pairDevice: () => ({ ok: true, id: 'device-1' }), vapidPublicKey: () => 'vk', setPushEndpoint: () => {},
  });
  t.after(() => {
    transport.stop();
    return relay.close();
  });
  const session = newRelaySession(relay.origin);
  await transport.start(session, { pollIntervalMs: POLL_MS });
  const key = await phoneKey(session.key);

  await relay.post('pc', await seal(key, { rid: 's2', t: 'status?' }));
  await settle();
  const reply = await open(key, (await relay.drain('phone'))[0]!);
  assert.equal(reply.ok, true);
  assert.equal(reply.status, null);
});
