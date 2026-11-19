// lanServer.test.ts — the listener's security properties, exercised over a real
// socket rather than by calling its methods directly.
//
// These are written against the failure modes that matter for a listening port:
// enrolling without a code, guessing a code, reading pending requests without
// being paired, and answering with a key that is not the paired one. A test
// that only proves the happy path would pass just as happily on a version of
// this file with every check removed.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { LanServer } from './lanServer.ts';
import { verifyDeviceSignature } from '../core/confirm.ts';
import type { PairedDevice } from '../core/types.ts';
import type { PresentedRequest } from '../core/gate.ts';

function deviceKeypair(): { publicKeyBase64: string; privateKey: crypto.KeyObject } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    publicKeyBase64: (publicKey.export({ format: 'der', type: 'spki' }) as Buffer).toString('base64'),
    privateKey,
  };
}

function presented(id: string): PresentedRequest {
  return {
    request: {
      id,
      kind: 'shell',
      command: 'npm run build',
      cwd: 'C:\\work',
      originator: { id: 'claude-code', label: 'Claude Code' },
      requestedAt: new Date().toISOString(),
    },
    verdict: { hardBlocked: false, reasons: [], notes: [] },
    confirmToken: 'unused-here',
    expiresAt: new Date(Date.now() + 60000).toISOString(),
    nonce: 'test-nonce',
    hash: 'test-hash',
  } as PresentedRequest;
}

interface Harness {
  server: LanServer;
  base: string;
  devices: PairedDevice[];
  answers: unknown[];
  stop(): Promise<void>;
}

async function harness(): Promise<Harness> {
  const devices: PairedDevice[] = [];
  const answers: unknown[] = [];

  const server = new LanServer({
    listDevices: () => devices,
    pairDevice: (label, publicKey) => {
      const id = `device-${devices.length + 1}`;
      devices.push({ id, label, publicKey, pairedAt: new Date().toISOString() });
      return { ok: true, id };
    },
    vapidPublicKey: () => 'vk',
    setPushEndpoint: () => {},
  });

  server.onAnswer((a) => answers.push(a));
  // Port 0 would be ideal, but the certificate has to name the address before
  // listen() runs, so a fixed high port on loopback is used instead.
  const status = await server.start('127.0.0.1', 18787);
  return {
    server,
    base: status.url!,
    devices,
    answers,
    stop: () => server.stopAsync(),
  };
}

// The certificate is self-signed by design, so the test client must not verify
// it — exactly as the phone's browser will not, after the user accepts it once.
const call = async (url: string, init?: RequestInit): Promise<any> => {
  const res = await fetch(url, {
    ...init,
    // @ts-expect-error Node's fetch accepts a dispatcher-free TLS opt-out here
    tls: { rejectUnauthorized: false },
  });
  return res.json();
};

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

test('enrollment is refused when no code is open', async () => {
  const h = await harness();
  try {
    const key = deviceKeypair();
    const res = await call(`${h.base}api/enroll`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ code: '000000', label: 'Phone', publicKey: key.publicKeyBase64 }),
    });
    assert.equal(res.ok, false);
    assert.equal(h.devices.length, 0);
  } finally {
    await h.stop();
  }
});

test('a wrong code does not pair, and the real code still works afterwards', async () => {
  const h = await harness();
  try {
    const { code } = h.server.openEnrollment();
    const key = deviceKeypair();

    const wrong = await call(`${h.base}api/enroll`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ code: '999999', label: 'Phone', publicKey: key.publicKeyBase64 }),
    });
    assert.equal(wrong.ok, false);
    assert.equal(h.devices.length, 0);

    const right = await call(`${h.base}api/enroll`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ code, label: 'Phone', publicKey: key.publicKeyBase64 }),
    });
    assert.equal(right.ok, true);
    assert.equal(h.devices.length, 1);
  } finally {
    await h.stop();
  }
});

test('an enrollment code is single-use', async () => {
  const h = await harness();
  try {
    const { code } = h.server.openEnrollment();
    const first = deviceKeypair();
    const second = deviceKeypair();

    const a = await call(`${h.base}api/enroll`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ code, label: 'Phone', publicKey: first.publicKeyBase64 }),
    });
    assert.equal(a.ok, true);

    const b = await call(`${h.base}api/enroll`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ code, label: 'Laptop', publicKey: second.publicKeyBase64 }),
    });
    assert.equal(b.ok, false, 'a reused code must not pair a second device');
    assert.equal(h.devices.length, 1);
  } finally {
    await h.stop();
  }
});

test('pending requests are not readable without a paired device id', async () => {
  const h = await harness();
  try {
    h.server.push(presented('req-1'));

    const anonymous = await call(`${h.base}api/pending`);
    assert.deepEqual(anonymous.requests, [], 'an unknown caller must learn nothing');

    const guessed = await call(`${h.base}api/pending?deviceId=device-1`);
    assert.deepEqual(guessed.requests, [], 'a device id that is not paired must learn nothing');
  } finally {
    await h.stop();
  }
});

test('a paired device sees the request and can sign an answer the gate accepts', async () => {
  const h = await harness();
  try {
    const { code } = h.server.openEnrollment();
    const key = deviceKeypair();
    const enrolled = await call(`${h.base}api/enroll`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ code, label: 'Phone', publicKey: key.publicKeyBase64 }),
    });

    h.server.push(presented('req-1'));

    const list = await call(`${h.base}api/pending?deviceId=${enrolled.deviceId}`);
    assert.equal(list.requests.length, 1);
    const req = list.requests[0];
    assert.equal(req.command, 'npm run build');

    const signature = crypto.sign(
      null,
      Buffer.from(`${req.hash}|${req.nonce}|approve`),
      key.privateKey,
    );
    const res = await call(`${h.base}api/answer`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        requestId: req.id,
        deviceId: enrolled.deviceId,
        decision: 'approve',
        signature: signature.toString('base64'),
      }),
    });
    assert.equal(res.ok, true);
    assert.equal(h.answers.length, 1);

    // The signature the phone produced must satisfy the same check the gate
    // runs. This is the property the whole transport rests on.
    const answer = h.answers[0] as { signatureBase64: string };
    assert.ok(
      verifyDeviceSignature({
        publicKeyBase64: key.publicKeyBase64,
        requestHash: req.hash,
        nonce: req.nonce,
        decision: 'approve',
        signatureBase64: answer.signatureBase64,
      }),
    );
  } finally {
    await h.stop();
  }
});

test('an answer signed by an unpaired key fails the gate check', async () => {
  const h = await harness();
  try {
    const { code } = h.server.openEnrollment();
    const real = deviceKeypair();
    const attacker = deviceKeypair();
    const enrolled = await call(`${h.base}api/enroll`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ code, label: 'Phone', publicKey: real.publicKeyBase64 }),
    });

    h.server.push(presented('req-1'));
    const list = await call(`${h.base}api/pending?deviceId=${enrolled.deviceId}`);
    const req = list.requests[0];

    const forged = crypto.sign(
      null,
      Buffer.from(`${req.hash}|${req.nonce}|approve`),
      attacker.privateKey,
    );
    await call(`${h.base}api/answer`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        requestId: req.id,
        deviceId: enrolled.deviceId,
        decision: 'approve',
        signature: forged.toString('base64'),
      }),
    });

    // The listener forwards it — it is not the trust boundary — but the check
    // the gate performs must reject it.
    const answer = h.answers[0] as { signatureBase64: string };
    assert.equal(
      verifyDeviceSignature({
        publicKeyBase64: real.publicKeyBase64,
        requestHash: req.hash,
        nonce: req.nonce,
        decision: 'approve',
        signatureBase64: answer.signatureBase64,
      }),
      false,
    );
  } finally {
    await h.stop();
  }
});

test('the server refuses to bind an address this machine does not hold', async () => {
  const server = new LanServer({
    listDevices: () => [],
    pairDevice: () => ({ ok: true, id: 'x' }),
    vapidPublicKey: () => 'vk',
    setPushEndpoint: () => {},
  });
  await assert.rejects(
    () => server.start('203.0.113.9'),
    /not an address on this machine/,
    'a typo must not fall through to a wildcard bind',
  );
});
