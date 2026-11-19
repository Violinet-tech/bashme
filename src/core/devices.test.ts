import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

import {
  parseDeviceKey,
  fingerprintOf,
  generateDeviceKeypair,
  signDeviceAnswer,
} from './devices.ts';
import { verifyDeviceSignature } from './confirm.ts';
import { Gate } from './gate.ts';
import { SqliteStore } from './store.ts';
import type { Db, GateRequest, PresentedRequest } from './index.ts';

test('a generated device key parses and fingerprints consistently', () => {
  const kp = generateDeviceKeypair();
  const parsed = parseDeviceKey(kp.publicKey);
  assert.ok(parsed.ok);
  assert.equal(parsed.value.fingerprint, kp.fingerprint);
  assert.equal(fingerprintOf(kp.publicKey), kp.fingerprint);
});

test('fingerprints are grouped for comparison and differ per key', () => {
  const a = generateDeviceKeypair();
  const b = generateDeviceKeypair();
  assert.match(a.fingerprint, /^[0-9A-F]{4}( [0-9A-F]{4}){3}$/);
  assert.notEqual(a.fingerprint, b.fingerprint);
});

test('PEM wrapping and stray whitespace are tolerated', () => {
  const kp = generateDeviceKeypair();
  const pem = `-----BEGIN PUBLIC KEY-----\n${kp.publicKey}\n-----END PUBLIC KEY-----`;
  const parsed = parseDeviceKey(pem);
  assert.ok(parsed.ok);
  assert.equal(parsed.value.publicKey, kp.publicKey);
});

test('the stored key is re-exported, so two encodings are one device', () => {
  const kp = generateDeviceKeypair();
  const spaced = kp.publicKey.match(/.{1,20}/g)?.join('\n') ?? kp.publicKey;
  const a = parseDeviceKey(kp.publicKey);
  const b = parseDeviceKey(spaced);
  assert.ok(a.ok && b.ok);
  assert.equal(a.value.publicKey, b.value.publicKey);
});

test('empty input is refused with an instruction, not a stack trace', () => {
  const r = parseDeviceKey('   ');
  assert.equal(r.ok, false);
  assert.match(r.ok === false ? r.error : '', /paste/i);
});

test('non-base64 is refused', () => {
  const r = parseDeviceKey('!!!! not base64 !!!!');
  assert.equal(r.ok, false);
});

test('a valid key of the wrong algorithm is refused, not stored', () => {
  // The failure this prevents: an RSA key stores fine, the device looks paired,
  // and then every approval it sends fails verification.
  const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const der = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
  const r = parseDeviceKey(der);
  assert.equal(r.ok, false);
  assert.match(r.ok === false ? r.error : '', /Ed25519/);
});

test('a keypair from this module produces signatures the gate accepts', () => {
  const kp = generateDeviceKeypair();
  const requestHash = 'a'.repeat(64);
  const nonce = 'nonce-1';
  const signatureBase64 = signDeviceAnswer({
    privateKeyPem: kp.privateKey,
    requestHash,
    nonce,
    decision: 'approve',
  });

  assert.equal(
    verifyDeviceSignature({
      publicKeyBase64: kp.publicKey,
      requestHash,
      nonce,
      decision: 'approve',
      signatureBase64,
    }),
    true,
  );

  // The same signature must not carry to a different decision or nonce.
  assert.equal(
    verifyDeviceSignature({
      publicKeyBase64: kp.publicKey,
      requestHash,
      nonce,
      decision: 'deny',
      signatureBase64,
    }),
    false,
  );
  assert.equal(
    verifyDeviceSignature({
      publicKeyBase64: kp.publicKey,
      requestHash,
      nonce: 'nonce-2',
      decision: 'approve',
      signatureBase64,
    }),
    false,
  );
});

test('a device paired the way the UI pairs it can actually approve', async () => {
  // The whole path pairing exists for: a key minted the way `bashme device
  // keygen` mints it, parsed and normalised the way the pairing screen does,
  // stored the way the store stores it, then used to settle a real request.
  const ROOT = process.platform === 'win32' ? 'C:\\work' : '/work';
  const kp = generateDeviceKeypair();
  const parsed = parseDeviceKey(kp.publicKey);
  assert.ok(parsed.ok);

  const store = new SqliteStore(new DatabaseSync(':memory:') as unknown as Db);
  store.pairDevice({
    id: 'device:phone-a1b2',
    label: 'Phone',
    publicKey: parsed.value.publicKey,
    pairedAt: new Date().toISOString(),
  });

  let presented: PresentedRequest | null = null;
  const gate = new Gate(
    { enabled: true, rulesEnabled: false, devicesEnabled: true, workspaceRoot: ROOT, timeoutMs: 500 },
    {
      audit: { append: (r) => store.appendAudit(r) },
      rules: { list: () => [], recordMatch: () => {} },
      present: (p) => {
        presented = p;
      },
      listDevices: () => store.listDevices(),
      pushToDevices: () => {},
    },
  );

  const req: GateRequest = {
    id: 'req-1',
    kind: 'shell',
    command: 'npm run build',
    cwd: ROOT,
    originator: { id: 'client:cli', label: 'CLI' },
    requestedAt: new Date().toISOString(),
  };
  const promise = gate.request(req);
  const p = presented as unknown as PresentedRequest;

  assert.equal(
    gate.respondDevice({
      requestId: req.id,
      deviceId: 'device:phone-a1b2',
      decision: 'approve',
      signatureBase64: signDeviceAnswer({
        privateKeyPem: kp.privateKey,
        requestHash: p.hash,
        nonce: p.nonce,
        decision: 'approve',
      }),
    }),
    true,
  );
  assert.equal(await promise, true);
  assert.deepEqual(store.recentAudit()[0]?.resolution, {
    type: 'approved-by-device',
    deviceId: 'device:phone-a1b2',
  });
});

test('a revoked device cannot approve even with a valid signature', async () => {
  const ROOT = process.platform === 'win32' ? 'C:\\work' : '/work';
  const kp = generateDeviceKeypair();
  const store = new SqliteStore(new DatabaseSync(':memory:') as unknown as Db);
  store.pairDevice({
    id: 'device:old',
    label: 'Old phone',
    publicKey: kp.publicKey,
    pairedAt: new Date().toISOString(),
  });
  store.revokeDevice('device:old');

  let presented: PresentedRequest | null = null;
  const gate = new Gate(
    { enabled: true, rulesEnabled: false, devicesEnabled: true, workspaceRoot: ROOT, timeoutMs: 120 },
    {
      audit: { append: (r) => store.appendAudit(r) },
      rules: { list: () => [], recordMatch: () => {} },
      present: (p) => {
        presented = p;
      },
      listDevices: () => store.listDevices(),
      pushToDevices: () => {},
    },
  );

  const req: GateRequest = {
    id: 'req-2',
    kind: 'shell',
    command: 'npm run build',
    cwd: ROOT,
    originator: { id: 'client:cli', label: 'CLI' },
    requestedAt: new Date().toISOString(),
  };
  const promise = gate.request(req);
  const p = presented as unknown as PresentedRequest;

  assert.equal(
    gate.respondDevice({
      requestId: req.id,
      deviceId: 'device:old',
      decision: 'approve',
      signatureBase64: signDeviceAnswer({
        privateKeyPem: kp.privateKey,
        requestHash: p.hash,
        nonce: p.nonce,
        decision: 'approve',
      }),
    }),
    false,
  );
  assert.equal(await promise, false);
});

test('one device cannot sign for another', () => {
  const a = generateDeviceKeypair();
  const b = generateDeviceKeypair();
  const signatureBase64 = signDeviceAnswer({
    privateKeyPem: a.privateKey,
    requestHash: 'b'.repeat(64),
    nonce: 'n',
    decision: 'approve',
  });
  assert.equal(
    verifyDeviceSignature({
      publicKeyBase64: b.publicKey,
      requestHash: 'b'.repeat(64),
      nonce: 'n',
      decision: 'approve',
      signatureBase64,
    }),
    false,
  );
});
