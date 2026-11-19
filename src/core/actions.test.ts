// actions.test.ts
//
// The tests that matter here are the refusals. An action that runs is easy;
// what this file is really asserting is that the phone cannot name anything
// the owner did not write down, cannot spend a nonce twice, and cannot carry
// a signature across from the approval scheme.

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { ActionService, parseActions, verifyActionSignature } from './actions.ts';
import type { ActionDef } from './actions.ts';
import type { PairedDevice } from './types.ts';

function newDevice(id = 'device-1'): { device: PairedDevice; sign: (msg: string) => string } {
  const pair = crypto.generateKeyPairSync('ed25519');
  const publicKey = pair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
  return {
    device: { id, label: 'Phone', publicKey, pairedAt: new Date().toISOString() },
    sign: (msg) => crypto.sign(null, Buffer.from(msg), pair.privateKey).toString('base64'),
  };
}

const DEFS: ActionDef[] = [{ id: 'netfix', label: 'Fix the network', command: 'echo fixed' }];

function harness(defs = DEFS, device = newDevice()) {
  const ran: string[] = [];
  const audited: Array<{ actionId: string; ok: boolean }> = [];
  const service = new ActionService(
    {
      devices: () => [device.device],
      run: async (a) => {
        ran.push(a.id);
        return { ok: true, output: 'ok' };
      },
      audit: (e) => audited.push({ actionId: e.actionId, ok: e.ok }),
    },
    defs,
  );
  return { service, ran, audited, device };
}

test('a signed action from a paired device runs', async () => {
  const h = harness();
  const { nonce } = h.service.offer();
  const res = await h.service.invoke({
    actionId: 'netfix',
    deviceId: 'device-1',
    nonce,
    signatureBase64: h.device.sign(`action|netfix|${nonce}`),
  });
  assert.equal(res.ok, true);
  assert.deepEqual(h.ran, ['netfix']);
});

test('the offer carries no command, only a label', () => {
  const { service } = harness([{ id: 'netfix', label: 'Fix the network', command: 'rm -rf /' }]);
  const offer = service.offer();
  assert.deepEqual(Object.keys(offer.actions[0]!).sort(), ['description', 'id', 'label']);
  assert.doesNotMatch(JSON.stringify(offer), /rm -rf/);
});

test('a nonce is spendable exactly once', async () => {
  const h = harness();
  const { nonce } = h.service.offer();
  const sig = h.device.sign(`action|netfix|${nonce}`);
  const first = await h.service.invoke({ actionId: 'netfix', deviceId: 'device-1', nonce, signatureBase64: sig });
  const replay = await h.service.invoke({ actionId: 'netfix', deviceId: 'device-1', nonce, signatureBase64: sig });
  assert.equal(first.ok, true);
  assert.equal(replay.ok, false);
  assert.deepEqual(h.ran, ['netfix'], 'the replay must not have run anything');
});

test('an unknown action id runs nothing and says nothing useful', async () => {
  const h = harness();
  const { nonce } = h.service.offer();
  const res = await h.service.invoke({
    actionId: 'not-a-real-action',
    deviceId: 'device-1',
    nonce,
    signatureBase64: h.device.sign(`action|not-a-real-action|${nonce}`),
  });
  assert.equal(res.ok, false);
  assert.deepEqual(h.ran, []);
  // Identical to the bad-signature message, so the list cannot be enumerated.
  assert.equal(res.error, 'that action is not available');
});

test('a wrong signature runs nothing', async () => {
  const h = harness();
  const other = newDevice('device-1');
  const { nonce } = h.service.offer();
  const res = await h.service.invoke({
    actionId: 'netfix',
    deviceId: 'device-1',
    nonce,
    signatureBase64: other.sign(`action|netfix|${nonce}`),
  });
  assert.equal(res.ok, false);
  assert.deepEqual(h.ran, []);
});

test('a revoked device runs nothing', async () => {
  const device = newDevice();
  const h = harness(DEFS, device);
  device.device.revokedAt = new Date().toISOString();
  const { nonce } = h.service.offer();
  const res = await h.service.invoke({
    actionId: 'netfix',
    deviceId: 'device-1',
    nonce,
    signatureBase64: device.sign(`action|netfix|${nonce}`),
  });
  assert.equal(res.ok, false);
  assert.deepEqual(h.ran, []);
});

test('an approval signature cannot be presented as an action', () => {
  // Both schemes sign three pipe-separated fields. The `action|` prefix is the
  // only thing keeping them apart, so this asserts the prefix is load-bearing.
  const { device, sign } = newDevice();
  const forged = sign('netfix|some-nonce|approve');
  assert.equal(
    verifyActionSignature({
      publicKeyBase64: device.publicKey,
      actionId: 'netfix',
      nonce: 'some-nonce',
      signatureBase64: forged,
    }),
    false,
  );
});

test('every attempt is audited, refusals included', async () => {
  const h = harness();
  const { nonce } = h.service.offer();
  await h.service.invoke({ actionId: 'netfix', deviceId: 'device-1', nonce, signatureBase64: 'not-a-signature' });
  assert.deepEqual(h.audited, [{ actionId: 'netfix', ok: false }]);
});

test('parseActions drops what it cannot understand and says why', () => {
  const { actions, errors } = parseActions({
    actions: [
      { id: 'good', label: 'Good', command: 'echo hi' },
      { id: 'UPPER', label: 'Bad id', command: 'echo hi' },
      { id: 'good', label: 'Duplicate', command: 'echo hi' },
      { id: 'no-command', label: 'Missing' },
    ],
  });
  assert.deepEqual(actions.map((a) => a.id), ['good']);
  assert.equal(errors.length, 3);
});

test('a bare array is accepted, anything else is an error not a crash', () => {
  assert.equal(parseActions([{ id: 'a', label: 'A', command: 'echo' }]).actions.length, 1);
  assert.equal(parseActions('nope').errors.length, 1);
  assert.equal(parseActions(null).errors.length, 1);
});
