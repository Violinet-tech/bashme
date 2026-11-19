// devices.ts — pairing an approving device, and the fingerprint that makes it
// checkable by a human.
//
// Pairing is key establishment only. It needs no transport: a public key is not
// secret, so it can be carried by hand, and the outbound channel that later
// delivers requests is a separate concern (core/channel.ts).
//
// The risk in a paste-based pairing is not eavesdropping, it is pasting the
// WRONG key -- an attacker's. So every key gets a short fingerprint that is
// displayed on both sides and compared by a person, the same reason SSH prints
// a host fingerprint. Without that comparison the pairing step proves nothing.

import crypto from 'node:crypto';

export interface ParsedDeviceKey {
  /** Normalised SPKI DER, base64. Stored, and what signatures verify against. */
  publicKey: string;
  fingerprint: string;
}

/**
 * Group into 4-char blocks.
 *
 * Read aloud or compared across a room, unbroken hex is where transposition
 * errors hide -- and a fingerprint nobody actually compares is decoration.
 */
function groupHex(hex: string): string {
  return (hex.toUpperCase().match(/.{1,4}/g) ?? []).join(' ');
}

/** 64 bits of SHA-256 over the DER. Short enough to compare, long enough to matter. */
export function fingerprintFromDer(der: Buffer): string {
  return groupHex(crypto.createHash('sha256').update(der).digest('hex').slice(0, 16));
}

/**
 * Validate a pasted public key.
 *
 * Rejects rather than coerces. A key that is not Ed25519 would be stored, look
 * paired, and then fail every signature check -- a device that appears enrolled
 * but can never approve is worse than a refusal at paste time.
 */
export function parseDeviceKey(input: string): { ok: true; value: ParsedDeviceKey } | { ok: false; error: string } {
  const cleaned = String(input ?? '')
    .trim()
    .replace(/-----(BEGIN|END) PUBLIC KEY-----/g, '')
    .replace(/\s+/g, '');
  if (!cleaned) return { ok: false, error: 'Paste the public key the device showed you.' };

  let der: Buffer;
  try {
    der = Buffer.from(cleaned, 'base64');
  } catch {
    return { ok: false, error: 'That is not valid base64.' };
  }
  if (der.length === 0) return { ok: false, error: 'That is not valid base64.' };

  let key: crypto.KeyObject;
  try {
    key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
  } catch {
    return { ok: false, error: 'That is not a public key in SPKI form.' };
  }
  if (key.asymmetricKeyType !== 'ed25519') {
    return {
      ok: false,
      error: `Key is ${key.asymmetricKeyType ?? 'of an unknown type'}, but approvals are signed with Ed25519.`,
    };
  }

  // Re-export rather than trusting the input bytes, so two encodings of the
  // same key cannot become two rows that look like two devices.
  const normalised = key.export({ format: 'der', type: 'spki' });
  return {
    ok: true,
    value: { publicKey: normalised.toString('base64'), fingerprint: fingerprintFromDer(normalised) },
  };
}

/** Fingerprint of an already-stored key. Returns null if the row is unreadable. */
export function fingerprintOf(publicKeyBase64: string): string | null {
  const parsed = parseDeviceKey(publicKeyBase64);
  return parsed.ok ? parsed.value.fingerprint : null;
}

/** Generate a device identity. The private key never leaves the device. */
export function generateDeviceKeypair(): {
  publicKey: string;
  privateKey: string;
  fingerprint: string;
} {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const der = publicKey.export({ format: 'der', type: 'spki' });
  return {
    publicKey: der.toString('base64'),
    privateKey: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    fingerprint: fingerprintFromDer(der),
  };
}

/** Sign one approval on the device side. Mirrors verifyDeviceSignature. */
export function signDeviceAnswer(args: {
  privateKeyPem: string;
  requestHash: string;
  nonce: string;
  decision: 'approve' | 'deny';
}): string {
  const key = crypto.createPrivateKey(args.privateKeyPem);
  return crypto
    .sign(null, Buffer.from(`${args.requestHash}|${args.nonce}|${args.decision}`), key)
    .toString('base64');
}
