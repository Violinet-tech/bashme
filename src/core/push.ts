// push.ts — the "ding" itself: a Web Push ping to a paired device, so a phone
// or iPad that is not holding the LAN/relay poll open still gets notified.
//
// Deliberately payload-free. RFC 8291 message encryption (ECDH + HKDF +
// aes128gcm) is a real amount of code for a notification whose entire job is
// "open the app" -- so this sends an EMPTY push body. The service worker shows
// a generic "bashme: new approval request" notification on any push event,
// with no content to decrypt and nothing sensitive in transit. The actual
// command text still only ever travels over the signed LAN/relay channel.
//
// VAPID (RFC 8292) is still required -- it is how the push service (Apple's,
// Google's, Mozilla's) knows this server is the one the subscription was
// issued to, and it costs only a signed JWT, not payload crypto.

import crypto from 'node:crypto';

export interface VapidKeys {
  /** Uncompressed P-256 point, base64url. Handed to PushManager.subscribe. */
  publicKey: string;
  /** PKCS8 PEM. Never leaves this machine. */
  privateKeyPem: string;
}

const b64url = (buf: Buffer): string =>
  buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

/** One VAPID identity per install, generated once and stored (see store.ts). */
export function generateVapidKeys(): VapidKeys {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  // The uncompressed point is what PushManager.subscribe's applicationServerKey
  // wants: 0x04 || X || Y, 65 bytes.
  const jwk = publicKey.export({ format: 'jwk' }) as { x: string; y: string };
  const x = Buffer.from(jwk.x.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  const y = Buffer.from(jwk.y.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  const point = Buffer.concat([Buffer.from([0x04]), x, y]);
  return {
    publicKey: b64url(point),
    privateKeyPem: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
  };
}

/** ES256 JWT, raw r||s signature (not DER) -- what the Push API's VAPID header needs. */
function signVapidJwt(audience: string, subject: string, privateKeyPem: string): string {
  const header = b64url(Buffer.from(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const now = Math.floor(Date.now() / 1000);
  const claims = b64url(
    Buffer.from(JSON.stringify({ aud: audience, exp: now + 12 * 60 * 60, sub: subject })),
  );
  const signingInput = `${header}.${claims}`;
  const key = crypto.createPrivateKey(privateKeyPem);
  const signature = crypto.sign('sha256', Buffer.from(signingInput), {
    key,
    dsaEncoding: 'ieee-p1363', // fixed-length r||s, what JWS ES256 requires
  });
  return `${signingInput}.${b64url(signature)}`;
}

export interface PushSubscription {
  endpoint: string;
}

/**
 * Fire one empty push at a subscribed endpoint.
 *
 * Best-effort: a dead subscription (uninstalled PWA, revoked permission)
 * fails here and must never be allowed to affect the gate's decision, so
 * callers always wrap this and swallow the error. A 404/410 from the push
 * service means "this subscription is gone" -- returned so a caller can drop
 * it, not thrown.
 */
export async function sendPushPing(
  subscription: PushSubscription,
  vapid: VapidKeys,
  subject: string,
): Promise<{ ok: boolean; gone: boolean }> {
  const endpointUrl = new URL(subscription.endpoint);
  const audience = `${endpointUrl.protocol}//${endpointUrl.host}`;
  const jwt = signVapidJwt(audience, subject, vapid.privateKeyPem);

  const res = await fetch(subscription.endpoint, {
    method: 'POST',
    headers: {
      Authorization: `vapid t=${jwt}, k=${vapid.publicKey}`,
      TTL: '86400',
      'content-length': '0',
    },
  });
  return { ok: res.ok, gone: res.status === 404 || res.status === 410 };
}
