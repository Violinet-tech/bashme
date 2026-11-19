// selfSignedCert.ts — generate a self-signed TLS certificate, no dependencies.
//
// WHY THIS EXISTS AT ALL: the phone generates its own Ed25519 keypair in the
// browser, via WebCrypto. Browsers only expose `crypto.subtle` in a secure
// context, and a plain http:// page on a LAN address is not one. So the LAN
// listener has to speak TLS, which means it needs a certificate, and there is
// no certificate authority that will issue one for 192.168.x.x.
//
// Node can PARSE X.509 (crypto.X509Certificate) but cannot issue one, and this
// package deliberately has zero runtime dependencies — so the DER is written by
// hand here rather than pulling in node-forge for one call.
//
// WHAT THIS CERTIFICATE IS AND IS NOT: it is not an identity. Nothing verifies
// it, the phone will show a warning, and the user clicks through. Its only jobs
// are (1) making the browser treat the page as a secure context so WebCrypto
// works, and (2) giving the connection a stable fingerprint the user can
// compare against what the app displays — trust on first use, the same check
// pairing already asks for with the device key.
//
// It is emphatically NOT what makes an approval trustworthy. That remains the
// Ed25519 signature checked in confirm.ts, which is verified on whatever
// arrives regardless of how it got here.

import crypto from 'node:crypto';

// --- minimal DER writer -----------------------------------------------------
//
// DER is tag-length-value. Only the handful of types an X.509 certificate needs
// are here; anything else is out of scope on purpose.

function len(n: number): Buffer {
  // Short form below 128, long form above: one byte giving the byte-count of
  // the length, then the length itself big-endian.
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag: number, value: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), len(value.length), value]);
}

const seq = (...parts: Buffer[]): Buffer => tlv(0x30, Buffer.concat(parts));
const set = (...parts: Buffer[]): Buffer => tlv(0x31, Buffer.concat(parts));

function integer(value: Buffer | number): Buffer {
  if (typeof value === 'number') return tlv(0x02, Buffer.from([value]));
  // A leading bit of 1 would read as negative, so pad with a zero byte.
  const padded = value[0]! & 0x80 ? Buffer.concat([Buffer.from([0]), value]) : value;
  return tlv(0x02, padded);
}

function bitString(value: Buffer): Buffer {
  // The leading 0 is the count of unused bits in the final byte; always 0 here.
  return tlv(0x03, Buffer.concat([Buffer.from([0]), value]));
}

function oid(dotted: string): Buffer {
  const parts = dotted.split('.').map(Number);
  // The first two arcs share one byte, then each arc is base-128, high bit set
  // on every byte but the last.
  const body: number[] = [parts[0]! * 40 + parts[1]!];
  for (const part of parts.slice(2)) {
    const chunk: number[] = [part & 0x7f];
    let v = part >> 7;
    while (v > 0) {
      chunk.unshift((v & 0x7f) | 0x80);
      v >>= 7;
    }
    body.push(...chunk);
  }
  return tlv(0x06, Buffer.from(body));
}

const utf8 = (text: string): Buffer => tlv(0x0c, Buffer.from(text, 'utf8'));

function utcTime(date: Date): Buffer {
  const pad = (n: number): string => String(n).padStart(2, '0');
  const text =
    pad(date.getUTCFullYear() % 100) +
    pad(date.getUTCMonth() + 1) +
    pad(date.getUTCDate()) +
    pad(date.getUTCHours()) +
    pad(date.getUTCMinutes()) +
    pad(date.getUTCSeconds()) +
    'Z';
  return tlv(0x17, Buffer.from(text, 'ascii'));
}

const context = (n: number, value: Buffer): Buffer => tlv(0xa0 | n, value);

// --- certificate ------------------------------------------------------------

const OID_COMMON_NAME = '2.5.4.3';
const OID_ECDSA_SHA256 = '1.2.840.10045.4.3.2';
const OID_SAN = '2.5.29.17';
const OID_BASIC_CONSTRAINTS = '2.5.29.19';
const OID_KEY_USAGE = '2.5.29.15';
const OID_EXT_KEY_USAGE = '2.5.29.37';
const OID_SERVER_AUTH = '1.3.6.1.5.5.7.3.1';

export interface SelfSigned {
  /** PEM certificate, for https.createServer({ cert }). */
  cert: string;
  /** PEM private key, for https.createServer({ key }). */
  key: string;
  /** SHA-256 of the DER, grouped for reading aloud. This is what to compare. */
  fingerprint: string;
  expiresAt: string;
}

/**
 * Issue a self-signed certificate covering the given addresses.
 *
 * ECDSA P-256 rather than Ed25519: browsers do not accept Ed25519 in TLS
 * certificates yet, and a certificate no browser will load defeats the whole
 * point of having one.
 *
 * Every address the phone might type has to appear in subjectAltName — modern
 * browsers ignore commonName entirely, so an omitted address fails to load
 * rather than merely warning.
 */
export function issueSelfSigned(addresses: string[], days = 365): SelfSigned {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
  });

  const spki = publicKey.export({ format: 'der', type: 'spki' }) as Buffer;

  const notBefore = new Date(Date.now() - 60 * 60 * 1000); // clock skew
  const notAfter = new Date(Date.now() + days * 24 * 60 * 60 * 1000);

  const name = seq(set(seq(oid(OID_COMMON_NAME), utf8('bashme'))));
  const algorithm = seq(oid(OID_ECDSA_SHA256));

  // SAN entry types: dNSName is context tag 2, iPAddress is tag 7 carrying the
  // raw 4 octets rather than the dotted text.
  const sanEntries = addresses.map((address) => {
    const octets = address.split('.').map(Number);
    const isIPv4 = octets.length === 4 && octets.every((n) => Number.isInteger(n) && n >= 0 && n <= 255);
    return isIPv4
      ? tlv(0x87, Buffer.from(octets))
      : tlv(0x82, Buffer.from(address, 'ascii'));
  });

  const extensions = context(
    3,
    seq(
      // CA:FALSE — this certificate signs nothing but itself.
      seq(oid(OID_BASIC_CONSTRAINTS), tlv(0x01, Buffer.from([0xff])), tlv(0x04, seq())),
      seq(oid(OID_KEY_USAGE), tlv(0x01, Buffer.from([0xff])), tlv(0x04, bitString(Buffer.from([0xa0])))),
      seq(oid(OID_EXT_KEY_USAGE), tlv(0x04, seq(oid(OID_SERVER_AUTH)))),
      seq(oid(OID_SAN), tlv(0x04, seq(...sanEntries))),
    ),
  );

  const tbs = seq(
    context(0, integer(2)), // v3
    integer(crypto.randomBytes(16)),
    algorithm,
    name,
    seq(utcTime(notBefore), utcTime(notAfter)),
    name,
    spki,
    extensions,
  );

  const signature = crypto.sign('sha256', tbs, privateKey);
  const der = seq(tbs, algorithm, bitString(signature));

  const pem = (label: string, body: Buffer): string =>
    `-----BEGIN ${label}-----\n${
      body.toString('base64').replace(/(.{64})/g, '$1\n').replace(/\n$/, '')
    }\n-----END ${label}-----\n`;

  const digest = crypto.createHash('sha256').update(der).digest('hex').toUpperCase();

  return {
    cert: pem('CERTIFICATE', der),
    key: privateKey.export({ format: 'pem', type: 'pkcs8' }) as string,
    fingerprint: (digest.match(/.{4}/g) ?? []).slice(0, 8).join('-'),
    expiresAt: notAfter.toISOString(),
  };
}
