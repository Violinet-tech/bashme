// lanServer.ts — approvals on a phone, over the local network.
//
// READ THIS BEFORE CHANGING ANYTHING HERE.
//
// This is the one listening socket in the project, and it exists against a
// standing rule. violet-dev's SECURITY.md records four RCE paths that existed
// because that app had an HTTP surface, all deleted rather than patched, and
// core/channel.ts pre-commits transports to outbound-only for that reason.
//
// It is here anyway because the rule and the goal are not simultaneously
// satisfiable: a phone browser cannot accept an inbound connection, so
// "outbound-only" and "approve from a phone with no app installed" cannot both
// hold. The user was told this and chose the phone.
//
// What keeps that from re-opening the old hole:
//
//   * It lives in the STANDALONE APP ONLY. core/ never imports it, so VIOLINET OS
//     — which is what SECURITY.md actually governs — still has no listener.
//   * Off unless explicitly switched on, and it binds to ONE chosen address,
//     never 0.0.0.0. Nothing starts listening as a side effect of anything.
//   * The socket is not a trust boundary and grants nothing. Every approval is
//     an Ed25519 signature over hash|nonce|decision, verified by confirm.ts
//     exactly as it would be from any other transport. Reaching the port lets
//     you ASK; only a paired key can ANSWER.
//   * Enrollment needs a code shown on the PC screen, valid briefly, one use.
//     Being on the subnet is not enough — "a LAN is not a trust boundary" is
//     SECURITY.md's own phrasing and it still holds.
//   * Bodies are capped and unauthenticated requests are rate-limited, because
//     the cheapest attack on a listener is not a clever one.
//
// The TLS certificate is not an identity — see selfSignedCert.ts. It buys a
// secure context so the phone can use WebCrypto, and a fingerprint to compare.

import { createServer, type Server } from 'node:https';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { networkInterfaces } from 'node:os';
import crypto from 'node:crypto';
import type { ApprovalTransport, DeviceAnswer } from '../core/channel.ts';
import type { PresentedRequest } from '../core/gate.ts';
import type { PairedDevice } from '../core/types.ts';
import { issueSelfSigned, type SelfSigned } from './selfSignedCert.ts';
import { PHONE_PAGE } from './phonePage.ts';
import { MANIFEST_JSON, SW_JS } from './pwaAssets.ts';
import { encodeQr, type QrMatrix } from './qr.ts';

const MAX_BODY_BYTES = 64 * 1024;
const ENROLL_CODE_TTL_MS = 5 * 60 * 1000;
const RATE_WINDOW_MS = 60 * 1000;
const RATE_MAX_UNAUTHENTICATED = 30;

export interface LanAddress {
  address: string;
  label: string;
}

/** Every IPv4 address on this machine that a phone could plausibly reach. */
export function lanAddresses(): LanAddress[] {
  const out: LanAddress[] = [];
  for (const [name, entries] of Object.entries(networkInterfaces())) {
    for (const entry of entries ?? []) {
      if (entry.family !== 'IPv4' || entry.internal) continue;
      // Tailscale's own adapter (matched by NAME: a Wi-Fi adapter on a CGNAT network can hold 100.64/10 too): private to the owner's devices, works away from home.
      const tailnet = /tailscale/i.test(name) && /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(entry.address);
      out.push({ address: entry.address, label: tailnet ? 'Tailscale (anywhere, only your own devices)' : name });
    }
  }
  return out.sort((a, b) => Number(b.label.startsWith('Tailscale')) - Number(a.label.startsWith('Tailscale')));
}

export interface LanStatus {
  running: boolean;
  address: string | null;
  port: number | null;
  url: string | null;
  certFingerprint: string | null;
  enrollCode: string | null;
  enrollExpiresAt: string | null;
  /** The URL with the code already in it, so the phone need not be typed at. */
  enrollUrl: string | null;
  /** The same URL as a scannable matrix. Null when there is nothing to scan. */
  enrollQr: QrMatrix | null;
  available: LanAddress[];
}

export interface LanServerDeps {
  /** Paired devices, for verifying which key may answer. */
  listDevices(): PairedDevice[];
  /** Store a newly enrolled phone. Returns the device id. */
  pairDevice(label: string, publicKeyBase64: string): { ok: boolean; id?: string; error?: string };
  /** The VAPID public key the phone's PushManager.subscribe needs. */
  vapidPublicKey(): string;
  /** Record the endpoint a paired device's service worker subscribed with. */
  setPushEndpoint(deviceId: string, endpoint: string): void;
}

interface Enrollment {
  code: string;
  expiresAt: number;
}

export class LanServer implements ApprovalTransport {
  readonly id = 'lan';
  readonly label = 'Local network (paired devices only)';

  #server: Server | null = null;
  #cert: SelfSigned | null = null;
  #address: string | null = null;
  #port: number | null = null;
  #enrollment: Enrollment | null = null;
  #handler: ((answer: DeviceAnswer) => void) | null = null;
  #deps: LanServerDeps;

  // Presented requests the gate has pushed, keyed by request id. The phone polls
  // this rather than being pushed to, because a phone browser cannot be pushed
  // to without a connection it holds open — and a poll that returns nothing is
  // the correct behaviour when there is nothing to approve.
  #pending = new Map<string, PresentedRequest>();
  #hits = new Map<string, { count: number; resetAt: number }>();

  constructor(deps: LanServerDeps) {
    this.#deps = deps;
  }

  isAvailable(): boolean {
    return this.#server !== null;
  }

  status(): LanStatus {
    const url = this.#address && this.#port ? `https://${this.#address}:${this.#port}/` : null;
    const live = this.#enrollment !== null && this.#enrollment.expiresAt > Date.now();
    const code = live ? this.#enrollment!.code : null;

    // The QR carries the code because the code is the slow, error-prone part --
    // but it is still shown as digits underneath. A camera that will not focus,
    // a cracked screen or a phone with no scanner must not be a dead end.
    const enrollUrl = url && code ? `${url}?code=${code}` : null;

    return {
      running: this.#server !== null,
      address: this.#address,
      port: this.#port,
      url,
      certFingerprint: this.#cert?.fingerprint ?? null,
      enrollCode: code,
      enrollExpiresAt: live ? new Date(this.#enrollment!.expiresAt).toISOString() : null,
      enrollUrl,
      enrollQr: enrollUrl ? encodeQr(enrollUrl) : null,
      available: lanAddresses(),
    };
  }

  /**
   * Start listening on one address.
   *
   * Rejects an address this machine does not actually hold, so a typo cannot
   * become a wildcard bind.
   */
  async start(address: string, port = 8787): Promise<LanStatus> {
    if (this.#server) await this.stopAsync();

    const known = lanAddresses().some((a) => a.address === address);
    if (!known && address !== '127.0.0.1') {
      throw new Error(`${address} is not an address on this machine`);
    }

    // 127.0.0.1 is included so the certificate still works when testing from
    // this machine; it is not what the phone connects to.
    this.#cert = issueSelfSigned([address, '127.0.0.1', 'localhost']);

    const server = createServer(
      { cert: this.#cert.cert, key: this.#cert.key },
      (req, res) => void this.#route(req, res),
    );

    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, address, () => {
        server.removeListener('error', reject);
        resolve();
      });
    });

    this.#server = server;
    this.#address = address;
    this.#port = port;
    return this.status();
  }

  /** Open a one-use enrollment window. The code is shown on the PC, typed on the phone. */
  openEnrollment(): { code: string; expiresAt: string } {
    // Six digits from rejection-free randomness. Short enough to type on a
    // phone, and it only has to survive five minutes against a rate-limited
    // endpoint.
    const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
    const expiresAt = Date.now() + ENROLL_CODE_TTL_MS;
    this.#enrollment = { code, expiresAt };
    return { code, expiresAt: new Date(expiresAt).toISOString() };
  }

  closeEnrollment(): void {
    this.#enrollment = null;
  }

  push(presented: PresentedRequest): void {
    this.#pending.set(presented.request.id, presented);
  }

  /** The gate settled this elsewhere; stop offering it to the phone. */
  withdraw(requestId: string): void {
    this.#pending.delete(requestId);
  }

  onAnswer(handler: (answer: DeviceAnswer) => void): void {
    this.#handler = handler;
  }

  stop(): void {
    void this.stopAsync();
  }

  async stopAsync(): Promise<void> {
    const server = this.#server;
    this.#server = null;
    this.#address = null;
    this.#port = null;
    this.#cert = null;
    this.#enrollment = null;
    this.#pending.clear();
    if (server) await new Promise<void>((resolve) => server.close(() => resolve()));
  }

  // --- request handling -----------------------------------------------------

  #rateLimited(req: IncomingMessage): boolean {
    const key = req.socket.remoteAddress ?? 'unknown';
    const now = Date.now();
    const entry = this.#hits.get(key);
    if (!entry || entry.resetAt < now) {
      this.#hits.set(key, { count: 1, resetAt: now + RATE_WINDOW_MS });
      return false;
    }
    entry.count += 1;
    return entry.count > RATE_MAX_UNAUTHENTICATED;
  }

  async #body(req: IncomingMessage): Promise<unknown> {
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of req) {
      size += (chunk as Buffer).length;
      // Cap while reading, not after: the point is to never hold an oversized
      // body in memory at all.
      if (size > MAX_BODY_BYTES) throw new Error('body too large');
      chunks.push(chunk as Buffer);
    }
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  }

  async #route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const send = (status: number, body: unknown, type = 'application/json'): void => {
      const text = type === 'application/json' ? JSON.stringify(body) : String(body);
      res.writeHead(status, {
        'content-type': type === 'application/json' ? 'application/json; charset=utf-8' : type,
        'cache-control': 'no-store',
        // This page talks only to its own origin; nothing embeds it, nothing
        // else may read it.
        'content-security-policy':
          "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'",
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer',
      });
      res.end(text);
    };

    try {
      if (this.#rateLimited(req)) {
        send(429, { error: 'too many requests' });
        return;
      }

      const url = new URL(req.url ?? '/', 'https://bashme.local');
      const path = url.pathname;

      if (req.method === 'GET' && (path === '/' || path === '/index.html')) {
        send(200, PHONE_PAGE, 'text/html; charset=utf-8');
        return;
      }

      if (req.method === 'GET' && path === '/manifest.webmanifest') {
        send(200, MANIFEST_JSON, 'application/manifest+json; charset=utf-8');
        return;
      }

      if (req.method === 'GET' && path === '/sw.js') {
        send(200, SW_JS, 'text/javascript; charset=utf-8');
        return;
      }

      if (req.method === 'GET' && path === '/api/vapid-key') {
        send(200, { key: this.#deps.vapidPublicKey() });
        return;
      }

      if (req.method === 'POST' && path === '/api/enroll') {
        send(200, this.#enroll(await this.#body(req)));
        return;
      }

      if (req.method === 'POST' && path === '/api/subscribe') {
        send(200, this.#subscribe(await this.#body(req)));
        return;
      }

      if (req.method === 'GET' && path === '/api/pending') {
        send(200, this.#listForDevice(url.searchParams.get('deviceId')));
        return;
      }

      if (req.method === 'POST' && path === '/api/answer') {
        send(200, this.#answer(await this.#body(req)));
        return;
      }

      send(404, { error: 'not found' });
    } catch (err) {
      // Never leak internals to an unauthenticated caller.
      send(400, { error: err instanceof Error && err.message === 'body too large' ? err.message : 'bad request' });
    }
  }

  #enroll(body: unknown): { ok: boolean; deviceId?: string; vapidKey?: string; error?: string } {
    const input = body as { code?: unknown; label?: unknown; publicKey?: unknown };
    const enrollment = this.#enrollment;
    if (!enrollment || enrollment.expiresAt < Date.now()) {
      return { ok: false, error: 'No enrollment is open. Start one on the PC.' };
    }

    const given = String(input.code ?? '');
    const expected = enrollment.code;
    // Constant-time, and length-checked first so the comparison never throws.
    const match =
      given.length === expected.length &&
      crypto.timingSafeEqual(Buffer.from(given), Buffer.from(expected));
    if (!match) return { ok: false, error: 'That code is not right.' };

    const publicKey = String(input.publicKey ?? '');
    const label = String(input.label ?? 'Phone').slice(0, 60);
    const paired = this.#deps.pairDevice(label, publicKey);
    if (!paired.ok) return { ok: false, error: paired.error ?? 'Pairing failed.' };

    // One use. A code that keeps working is a code that leaks.
    this.#enrollment = null;
    return { ok: true, deviceId: paired.id!, vapidKey: this.#deps.vapidPublicKey() };
  }

  #subscribe(body: unknown): { ok: boolean; error?: string } {
    const input = body as { deviceId?: unknown; endpoint?: unknown };
    const deviceId = String(input.deviceId ?? '');
    const device = this.#deps.listDevices().find((d) => d.id === deviceId && !d.revokedAt);
    if (!device) return { ok: false, error: 'Not a paired device.' };
    const endpoint = String(input.endpoint ?? '');
    if (!/^https:\/\//.test(endpoint)) return { ok: false, error: 'Not a push endpoint.' };
    this.#deps.setPushEndpoint(deviceId, endpoint);
    return { ok: true };
  }

  #listForDevice(deviceId: string | null): { requests: unknown[] } {
    // Only a paired, unrevoked device is told anything at all — the command
    // text itself is sensitive, so an unknown caller gets an empty list rather
    // than an error that would confirm what exists.
    const device = this.#deps.listDevices().find((d) => d.id === deviceId && !d.revokedAt);
    if (!device) return { requests: [] };

    return {
      requests: [...this.#pending.values()].map((p) => ({
        id: p.request.id,
        kind: p.request.kind,
        command: p.request.command,
        cwd: p.request.cwd,
        summary: p.request.summary ?? null,
        originator: p.request.originator.label,
        hardBlocked: p.verdict.hardBlocked,
        reasons: p.verdict.reasons,
        expiresAt: p.expiresAt,
        // The phone signs over these two; they are not secrets.
        hash: p.hash,
        nonce: p.nonce,
      })),
    };
  }

  #answer(body: unknown): { ok: boolean; error?: string } {
    const input = body as {
      requestId?: unknown;
      deviceId?: unknown;
      decision?: unknown;
      signature?: unknown;
    };
    const decision = input.decision === 'approve' ? 'approve' : 'deny';
    const handler = this.#handler;
    if (!handler) return { ok: false, error: 'not accepting answers' };

    // Everything that decides whether this counts happens in the gate's
    // signature check. This only forwards.
    handler({
      requestId: String(input.requestId ?? ''),
      deviceId: String(input.deviceId ?? ''),
      decision,
      signatureBase64: String(input.signature ?? ''),
    });
    this.#pending.delete(String(input.requestId ?? ''));
    return { ok: true };
  }
}
