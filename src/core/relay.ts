// relay.ts — approvals on a phone that cannot see this machine.
//
// WHY THIS EXISTS WHEN lanServer.ts ALREADY WORKS
//
// It works on a network where the two devices can reach each other. This one
// cannot: the apartment's internet is behind CGNAT, the access point isolates
// clients from one another, and the user cannot change a router setting. The
// phone and the PC are two metres apart and have no path between them.
//
// So neither end waits for a connection. Both dial OUT to a forwarder, post to
// the other's mailbox and poll their own. That keeps this file inside the rule
// that lanServer.ts had to break: nothing here listens, so it belongs in core
// and VIOLINET OS can use it without gaining an inbound surface. SECURITY.md's
// "no listening inbound socket, ever" stays literally true of this path.
//
// WHAT THE RELAY IS TRUSTED WITH
//
// Bodies are AES-GCM sealed under a key generated here, handed to the phone in
// a URL FRAGMENT, and never sent to any server -- browsers do not transmit
// fragments, which is the property the whole design leans on. The forwarder
// sees a session id and opaque bytes. It cannot read a command, cannot read a
// decision, and cannot forge one: an approval is still an Ed25519 signature
// over hash|nonce|decision that confirm.ts verifies against the paired key.
//
// What it CAN do is drop messages, and that is survivable in one direction
// only: an unanswered request times out and is denied. Fail-closed is the
// default the gate already has.
//
// The caveat that is easy to skip past: the same host also serves the phone's
// page, and a host that serves your JavaScript can replace your JavaScript. A
// hostile relay could display one command and sign another. Encryption does
// not address that and neither does anything else served over the web. It is
// why relay mode is off by default, why the LAN path stays preferred whenever
// the two devices can actually see each other, and why the audit log records
// which transport answered.

// `CryptoKey` is a WebCrypto type and tsconfig's lib is ES2023, which does not
// carry the DOM globals. Node's own declaration is the right one to use here
// anyway: this runs in a main process, never in a renderer.
import type { webcrypto } from 'node:crypto';

import type { ActionService } from './actions.ts';
import type { ApprovalTransport, DeviceAnswer } from './channel.ts';
import type { PresentedRequest } from './gate.ts';
import { sanitizeStatus } from './status.ts';

/**
 * The relay Violinet Tech runs.
 *
 * LIVE as of 2026-09-29: deployed on the custom domain in
 * `bashme-relay/wrangler.toml`, D1-backed, verified answering.
 *
 * It is NOT a default, and `relayStart` must never fall back to it. The
 * security argument for relay mode is that the operator is trusted with the
 * phone's code, which only means anything if the user knowingly chose the
 * operator. So this is offered -- one tap to fill the field, clearly labelled
 * whose host it is -- and never assumed. A relay address that appeared without
 * anyone choosing it would make that paragraph a lie.
 */
export const OFFICIAL_RELAY_URL = 'https://relay.violinettech.ai';

const ENROLL_CODE_TTL_MS = 5 * 60 * 1000;
// Two seconds is the compromise the phone side also uses: fast enough that an
// approval does not feel broken, slow enough to be free. It is settable so a
// test does not have to spend real seconds waiting for a turn of the loop.
const POLL_INTERVAL_MS = 2000;
const MAX_BODY_BYTES = 64 * 1024;

/** Requests already answered, kept briefly so a duplicated delivery is a
 *  no-op rather than a second prompt. The relay may deliver twice by design:
 *  it reads before it deletes, because the other order can lose a message. */
const SETTLED_MEMORY = 200;

export interface RelaySession {
  /** Origin of the forwarder, e.g. https://bashme-relay.someone.workers.dev */
  relayUrl: string;
  /** 128 bits of hex. Public: it is the mailbox name, not a secret. */
  sessionId: string;
  /** The AES-GCM key, base64url. Secret, and never sent to the relay. */
  key: string;
}

export interface RelayStatus {
  running: boolean;
  relayUrl: string | null;
  sessionId: string | null;
  enrollCode: string | null;
  enrollExpiresAt: string | null;
  /** The whole pairing handshake as one URL, for a QR. Null when not pairing. */
  pairingUrl: string | null;
  /** Set when the last poll failed, so the UI can say so rather than look idle. */
  lastError: string | null;
}

export interface RelayDeps {
  /** Store a newly enrolled phone. Returns the device id. */
  pairDevice(label: string, publicKeyBase64: string): { ok: boolean; id?: string; error?: string };
  /** The VAPID public key the phone's PushManager.subscribe needs. Handed to
   *  it over this channel because a relay-paired phone has no origin of the
   *  PC's own to fetch it from. */
  vapidPublicKey(): string;
  /** Record the endpoint a paired device's service worker subscribed with. */
  setPushEndpoint(deviceId: string, endpoint: string): void;
  /**
   * Phone-initiated actions, if the host offers any.
   *
   * OPTIONAL on purpose. Omitting it is not a degraded mode -- it is the
   * original one, where the phone can only answer and never ask, and it stays
   * the default for any host that has not deliberately opted in. See the
   * header of actions.ts for why that distinction is the security boundary.
   */
  actions?: ActionService;
  /**
   * A read-only snapshot for the phone's status panel. OPTIONAL for the same
   * reason `actions` is: a host that does not supply it answers as if there were
   * nothing to show. The result is rebuilt by `sanitizeStatus` before it is sent,
   * so what the provider returns is a suggestion, not the wire format.
   */
  status?: () => unknown | Promise<unknown>;
}

const b64url = (bytes: Uint8Array): string =>
  Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

const hex = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');

/** Create a session. Separate from `start` so it can be persisted and reused:
 *  a phone that paired yesterday is still pointed at yesterday's mailbox. */
export function newRelaySession(relayUrl: string): RelaySession {
  return {
    relayUrl: relayUrl.replace(/\/+$/, ''),
    sessionId: hex(crypto.getRandomValues(new Uint8Array(16))),
    key: b64url(crypto.getRandomValues(new Uint8Array(32))),
  };
}

export class RelayTransport implements ApprovalTransport {
  readonly id = 'relay';
  readonly label = 'Relay (outbound only)';

  #deps: RelayDeps;
  #session: RelaySession | null = null;
  #key: webcrypto.CryptoKey | null = null;
  #timer: ReturnType<typeof setInterval> | null = null;
  #handler: ((answer: DeviceAnswer) => void) | null = null;
  #enrollment: { code: string; expiresAt: number } | null = null;
  #lastError: string | null = null;

  #pending = new Map<string, PresentedRequest>();
  #settled: string[] = [];

  constructor(deps: RelayDeps) {
    this.#deps = deps;
  }

  isAvailable(): boolean {
    return this.#timer !== null;
  }

  status(): RelayStatus {
    const live = this.#enrollment !== null && this.#enrollment.expiresAt > Date.now();
    const code = live ? this.#enrollment!.code : null;
    const s = this.#session;
    return {
      running: this.#timer !== null,
      relayUrl: s?.relayUrl ?? null,
      sessionId: s?.sessionId ?? null,
      enrollCode: code,
      enrollExpiresAt: live ? new Date(this.#enrollment!.expiresAt).toISOString() : null,
      // Everything the phone needs, in the fragment so that none of it reaches
      // the relay: the session to poll, the key to decrypt with, and the code.
      pairingUrl: s && code ? `${s.relayUrl}/p#s=${s.sessionId}&k=${s.key}&c=${code}` : null,
      lastError: this.#lastError,
    };
  }

  /** Begin polling. Resolves once the relay has answered once, so a typo in
   *  the URL is an error the user sees now rather than silence later. */
  async start(session: RelaySession, options: { pollIntervalMs?: number } = {}): Promise<RelayStatus> {
    this.stop();
    this.#session = session;
    this.#key = await crypto.subtle.importKey(
      'raw',
      Buffer.from(session.key.replace(/-/g, '+').replace(/_/g, '/'), 'base64'),
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt'],
    );

    await this.#poll({ throwOnFailure: true });
    this.#timer = setInterval(
      () => void this.#poll({ throwOnFailure: false }),
      options.pollIntervalMs ?? POLL_INTERVAL_MS,
    );
    // Node keeps the process alive for a pending timer; a background poll is
    // not a reason for the app to refuse to exit.
    this.#timer.unref?.();
    return this.status();
  }

  openEnrollment(): { code: string; expiresAt: string } {
    const code = String((crypto.getRandomValues(new Uint32Array(1))[0] ?? 0) % 1_000_000).padStart(6, '0');
    const expiresAt = Date.now() + ENROLL_CODE_TTL_MS;
    this.#enrollment = { code, expiresAt };
    return { code, expiresAt: new Date(expiresAt).toISOString() };
  }

  closeEnrollment(): void {
    this.#enrollment = null;
  }

  push(presented: PresentedRequest): void {
    this.#pending.set(presented.request.id, presented);
    void this.#send({ t: 'request', request: this.#forPhone(presented) });
  }

  /** The gate settled this elsewhere; stop offering it to the phone. */
  withdraw(requestId: string): void {
    this.#pending.delete(requestId);
    void this.#send({ t: 'withdraw', id: requestId });
  }

  onAnswer(handler: (answer: DeviceAnswer) => void): void {
    this.#handler = handler;
  }

  stop(): void {
    if (this.#timer) clearInterval(this.#timer);
    this.#timer = null;
    this.#key = null;
    this.#enrollment = null;
    this.#pending.clear();
  }

  // --- the wire -------------------------------------------------------------

  /**
   * What the phone is shown.
   *
   * Only the fields the screen needs, and the hash and nonce it has to sign.
   * A transport that forwards the whole internal object is a transport that
   * leaks whatever gets added to that object later.
   */
  #forPhone(p: PresentedRequest): Record<string, unknown> {
    return {
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
    };
  }

  async #send(message: unknown): Promise<void> {
    const session = this.#session;
    const key = this.#key;
    if (!session || !key) return;

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plain = new TextEncoder().encode(JSON.stringify(message));
    const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain));
    const body = new Uint8Array(iv.length + sealed.length);
    body.set(iv, 0);
    body.set(sealed, iv.length);
    if (body.length > MAX_BODY_BYTES) {
      this.#lastError = 'a request was too large to relay';
      return;
    }

    try {
      await fetch(`${session.relayUrl}/s/${session.sessionId}/phone`, { method: 'POST', body });
      this.#lastError = null;
    } catch (err) {
      // A failed push is not fatal: the PC dialog is still the primary
      // approver and an unanswered request denies on timeout.
      this.#lastError = err instanceof Error ? err.message : 'could not reach the relay';
    }
  }

  async #poll({ throwOnFailure }: { throwOnFailure: boolean }): Promise<void> {
    const session = this.#session;
    const key = this.#key;
    if (!session || !key) return;

    let payload: { messages?: string[] };
    try {
      const res = await fetch(`${session.relayUrl}/s/${session.sessionId}/pc`);
      if (!res.ok) throw new Error(`relay answered ${res.status}`);
      payload = (await res.json()) as { messages?: string[] };
      this.#lastError = null;
    } catch (err) {
      this.#lastError = err instanceof Error ? err.message : 'could not reach the relay';
      if (throwOnFailure) throw err;
      return;
    }

    for (const text of payload.messages ?? []) {
      let message: Record<string, unknown>;
      try {
        const raw = Buffer.from(text, 'base64');
        const plain = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: raw.subarray(0, 12) },
          key,
          raw.subarray(12),
        );
        message = JSON.parse(new TextDecoder().decode(plain)) as Record<string, unknown>;
      } catch {
        // Undecryptable means it was not written by the paired phone. The
        // relay is allowed to be hostile; this is what that looks like from
        // here, and the right response is to ignore it silently.
        continue;
      }
      await this.#handle(message);
    }
  }

  async #handle(message: Record<string, unknown>): Promise<void> {
    if (message.t === 'enroll') {
      const body = (message.body ?? {}) as Record<string, unknown>;
      const live = this.#enrollment !== null && this.#enrollment.expiresAt > Date.now();
      if (!live || String(body.code ?? '') !== this.#enrollment!.code) {
        await this.#send({ rid: message.rid, ok: false, error: 'That code is not valid. Start a new pairing on the PC.' });
        return;
      }
      const res = this.#deps.pairDevice(
        String(body.label ?? 'Phone').slice(0, 64),
        String(body.publicKey ?? ''),
      );
      // One use. The window closes whether the key parsed or not, so a bad
      // key cannot be used to keep guessing against a live code.
      this.#enrollment = null;
      await this.#send({
        rid: message.rid,
        ok: res.ok,
        deviceId: res.id,
        error: res.error,
        vapidKey: res.ok ? this.#deps.vapidPublicKey() : undefined,
      });
      return;
    }

    if (message.t === 'subscribe') {
      const body = (message.body ?? {}) as Record<string, unknown>;
      const deviceId = String(body.deviceId ?? '');
      const endpoint = String(body.endpoint ?? '');
      if (deviceId && /^https:\/\//.test(endpoint)) this.#deps.setPushEndpoint(deviceId, endpoint);
      return;
    }

    // --- the phone asking, rather than answering ----------------------------
    // Both branches answer identically when no ActionService was supplied, so
    // a host that did not opt in is indistinguishable from one with an empty
    // list. There is nothing to probe.
    if (message.t === 'actions?') {
      const actions = this.#deps.actions;
      await this.#send({ rid: message.rid, ok: true, ...(actions ? actions.offer() : { actions: [], nonce: '' }) });
      return;
    }

    if (message.t === 'status?') {
      const provider = this.#deps.status;
      if (!provider) {
        await this.#send({ rid: message.rid, ok: true, status: null });
        return;
      }
      try {
        await this.#send({ rid: message.rid, ok: true, status: sanitizeStatus(await provider()) });
      } catch {
        await this.#send({ rid: message.rid, ok: false, error: 'status is not available right now' });
      }
      return;
    }

    if (message.t === 'action') {
      const body = (message.body ?? {}) as Record<string, unknown>;
      const actions = this.#deps.actions;
      if (!actions) {
        await this.#send({ rid: message.rid, ok: false, error: 'that action is not available' });
        return;
      }
      const res = await actions.invoke({
        actionId: String(body.actionId ?? ''),
        deviceId: String(body.deviceId ?? ''),
        nonce: String(body.nonce ?? ''),
        signatureBase64: String(body.signature ?? ''),
      });
      await this.#send({ rid: message.rid, ...res });
      return;
    }

    if (message.t === 'answer') {
      const body = (message.body ?? {}) as Record<string, unknown>;
      const requestId = String(body.requestId ?? '');
      if (!this.#pending.has(requestId) || this.#settled.includes(requestId)) return;
      const decision = body.decision === 'approve' ? 'approve' : 'deny';

      this.#settled.push(requestId);
      if (this.#settled.length > SETTLED_MEMORY) this.#settled.shift();
      this.#pending.delete(requestId);

      // Straight to the gate, which verifies the signature against the paired
      // key. Nothing this class has done makes the answer trustworthy.
      this.#handler?.({
        requestId,
        deviceId: String(body.deviceId ?? ''),
        decision,
        signatureBase64: String(body.signature ?? ''),
      });
    }
  }
}
