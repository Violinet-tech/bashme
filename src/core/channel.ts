// channel.ts — how a request reaches a device that is not this one.
//
// THE CONSTRAINT, restated because it is the one that shapes everything here:
// violet-dev's SECURITY.md records four separate RCE paths that existed because
// the app had an HTTP/WebSocket surface, and all of it was deleted rather than
// patched. That file pre-commits any future cross-device feature to "no
// listening inbound socket." So an approving phone CANNOT POST to this machine.
//
// Every transport IN THIS FILE is therefore outbound-only: this machine opens
// the connection, holds it, and reads the signed answer back down it. That is
// the same shape Claude Code's own Remote Control uses.
//
// ONE EXCEPTION EXISTS, and it is deliberately not here. `app/lanServer.ts`
// listens, because "outbound-only" and "approve from a phone with no app
// installed" cannot both be true — a phone browser cannot accept an inbound
// connection, so something has to. It lives in the standalone app and core
// never imports it, which is what keeps SECURITY.md literally true of Violet
// OS: that app still opens no port. Read the header of lanServer.ts before
// assuming anything about what reaching that socket grants — the answer is
// nothing, because the signature check below is still the only thing that
// makes an answer count.
//
// Nothing in this file is a trust boundary on its own. A transport only ever
// carries bytes; the decision to trust an answer lives in `confirm.ts`'s
// signature check, which runs on whatever arrives regardless of how it got here.

import type { PairedDevice } from './types.ts';
import type { PresentedRequest } from './gate.ts';

export interface DeviceAnswer {
  requestId: string;
  deviceId: string;
  decision: 'approve' | 'deny';
  signatureBase64: string;
}

export interface ApprovalTransport {
  readonly id: string;
  readonly label: string;
  /** False when the transport is present but not usable (unconfigured, offline). */
  isAvailable(): boolean;
  /** Push a pending request outward. Must not block the gate. */
  push(presented: PresentedRequest, devices: PairedDevice[]): void;
  /** Register the sink for signed answers coming back down the channel. */
  onAnswer(handler: (answer: DeviceAnswer) => void): void;
  stop(): void;
}

/*
 * Relay transport — the intended default, and it now exists.
 *
 * The implementation moved to `core/relay.ts` once the question of which relay
 * it rides on was settled: a small Cloudflare Worker that forwards sealed bytes
 * between two pollers (see `bashme-relay/`). It stays in core rather than in
 * the app because it opens no port -- both ends dial out -- so VIOLINET OS can
 * use it without gaining the inbound surface that put lanServer.ts outside core
 * in the first place.
 *
 *   export { RelayTransport, newRelaySession } from './relay.ts';
 *
 * is done in index.ts; nothing is re-exported from here, so there is exactly
 * one class by that name.
 */

/**
 * LAN transport — a placeholder kept for anything that imports core without the
 * standalone app, VIOLINET OS included.
 *
 * The working implementation is `app/lanServer.ts`, which listens and therefore
 * cannot live in core. This reports unavailable, so an app that has only core
 * falls back to the local dialog — the safe direction, and the behaviour Violet
 * OS is meant to keep.
 *
 * SECURITY.md's own words still apply to the real one: "a LAN is not a trust
 * boundary." Being on the subnet earns nothing; the signature check in
 * confirm.ts is what makes an answer trustworthy, and pairing is still required.
 */
export class LanTransport implements ApprovalTransport {
  readonly id = 'lan';
  readonly label = 'Local network (paired devices only)';
  #handler: ((answer: DeviceAnswer) => void) | null = null;

  isAvailable(): boolean {
    return false;
  }

  push(): void {
    throw new Error('LAN transport is not available in this build');
  }

  onAnswer(handler: (answer: DeviceAnswer) => void): void {
    this.#handler = handler;
  }

  stop(): void {
    this.#handler = null;
  }
}

/**
 * Fans one request out across every available transport.
 *
 * First correctly-signed answer wins, which the gate enforces by ignoring
 * answers for requests it has already settled.
 */
export class TransportSet {
  #transports: ApprovalTransport[];

  constructor(transports: ApprovalTransport[]) {
    this.#transports = transports;
  }

  available(): ApprovalTransport[] {
    return this.#transports.filter((t) => {
      try {
        return t.isAvailable();
      } catch {
        return false;
      }
    });
  }

  push(presented: PresentedRequest, devices: PairedDevice[]): boolean {
    let reached = false;
    for (const t of this.available()) {
      try {
        t.push(presented, devices);
        reached = true;
      } catch {
        /* one dead transport must not stop the others, or the local dialog */
      }
    }
    return reached;
  }

  onAnswer(handler: (answer: DeviceAnswer) => void): void {
    for (const t of this.#transports) t.onAnswer(handler);
  }

  stop(): void {
    for (const t of this.#transports) {
      try {
        t.stop();
      } catch {
        /* shutdown is best-effort */
      }
    }
  }
}
