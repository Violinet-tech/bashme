// gate.ts — the decision engine. Everything else in core/ feeds this.
//
// Order is load-bearing and is written out longhand rather than being folded
// into a clever pipeline, because the ordering IS the security property:
//
//   1. classify   -> hard category? rules are skipped entirely, a human answers
//   2. rules      -> exact originator + literal prefix + no chaining
//   3. hold       -> fan out to the local dialog and any paired device
//   4. settle     -> first correctly-bound answer wins; anything else denies
//
// Fail-closed is inherited from violet-dev's approval.ts and kept: a timeout,
// a missing presenter, or a throw all resolve to "denied".

import type {
  AuditRow,
  AuditSink,
  GateRequest,
  PairedDevice,
  Resolution,
  RuleStore,
  Verdict,
} from './types.ts';
import { classify } from './classify.ts';
import { matchRule } from './rules.ts';
import { issueConfirm, newNonce, requestHash, verifyConfirm, verifyDeviceSignature } from './confirm.ts';

export interface GateConfig {
  /**
   * The user-facing toggle.
   *
   * OFF DOES NOT MEAN "APPROVE EVERYTHING". It means the standing-rule and
   * paired-device layers are inert and every request falls back to a local
   * dialog -- exactly the behaviour of violet-dev's approval.ts today. There is
   * deliberately no setting anywhere in this app that disables the prompt.
   */
  enabled: boolean;
  /** Standing rules, independently switchable while the feature stays on. */
  rulesEnabled: boolean;
  /** Paired-device approval, independently switchable. */
  devicesEnabled: boolean;
  workspaceRoot: string;
  protectedPaths?: string[];
  timeoutMs?: number;
}

export interface PresentedRequest {
  request: GateRequest;
  verdict: Verdict;
  /** Present for the local dialog's reply; bound to this exact request. */
  confirmToken: string;
  expiresAt: string;
  /** Sent outbound to paired devices; their signature must cover it. */
  nonce: string;
  hash: string;
}

export interface GateDeps {
  audit: AuditSink;
  rules: RuleStore;
  /** Render the request for a human on this machine. */
  present(presented: PresentedRequest): void;
  /** Withdraw a request that settled elsewhere (device answered, timed out). */
  withdraw?(requestId: string): void;
  /** Outbound push to paired devices. Absent means local-only. */
  pushToDevices?(presented: PresentedRequest, devices: PairedDevice[]): void;
  listDevices?(): PairedDevice[];
}

const DEFAULT_TIMEOUT_MS = 2 * 60 * 1000;

interface Pending {
  presented: PresentedRequest;
  settle(resolution: Resolution): void;
  timer: ReturnType<typeof setTimeout>;
}

export class Gate {
  #pending = new Map<string, Pending>();
  #config: GateConfig;
  #deps: GateDeps;

  constructor(config: GateConfig, deps: GateDeps) {
    this.#config = config;
    this.#deps = deps;
  }

  get config(): Readonly<GateConfig> {
    return this.#config;
  }

  setConfig(patch: Partial<GateConfig>): void {
    this.#config = { ...this.#config, ...patch };
  }

  /** Requests currently awaiting an answer, newest last. */
  listPending(): PresentedRequest[] {
    return [...this.#pending.values()].map((p) => p.presented);
  }

  /**
   * Ask for permission to perform one side effect.
   *
   * Resolves true only on an explicit, correctly-bound approval.
   */
  request(req: GateRequest): Promise<boolean> {
    const verdict = classify(req, {
      workspaceRoot: this.#config.workspaceRoot,
      ...(this.#config.protectedPaths ? { protectedPaths: this.#config.protectedPaths } : {}),
    });

    // 2. Standing rules -- only ever consulted when nothing hard applies.
    if (!verdict.hardBlocked && this.#config.enabled && this.#config.rulesEnabled) {
      const match = matchRule(req, this.#deps.rules.list());
      if (match) {
        this.#deps.rules.recordMatch(match.rule.id);
        this.#writeAudit(req, verdict, { type: 'approved-by-rule', ruleId: match.rule.id });
        return Promise.resolve(true);
      }
    }

    // 3. Hold, and fan out.
    const { token, expiresAt } = issueConfirm(req);
    const presented: PresentedRequest = {
      request: req,
      verdict,
      confirmToken: token,
      expiresAt,
      nonce: newNonce(),
      hash: requestHash(req),
    };

    return new Promise<boolean>((resolve) => {
      const settle = (resolution: Resolution): void => {
        const entry = this.#pending.get(req.id);
        if (!entry) return; // already settled; late answers are ignored, not thrown
        clearTimeout(entry.timer);
        this.#pending.delete(req.id);
        this.#writeAudit(req, verdict, resolution);
        try {
          this.#deps.withdraw?.(req.id);
        } catch {
          /* withdrawal is cosmetic; never let it change the decision */
        }
        resolve(resolution.type === 'approved' || resolution.type === 'approved-by-device');
      };

      const timer = setTimeout(
        () => settle({ type: 'timeout' }),
        this.#config.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      );
      this.#pending.set(req.id, { presented, settle, timer });

      let reachedSomeone = false;
      try {
        this.#deps.present(presented);
        reachedSomeone = true;
      } catch {
        /* no renderer -> fall through to the device channel, then deny */
      }

      if (this.#config.enabled && this.#config.devicesEnabled && this.#deps.pushToDevices) {
        const devices = (this.#deps.listDevices?.() ?? []).filter((d) => !d.revokedAt);
        if (devices.length) {
          try {
            this.#deps.pushToDevices(presented, devices);
            reachedSomeone = true;
          } catch {
            /* push failed; local dialog may still answer */
          }
        }
      }

      // Nobody could be asked. Deny now rather than making the caller wait out
      // the full TTL for an answer that was never going to arrive.
      if (!reachedSomeone) settle({ type: 'no-approver' });
    });
  }

  /** Answer from the local dialog. The token proves it answers THIS request. */
  respondLocal(requestId: string, approved: boolean, confirmToken: string): boolean {
    const entry = this.#pending.get(requestId);
    if (!entry) return false;
    if (!verifyConfirm(entry.presented.request, confirmToken)) return false;
    entry.settle(approved ? { type: 'approved', by: 'local-dialog' } : { type: 'denied', by: 'local-dialog' });
    return true;
  }

  /**
   * The spoken/typed keyword.
   *
   * Only valid when exactly one request is pending, so "accept request" can
   * never approve something the speaker has not been shown, and never valid for
   * a hard-blocked request -- those always cost a deliberate tap.
   */
  respondKeyword(): { ok: boolean; reason?: string } {
    const entries = [...this.#pending.values()];
    if (entries.length === 0) return { ok: false, reason: 'Nothing is waiting for approval.' };
    if (entries.length > 1) {
      return { ok: false, reason: 'More than one request is pending. Answer them individually.' };
    }
    const entry = entries[0] as Pending;
    if (entry.presented.verdict.hardBlocked) {
      return { ok: false, reason: 'This request is in a category that always needs a deliberate approval.' };
    }
    entry.settle({ type: 'approved', by: 'keyword' });
    return { ok: true };
  }

  /** Answer from a paired device. Signature must cover hash + nonce + decision. */
  respondDevice(args: {
    requestId: string;
    deviceId: string;
    decision: 'approve' | 'deny';
    signatureBase64: string;
  }): boolean {
    const entry = this.#pending.get(args.requestId);
    if (!entry) return false;

    const device = (this.#deps.listDevices?.() ?? []).find((d) => d.id === args.deviceId);
    if (!device || device.revokedAt) return false;

    const ok = verifyDeviceSignature({
      publicKeyBase64: device.publicKey,
      requestHash: entry.presented.hash,
      nonce: entry.presented.nonce,
      decision: args.decision,
      signatureBase64: args.signatureBase64,
    });
    if (!ok) return false;

    entry.settle(
      args.decision === 'approve'
        ? { type: 'approved-by-device', deviceId: device.id }
        : { type: 'denied', by: 'device', deviceId: device.id },
    );
    return true;
  }

  /** Window closed, app quitting. Everything outstanding denies. */
  denyAll(): void {
    for (const entry of [...this.#pending.values()]) entry.settle({ type: 'no-approver' });
  }

  #writeAudit(req: GateRequest, verdict: Verdict, resolution: Resolution): void {
    const row: AuditRow = {
      requestId: req.id,
      kind: req.kind,
      command: req.command,
      cwd: req.cwd,
      originatorId: req.originator.id,
      originatorLabel: req.originator.label,
      requestedAt: req.requestedAt,
      settledAt: new Date().toISOString(),
      resolution,
      hardReasons: verdict.reasons,
    };
    try {
      this.#deps.audit.append(row);
    } catch {
      /* the audit log must never be able to block or change a decision */
    }
  }
}
