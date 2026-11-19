// actions.ts — the phone ASKING, instead of only answering.
//
// THIS INVERTS THE TRUST DIRECTION, so read the argument before extending it.
//
// Everything else in bashme is a veto. The PC proposes a command, the phone
// signs approve or deny, and a phone that is lost, unlocked or shoulder-surfed
// can do exactly one harmful thing: nothing. Unanswered denies. The worst case
// is a machine that refuses to work.
//
// An action runs the other way. The phone names something and this machine
// does it. A stolen phone is now a stolen capability, and no amount of
// encryption changes that -- the key is ON the phone, so anyone holding an
// unlocked phone holds the key. The mitigation is not cryptographic, it is
// that THE PHONE CANNOT SAY WHAT TO RUN:
//
//   * every action is written on the PC, in a file only a local user can edit
//   * the phone sends an ID, never a command string, never an argument
//   * an unknown ID is dropped; there is no fallthrough that executes text
//
// So the blast radius is exactly the list the owner wrote, and it is capped at
// definition time rather than at invocation time. That is the whole design.
// If you ever add a parameter the phone supplies, you have rebuilt a remote
// shell with extra steps, and the paragraph above stops being true.
//
// WHY THESE BYPASS THE CLASSIFIER, said out loud
//
// `schtasks /run /tn VioletNetFix` is hard-blocked by classify.ts, and it is
// also the single most useful thing to be able to do from another room. An
// action is pre-approved by the owner at the moment they wrote it into the
// file, which is a stronger act of consent than clicking through a dialog at
// 2am. It therefore does NOT go through the gate. What keeps that honest is
// that writing the file requires local access, which is the same access needed
// to just run the command -- so the file grants nothing new to an attacker who
// can write it, and everything to one who cannot.
//
// Every invocation is audited regardless of outcome. An action that fired is a
// thing the owner must be able to find afterwards.

import crypto from 'node:crypto';

import type { PairedDevice } from './types.ts';

/** How long an issued nonce stays spendable. Short: the phone asks for the
 *  list and taps within seconds, so anything older is a replay attempt or a
 *  stale tab, and both deserve the same answer. */
const NONCE_TTL_MS = 2 * 60 * 1000;

/** A run that produces more than this is truncated before it goes anywhere
 *  near the relay: the point is "did it work", not a log viewer. */
const MAX_OUTPUT_CHARS = 2000;

export interface ActionDef {
  /** Referenced by the phone. Stable, because a phone may hold a stale list. */
  id: string;
  label: string;
  description?: string;
  /** Run verbatim. Written by the owner, never composed from phone input. */
  command: string;
  cwd?: string;
}

export interface ActionRunResult {
  ok: boolean;
  output: string;
}

export interface ActionAuditEntry {
  actionId: string;
  deviceId: string;
  at: string;
  ok: boolean;
  error?: string;
}

export interface ActionDeps {
  /** Paired devices, live: a revoked phone must stop working immediately. */
  devices(): PairedDevice[];
  /** Execute. Injected so core stays free of child_process and VIOLINET OS can
   *  supply its own runner (or refuse to supply one at all). */
  run(action: ActionDef): Promise<ActionRunResult>;
  audit?(entry: ActionAuditEntry): void;
}

/** What the phone is allowed to know: no command, no cwd. It taps a label. */
export interface ActionOffer {
  id: string;
  label: string;
  description: string | null;
}

/**
 * Validate a parsed actions file.
 *
 * Invalid entries are DROPPED rather than defaulted. A half-understood action
 * definition is a command nobody wrote on purpose, and the failure mode of
 * dropping one is a missing button.
 */
export function parseActions(input: unknown): { actions: ActionDef[]; errors: string[] } {
  const errors: string[] = [];
  const actions: ActionDef[] = [];
  const seen = new Set<string>();

  const list = Array.isArray(input)
    ? input
    : Array.isArray((input as { actions?: unknown })?.actions)
      ? ((input as { actions: unknown[] }).actions)
      : null;

  if (!list) return { actions, errors: ['expected a JSON array of actions, or { "actions": [...] }'] };

  for (const [i, raw] of list.entries()) {
    const row = (raw ?? {}) as Record<string, unknown>;
    const id = String(row.id ?? '').trim();
    const label = String(row.label ?? '').trim();
    const command = String(row.command ?? '').trim();

    if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(id)) {
      errors.push(`action ${i}: id must be lowercase letters, digits and dashes`);
      continue;
    }
    if (seen.has(id)) {
      errors.push(`action ${i}: duplicate id "${id}"`);
      continue;
    }
    if (!label) {
      errors.push(`action "${id}": needs a label, which is all the phone shows`);
      continue;
    }
    if (!command) {
      errors.push(`action "${id}": needs a command`);
      continue;
    }

    seen.add(id);
    const def: ActionDef = { id, label: label.slice(0, 64), command };
    const description = String(row.description ?? '').trim();
    if (description) def.description = description.slice(0, 200);
    const cwd = String(row.cwd ?? '').trim();
    if (cwd) def.cwd = cwd;
    actions.push(def);
  }

  return { actions, errors };
}

export class ActionService {
  #deps: ActionDeps;
  #defs: ActionDef[] = [];
  /** Issued and not yet spent. A nonce is removed the moment it is used,
   *  successfully or not, so one message is one attempt. */
  #nonces = new Map<string, number>();

  constructor(deps: ActionDeps, defs: ActionDef[] = []) {
    this.#deps = deps;
    this.#defs = defs;
  }

  replace(defs: ActionDef[]): void {
    this.#defs = defs;
  }

  get size(): number {
    return this.#defs.length;
  }

  /**
   * The list, plus the single nonce that any one of them may be invoked with.
   *
   * The nonce is issued HERE rather than chosen by the phone, which is what
   * makes a replayed `action` message useless: the relay may deliver a copy of
   * a message it saw, but the nonce inside it was spent on first delivery.
   */
  offer(): { actions: ActionOffer[]; nonce: string } {
    this.#sweep();
    const nonce = crypto.randomBytes(16).toString('base64url');
    this.#nonces.set(nonce, Date.now() + NONCE_TTL_MS);
    return {
      actions: this.#defs.map((a) => ({
        id: a.id,
        label: a.label,
        description: a.description ?? null,
      })),
      nonce,
    };
  }

  /**
   * Run one, if the signature holds.
   *
   * Order matters: spend the nonce FIRST, before any check that could fail, so
   * a wrong guess cannot be retried against the same nonce.
   */
  async invoke(args: {
    actionId: string;
    deviceId: string;
    nonce: string;
    signatureBase64: string;
  }): Promise<{ ok: boolean; error?: string; output?: string }> {
    this.#sweep();

    const expiry = this.#nonces.get(args.nonce);
    this.#nonces.delete(args.nonce);
    if (expiry === undefined || expiry < Date.now()) {
      return this.#fail(args, 'that request was stale — reopen the list and try again');
    }

    const device = this.#deps.devices().find((d) => d.id === args.deviceId && !d.revokedAt);
    if (!device) return this.#fail(args, 'that device is not paired');

    const def = this.#defs.find((a) => a.id === args.actionId);
    // Deliberately the same message as a bad signature: a phone that can probe
    // which ids exist has learned something it was never shown.
    if (!def) return this.#fail(args, 'that action is not available');

    if (!verifyActionSignature({
      publicKeyBase64: device.publicKey,
      actionId: args.actionId,
      nonce: args.nonce,
      signatureBase64: args.signatureBase64,
    })) {
      return this.#fail(args, 'that action is not available');
    }

    let result: ActionRunResult;
    try {
      result = await this.#deps.run(def);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'the action failed to start';
      return this.#fail(args, message);
    }

    this.#deps.audit?.({
      actionId: def.id,
      deviceId: device.id,
      at: new Date().toISOString(),
      ok: result.ok,
    });
    return { ok: result.ok, output: result.output.slice(0, MAX_OUTPUT_CHARS) };
  }

  #fail(args: { actionId: string; deviceId: string }, error: string): { ok: false; error: string } {
    // A refusal is audited too. "Someone tried an action they could not run"
    // is precisely the event worth finding later.
    this.#deps.audit?.({
      actionId: args.actionId,
      deviceId: args.deviceId,
      at: new Date().toISOString(),
      ok: false,
      error,
    });
    return { ok: false, error };
  }

  #sweep(): void {
    const now = Date.now();
    for (const [nonce, expiry] of this.#nonces) if (expiry < now) this.#nonces.delete(nonce);
  }
}

/**
 * The device signs `action|${actionId}|${nonce}`.
 *
 * The literal prefix is not decoration. An approval signs
 * `${hash}|${nonce}|${decision}`, and without a distinct prefix a signature
 * harvested from one scheme could be presented to the other — three
 * pipe-separated fields is three pipe-separated fields to Ed25519.
 */
export function verifyActionSignature(args: {
  publicKeyBase64: string;
  actionId: string;
  nonce: string;
  signatureBase64: string;
}): boolean {
  try {
    const key = crypto.createPublicKey({
      key: Buffer.from(args.publicKeyBase64, 'base64'),
      format: 'der',
      type: 'spki',
    });
    const message = Buffer.from(`action|${args.actionId}|${args.nonce}`);
    return crypto.verify(null, message, key, Buffer.from(args.signatureBase64, 'base64'));
  } catch {
    return false;
  }
}
