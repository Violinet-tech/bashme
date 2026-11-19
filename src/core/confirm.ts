// confirm.ts — plan/apply tokens, ported from helm/server/auth.js.
//
// This is the piece MERGE_PLAN.md Phase 1 called for and never landed. The
// property it buys: an approval is a signature over the exact thing that was
// described, so a "yes" cannot be carried across to a different command, and
// cannot be replayed after it expires.
//
// The signing key is per-process and never persisted. A restart invalidates
// every outstanding token, which is the correct behaviour -- an approval the
// user granted to a process that no longer exists should not survive it.

import crypto from 'node:crypto';
import type { GateRequest } from './types.ts';

const CONFIRM_KEY = crypto.randomBytes(32);
const CONFIRM_TTL_MS = 2 * 60 * 1000;

/** Stable stringification, so key order cannot change a hash. */
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    return `{${Object.keys(obj)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(obj[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value ?? null);
}

function timingSafeEqual(a: string, b: string): boolean {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

/**
 * The bytes an approval commits to.
 *
 * Everything that changes what would actually run is in here. `id` is included
 * so two identical commands issued seconds apart are still distinct approvals.
 */
export function requestHash(req: GateRequest): string {
  return crypto
    .createHash('sha256')
    .update(
      canonical({
        id: req.id,
        kind: req.kind,
        command: req.command,
        cwd: req.cwd,
        originator: req.originator.id,
      }),
    )
    .digest('hex');
}

export interface ConfirmToken {
  token: string;
  expiresAt: string;
}

export function issueConfirm(req: GateRequest): ConfirmToken {
  const expires = Date.now() + CONFIRM_TTL_MS;
  const body = `${expires}|${requestHash(req)}`;
  const sig = crypto.createHmac('sha256', CONFIRM_KEY).update(body).digest('base64url');
  return { token: `${expires}.${sig}`, expiresAt: new Date(expires).toISOString() };
}

export function verifyConfirm(req: GateRequest, token: string): boolean {
  if (!token || typeof token !== 'string' || !token.includes('.')) return false;
  const [expiresRaw, sig] = token.split('.');
  const expires = Number(expiresRaw);
  if (!Number.isFinite(expires) || Date.now() > expires) return false;
  const body = `${expires}|${requestHash(req)}`;
  const expected = crypto.createHmac('sha256', CONFIRM_KEY).update(body).digest('base64url');
  return timingSafeEqual(sig ?? '', expected);
}

/**
 * Verify a paired device's answer.
 *
 * The device signs `${requestHash}|${nonce}|${decision}`. Binding all three is
 * what stops a captured "approve" signature being replayed against a different
 * request, or an "approve" being harvested and reused after the fact.
 */
export function verifyDeviceSignature(args: {
  publicKeyBase64: string;
  requestHash: string;
  nonce: string;
  decision: 'approve' | 'deny';
  signatureBase64: string;
}): boolean {
  try {
    const key = crypto.createPublicKey({
      key: Buffer.from(args.publicKeyBase64, 'base64'),
      format: 'der',
      type: 'spki',
    });
    const message = Buffer.from(`${args.requestHash}|${args.nonce}|${args.decision}`);
    return crypto.verify(null, message, key, Buffer.from(args.signatureBase64, 'base64'));
  } catch {
    return false; // malformed key or signature is a denial, never an error path
  }
}

export function newNonce(): string {
  return crypto.randomBytes(16).toString('base64url');
}
