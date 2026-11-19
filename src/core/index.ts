// index.ts — the whole public surface.
//
// VIOLINET OS imports from here and nowhere deeper, so the internals can move
// without a second consumer breaking.

// This file is package.json's "main", which is correct for an npm dependency
// and is also the field ELECTRON reads to find an app's entry point. So
// `electron .` in this directory loads the library: no window, no error, and a
// live process that looks exactly like a launch that silently failed. That cost
// a whole session of chasing a palette bug in an app that was never running.
//
// The guard is here rather than in main.ts because main.ts is the file that
// never got loaded. A library has no business knowing about Electron, which is
// why this only reads a version string and never imports anything.
// The marker is set by app/entryMarker.ts, which main.ts imports above its
// import of this file -- so if this is running under Electron's main process
// and the marker is absent, Electron resolved "main" and loaded the library.
if (
  typeof process !== 'undefined' &&
  process.versions?.electron &&
  process.type === 'browser' &&
  (globalThis as { __bashmeAppEntry?: boolean }).__bashmeAppEntry !== true
) {
  throw new Error(
    "bashme's core was loaded as an Electron entry point. " +
      'package.json "main" points at the library, which is what npm needs; ' +
      'the app is `npm run app` (electron src/app/main.ts), never `electron .`.',
  );
}

export type {
  AuditRow,
  AuditSink,
  GateRequest,
  HardReason,
  Originator,
  PairedDevice,
  RequestKind,
  Resolution,
  Rule,
  RuleStore,
  Verdict,
} from './types.ts';

export { Gate } from './gate.ts';
export type { GateConfig, GateDeps, PresentedRequest } from './gate.ts';

export { classify, isInside, HARD_REASON_LABELS } from './classify.ts';
export type { ClassifyOptions } from './classify.ts';

export { matchRule, validateRule, previewRule } from './rules.ts';
export type { RulePreview } from './rules.ts';
export { parseCommand, tokenize, commandName } from './shell.ts';

export {
  issueConfirm,
  verifyConfirm,
  verifyDeviceSignature,
  requestHash,
  newNonce,
} from './confirm.ts';

export {
  parseDeviceKey,
  fingerprintOf,
  fingerprintFromDer,
  generateDeviceKeypair,
  signDeviceAnswer,
} from './devices.ts';
export type { ParsedDeviceKey } from './devices.ts';

export { SqliteStore, migrate, SCHEMA } from './store.ts';
export type { Db } from './store.ts';

export { generateVapidKeys, sendPushPing } from './push.ts';
export type { VapidKeys, PushSubscription } from './push.ts';

export { LanTransport, TransportSet } from './channel.ts';
export { RelayTransport, newRelaySession, OFFICIAL_RELAY_URL } from './relay.ts';
export { ActionService, parseActions, verifyActionSignature } from './actions.ts';
export type { ActionDef, ActionDeps, ActionOffer, ActionAuditEntry, ActionRunResult } from './actions.ts';
export type { RelaySession, RelayStatus, RelayDeps } from './relay.ts';
export { sanitizeStatus, chatState, MAX_CHATS, WORKING_WINDOW_SECONDS } from './status.ts';
export type { ChatState, ChatStatus, StatusSnapshot } from './status.ts';
export type { ApprovalTransport, DeviceAnswer } from './channel.ts';
