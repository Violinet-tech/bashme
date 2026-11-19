// status.ts — what the phone is allowed to SEE about the PC, beyond approvals.
//
// A status panel is the one thing on the phone that shows the PC's state without
// being asked a question first, so the rule is the opposite of "forward the object":
// the host builds a snapshot, and everything it carries is rebuilt here from a fixed
// list of fields, with every string capped. A host that adds a field to its own
// record does not thereby start sending it to a phone.
//
// It carries titles and one-line states. It never carries message text, file
// contents, paths or commands: "is Claude open, and is each chat working, waiting on
// me, or done" is the whole of it.
//
// Read-only and opt-in, the same way actions are: a host that supplies no provider
// answers exactly as an empty one would, so there is nothing to probe.

export type ChatState = 'working' | 'needs-you' | 'review' | 'done' | 'idle';

export interface ChatStatus {
  id: string;
  title: string;
  state: ChatState;
  /** One short line, e.g. what a blocked chat is waiting for. May be empty. */
  detail: string;
  /** Seconds since the chat last did anything. */
  ageSeconds: number;
  model: string;
}

export interface StatusSnapshot {
  at: string;
  app: { name: string; running: boolean };
  chats: ChatStatus[];
}

/** More than this is a list nobody reads on a phone. */
export const MAX_CHATS = 8;

const STATES: readonly ChatState[] = ['working', 'needs-you', 'review', 'done', 'idle'];

const text = (value: unknown, max: number): string =>
  typeof value === 'string' ? value.replace(/\s+/g, ' ').trim().slice(0, max) : '';

/**
 * Rebuild a snapshot from untrusted-shaped input. Unknown fields are dropped,
 * unknown states become 'idle', and a row with no id is skipped rather than defaulted.
 */
export function sanitizeStatus(input: unknown): StatusSnapshot {
  const raw = (input ?? {}) as Record<string, unknown>;
  const app = (raw.app ?? {}) as Record<string, unknown>;
  const rows = Array.isArray(raw.chats) ? raw.chats : [];

  const chats: ChatStatus[] = [];
  for (const row of rows) {
    if (chats.length >= MAX_CHATS) break;
    const r = (row ?? {}) as Record<string, unknown>;
    const id = text(r.id, 80);
    if (!id) continue;
    const state = STATES.includes(r.state as ChatState) ? (r.state as ChatState) : 'idle';
    const age = Number(r.ageSeconds);
    chats.push({
      id,
      title: text(r.title, 80) || 'Untitled chat',
      state,
      detail: text(r.detail, 100),
      ageSeconds: Number.isFinite(age) && age >= 0 ? Math.round(age) : 0,
      model: text(r.model, 40),
    });
  }

  return {
    at: new Date().toISOString(),
    app: { name: text(app.name, 40) || 'Claude', running: app.running === true },
    chats,
  };
}

/**
 * Map the fields the Claude desktop app keeps for each chat onto a state.
 *
 * `category` is the app's own post-turn summary label. A chat that moved in the last
 * minute is working whatever its last summary said, because the summary describes the
 * turn before.
 */
export function chatState(category: string | null | undefined, ageSeconds: number): ChatState {
  if (ageSeconds <= WORKING_WINDOW_SECONDS) return 'working';
  switch (category) {
    case 'blocked':
      return 'needs-you';
    case 'review_ready':
      return 'review';
    case 'completed':
      return 'done';
    default:
      return 'idle';
  }
}

/** Quiet for longer than this and a chat is no longer counted as running. */
export const WORKING_WINDOW_SECONDS = 60;
