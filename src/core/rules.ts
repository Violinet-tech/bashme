// rules.ts — standing auto-approve, deliberately hard to write too broadly.
//
// The reference failure is already in this workspace: `.claude/settings.local.json`
// allows `Bash(npm install *)`, and `npm install` runs arbitrary postinstall
// scripts. The rule's author meant "installing packages is routine"; what they
// wrote was "any package may execute code here."
//
// So a rule here cannot contain a wildcard, cannot name a wildcard originator,
// and -- the part that actually closes the npm-install-shaped hole -- cannot
// match a command that chains. `npm run build` matching is not the same as
// `npm run build && curl ... | sh` matching.

import type { AuditRow, GateRequest, Rule } from './types.ts';
import { parseCommand } from './shell.ts';
import { classify } from './classify.ts';
import type { ClassifyOptions } from './classify.ts';

export interface RuleMatch {
  rule: Rule;
}

/** Reasons a candidate rule is rejected at authoring time. */
export function validateRule(rule: Omit<Rule, 'matchCount' | 'createdAt'>): string[] {
  const errors: string[] = [];
  if (!rule.originatorId.trim()) errors.push('A rule must name exactly one originator.');
  if (/[*?]/.test(rule.originatorId)) errors.push('Originator cannot contain a wildcard.');
  if (!rule.prefixes.length) errors.push('A rule must list at least one command prefix.');

  for (const p of rule.prefixes) {
    const prefix = p.trim();
    if (!prefix) {
      errors.push('A command prefix cannot be empty.');
      continue;
    }
    if (/[*?]/.test(prefix)) {
      errors.push(`"${prefix}" contains a wildcard. List the literal commands instead.`);
    }
    if (prefix.length < 3) {
      errors.push(`"${prefix}" is too short to be a meaningful prefix.`);
    }
    const parsed = parseCommand(prefix);
    if (parsed.chained || parsed.opaque) {
      errors.push(`"${prefix}" contains shell chaining, which a prefix may not.`);
    }
  }
  return errors;
}

/** Collapse runs of whitespace so formatting differences do not defeat a prefix. */
function normalize(command: string): string {
  return command.trim().replace(/\s+/g, ' ');
}

/**
 * First enabled rule that matches, or null.
 *
 * Callers MUST have run `classify` first and skipped this entirely when the
 * verdict is hard-blocked -- this function does not re-check that, on purpose,
 * so the ordering is visible at the call site rather than hidden in here.
 */
export function matchRule(req: GateRequest, rules: readonly Rule[]): RuleMatch | null {
  const parsed = parseCommand(req.command);

  // A chained or opaque command can always hide a second, unapproved command
  // behind an approved-looking first one.
  if (parsed.chained || parsed.opaque) return null;

  const command = normalize(req.command);

  for (const rule of rules) {
    if (!rule.enabled) continue;
    if (rule.originatorId !== req.originator.id) continue;
    if (rule.kind !== req.kind) continue;

    for (const raw of rule.prefixes) {
      const prefix = normalize(raw);
      if (!prefix) continue;
      if (command === prefix) return { rule };
      // Require a word boundary so `npm run build` cannot match `npm run build-prod`.
      if (command.startsWith(prefix + ' ')) return { rule };
    }
  }
  return null;
}

export interface RulePreview {
  errors: string[];
  /** Past requests this rule would have auto-approved, newest first. */
  matches: Array<{ command: string; settledAt: string }>;
  /**
   * Requests matching the prefix that would STILL have prompted, because they
   * fall in a never-auto-approve category. Counted separately so the number in
   * `matches` is not read as "everything this touches".
   */
  hardBlocked: number;
  sampled: number;
}

/**
 * What a rule would have done to the requests already in the audit log.
 *
 * Written for the authoring UI, and it is the honest version of "is this rule
 * too broad?": a prefix's real scope is not obvious from reading it, but the
 * list of commands it would have waved through is. Shown BEFORE the rule is
 * saved, because a standing grant of execution should not be the thing you
 * discover the scope of afterwards.
 */
export function previewRule(
  rule: Omit<Rule, 'matchCount' | 'createdAt'>,
  history: readonly AuditRow[],
  opts: ClassifyOptions,
): RulePreview {
  const errors = validateRule(rule);
  if (errors.length) return { errors, matches: [], hardBlocked: 0, sampled: history.length };

  const candidate: Rule = { ...rule, createdAt: new Date(0).toISOString(), matchCount: 0 };
  const matches: Array<{ command: string; settledAt: string }> = [];
  let hardBlocked = 0;

  for (const row of history) {
    const asRequest: GateRequest = {
      id: row.requestId,
      kind: row.kind,
      command: row.command,
      cwd: row.cwd,
      originator: { id: row.originatorId, label: row.originatorLabel },
      requestedAt: row.requestedAt,
    };
    if (!matchRule(asRequest, [candidate])) continue;
    // Replay the classifier rather than trusting the stored reasons: the
    // workspace root or the protected-path list may have changed since, and the
    // preview must describe what the rule would do NOW.
    if (classify(asRequest, opts).hardBlocked) hardBlocked++;
    else matches.push({ command: row.command, settledAt: row.settledAt });
  }

  return { errors: [], matches, hardBlocked, sampled: history.length };
}
