// claudeStatus.ts — reads the Claude desktop app's own bookkeeping to answer
// "is it open, and what is each chat doing".
//
// The app keeps one small JSON file per chat under
// %APPDATA%\Claude\claude-code-sessions\<account>\<org>\local_<id>.json. This reads
// ONLY: the title, the model, when the chat last did anything, whether it is archived,
// and the app's own one-line post-turn label. Nothing is parsed out of the transcripts,
// and nothing is written. The result goes through `sanitizeStatus` before it leaves,
// which is what actually bounds what a phone can learn.

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { execFile } from 'node:child_process';

import { MAX_CHATS, chatState } from '../core/status.ts';
import type { ChatStatus, StatusSnapshot } from '../core/status.ts';

/** A chat untouched this long is not "recent", whatever its state says. */
const RECENT_DAYS = 7;
/** Reading a few hundred files per poll is the cost this avoids. */
const MAX_FILES_READ = 40;

export interface ClaudeStatusDeps {
  sessionsDir: string;
  /** Where Claude Code keeps each chat's transcript (`<project>/<cliSessionId>.jsonl`).
   *  Only the modification time is read, never the contents. */
  transcriptsDir?: string;
  now?: () => number;
  isAppRunning?: () => Promise<boolean>;
}

/** Newest-first list of the live, recent chat files, by modification time. */
function recentSessionFiles(root: string, nowMs: number): string[] {
  const found: Array<{ file: string; mtime: number }> = [];
  const cutoff = nowMs - RECENT_DAYS * 86_400_000;
  const dirs = (path: string): string[] => {
    try {
      return readdirSync(path, { withFileTypes: true })
        .filter((e) => e.isDirectory())
        .map((e) => join(path, e.name));
    } catch {
      return [];
    }
  };
  for (const account of dirs(root)) {
    for (const org of dirs(account)) {
      let names: string[] = [];
      try {
        names = readdirSync(org).filter((n) => n.startsWith('local_') && n.endsWith('.json'));
      } catch {
        continue;
      }
      for (const name of names) {
        const file = join(org, name);
        try {
          const mtime = statSync(file).mtimeMs;
          if (mtime >= cutoff) found.push({ file, mtime });
        } catch {
          /* a file that vanished between readdir and stat is just not there */
        }
      }
    }
  }
  return found.sort((a, b) => b.mtime - a.mtime).slice(0, MAX_FILES_READ).map((f) => f.file);
}

/**
 * When a chat's transcript was last written, if it can be found.
 *
 * `lastActivityAt` only moves when a message does, so a chat in the middle of a long
 * run of tool calls looks idle after a minute. The transcript is appended to on every
 * step, so its mtime is the honest "is it doing something". The file is statted, not
 * opened.
 */
function transcriptMtime(projectDirs: string[], cliSessionId: string): number | null {
  for (const dir of projectDirs) {
    try {
      return statSync(join(dir, `${cliSessionId}.jsonl`)).mtimeMs;
    } catch {
      /* not in this project folder */
    }
  }
  return null;
}

export async function readClaudeStatus(deps: ClaudeStatusDeps): Promise<StatusSnapshot> {
  const nowMs = (deps.now ?? Date.now)();
  const chats: ChatStatus[] = [];
  const projectDirs: string[] = [];
  if (deps.transcriptsDir) {
    try {
      for (const e of readdirSync(deps.transcriptsDir, { withFileTypes: true })) {
        if (e.isDirectory()) projectDirs.push(join(deps.transcriptsDir, e.name));
      }
    } catch {
      /* no transcripts folder: fall back to lastActivityAt alone */
    }
  }

  for (const file of recentSessionFiles(deps.sessionsDir, nowMs)) {
    if (chats.length >= MAX_CHATS) break;
    let doc: Record<string, unknown>;
    try {
      doc = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
    } catch {
      continue;
    }
    if (doc.isArchived === true) continue;

    const id = String(doc.sessionId ?? '');
    const last = Number(doc.lastActivityAt);
    if (!id || !Number.isFinite(last)) continue;

    const cli = typeof doc.cliSessionId === 'string' ? doc.cliSessionId : '';
    const written = cli && projectDirs.length ? transcriptMtime(projectDirs, cli) : null;
    const age = Math.max(0, Math.round((nowMs - Math.max(last, written ?? 0)) / 1000));
    const summary = (doc.postTurnSummary ?? {}) as Record<string, unknown>;
    const category = typeof summary.status_category === 'string' ? summary.status_category : null;
    const state = chatState(category, age);

    chats.push({
      id,
      title: String(doc.title ?? ''),
      state,
      // Only a chat waiting on the owner has a detail worth a line on the phone.
      detail: state === 'needs-you' && typeof summary.status_detail === 'string' ? summary.status_detail : '',
      ageSeconds: age,
      model: String(doc.model ?? ''),
    });
  }

  // Most recent activity first, so a working chat is never buried under older ones.
  chats.sort((a, b) => a.ageSeconds - b.ageSeconds);

  const running = await (deps.isAppRunning ?? desktopAppRunning)();
  return { at: new Date(nowMs).toISOString(), app: { name: 'Claude', running }, chats };
}

let cached: { at: number; value: boolean } | null = null;

/**
 * Whether the Claude DESKTOP app is up, as opposed to the Claude Code CLI, which is
 * also called claude.exe. The desktop app lives under WindowsApps; the CLI under
 * AppData, so the path is what tells them apart. Cached for a few seconds because the
 * phone polls and PowerShell is the slow part.
 */
export function desktopAppRunning(): Promise<boolean> {
  if (cached && Date.now() - cached.at < 5000) return Promise.resolve(cached.value);
  return new Promise((resolve) => {
    execFile(
      'powershell.exe',
      [
        '-NoProfile',
        '-Command',
        "@(Get-Process Claude -ErrorAction SilentlyContinue | Where-Object { $_.Path -like '*WindowsApps*Claude*' }).Count",
      ],
      { windowsHide: true, timeout: 10_000 },
      (err, stdout) => {
        const value = !err && Number(String(stdout).trim()) > 0;
        cached = { at: Date.now(), value };
        resolve(value);
      },
    );
  });
}
