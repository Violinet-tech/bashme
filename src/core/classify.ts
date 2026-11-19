// classify.ts — the categories no standing rule may ever auto-approve.
//
// This runs BEFORE rule matching, not after, and its answer is final. A user
// who writes a broad rule should still get a dialog for `rm -rf`, because the
// realistic failure is not a malicious user -- it is a rule whose author
// pictured a narrower set of commands than it actually matches.
//
// Every check here is allowed to be over-eager. A false positive costs one tap.
// A false negative is the whole reason this file exists.

import path from 'node:path';
import type { GateRequest, HardReason, Verdict } from './types.ts';
import { parseCommand, tokenize, commandName } from './shell.ts';

export interface ClassifyOptions {
  /** Everything outside this directory is treated as off-limits to auto-approval. */
  workspaceRoot: string;
  /** Literal paths that must never be auto-approved even inside the workspace. */
  protectedPaths?: string[];
}

// --- detection tables -------------------------------------------------------
// Kept as data rather than code so the UI can render "what is never
// auto-approved" from the same source the gate enforces.

const DESTRUCTIVE: Array<[RegExp, string]> = [
  [/^rm$/i, '`rm`'],
  [/^(?:del|erase)$/i, '`del`'],
  [/^(?:rd|rmdir)$/i, '`rmdir`'],
  [/^remove-item$/i, '`Remove-Item`'],
  [/^(?:format|diskpart|mkfs.*|shred|cipher)$/i, 'disk/format tooling'],
  [/^(?:mv|move|rename|ren)$/i, 'move/rename'],
  [/^dd$/i, '`dd`'],
];

const CREDENTIAL_PATH = /(?:^|[/\\])(?:\.env(?:\.[\w-]+)?|\.ssh|\.aws|\.azure|\.gnupg|\.netrc|_netrc|\.npmrc|\.pypirc|\.git-credentials|id_rsa|id_ed25519|id_ecdsa|credentials(?:\.json)?|secrets?(?:\.(?:json|ya?ml|env|toml))?|\.pem|\.pfx|\.p12|\.keystore)(?:$|[/\\])/i;

const CREDENTIAL_CMD: Array<[RegExp, string]> = [
  [/^(?:printenv|env)$/i, 'environment dump'],
  [/^cmdkey$/i, '`cmdkey`'],
  [/^vaultcmd$/i, '`vaultcmd`'],
  [/^get-credential$/i, '`Get-Credential`'],
  [/^security$/i, 'keychain access'],
  [/^gpg$/i, '`gpg`'],
];

const CREDENTIAL_TEXT: Array<[RegExp, string]> = [
  [/\bget-childitem\s+env:/i, 'environment dump'],
  [/\bdir\s+env:/i, 'environment dump'],
  [/\$env:[A-Za-z_]/, 'environment variable read'],
  [/\breg\b[^\n]*\b(?:sam|security|hklm\\+sam)\b/i, 'registry credential hive'],
  [/\b(?:api[_-]?key|secret|token|password|passwd)\s*=/i, 'inline secret'],
];

const POSTURE: Array<[RegExp, string]> = [
  [/^netsh$/i, '`netsh`'],
  [/^bcdedit$/i, '`bcdedit`'],
  [/^sc$/i, 'service control'],
  [/^(?:takeown|icacls|cacls|attrib)$/i, 'ACL/ownership change'],
  [/^pnputil$/i, 'driver store'],
  [/^schtasks$/i, 'scheduled tasks'],
  [/^(?:reg|regedit)$/i, 'registry edit'],
  [/^net$/i, '`net` user/group'],
  [/^(?:wmic|bcdboot|cipher)$/i, 'system configuration'],
  [/^set-executionpolicy$/i, '`Set-ExecutionPolicy`'],
  [/^(?:add|set)-mppreference$/i, 'Defender configuration'],
  [/^(?:new|set|remove)-local(?:user|group)$/i, 'local account change'],
  [/^(?:enable|disable)-windowsoptionalfeature$/i, 'Windows feature change'],
  [/^(?:systemctl|service|chmod|chown|setenforce|ufw|iptables)$/i, 'system/permission change'],
];

const ELEVATION: Array<[RegExp, string]> = [
  [/^(?:sudo|doas|runas|gsudo|psexec|pkexec)$/i, 'elevation wrapper'],
];

const ELEVATION_TEXT: Array<[RegExp, string]> = [
  [/-verb\s+['"]?runas/i, '`Start-Process -Verb RunAs`'],
  [/\brequestedexecutionlevel\b/i, 'manifest elevation'],
];

/** Commands that move bytes off this machine. */
const NETWORK: RegExp = /^(?:curl|wget|scp|sftp|rsync|nc|ncat|netcat|telnet|ftp|bitsadmin|invoke-webrequest|invoke-restmethod|iwr|wget\.exe|start-bitstransfer)$/i;

/** Flags that make a network command carry a local file as its payload. */
const UPLOAD_FLAG = /(?:^|\s)(?:-T\b|--upload-file\b|--data-binary\s*@|--data\s*@|-d\s*@|-F\s*['"]?[^=]*=@|-InFile\b|-Body\b)/i;

const WINDOWS_SYSTEM_DIR = /^[a-z]:[/\\](?:windows|program files( \(x86\))?|programdata|system32)(?:[/\\]|$)/i;

// --- path helpers -----------------------------------------------------------

/** Choose the right path flavour from the shape of the string, not the host OS. */
function flavour(p: string): path.PlatformPath {
  return /^[a-zA-Z]:[/\\]/.test(p) || p.includes('\\') ? path.win32 : path.posix;
}

function isPathLike(token: string): boolean {
  if (!token || token.startsWith('-')) return false;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(token)) return false; // URL
  return token.includes('/') || token.includes('\\') || /^[a-zA-Z]:/.test(token);
}

/** True when `target` resolves inside `root`. Comparison is case-insensitive on Windows paths. */
export function isInside(root: string, target: string): boolean {
  const f = flavour(root);
  const r = f.resolve(root);
  const t = f.resolve(r, target);
  const norm = (s: string): string => (f === path.win32 ? s.toLowerCase() : s);
  const rel = f.relative(norm(r), norm(t));
  return rel === '' || (!rel.startsWith('..') && !f.isAbsolute(rel));
}

// --- the classifier ---------------------------------------------------------

export function classify(req: GateRequest, opts: ClassifyOptions): Verdict {
  const reasons = new Set<HardReason>();
  const notes: string[] = [];

  const add = (reason: HardReason, note: string): void => {
    reasons.add(reason);
    if (!notes.includes(note)) notes.push(note);
  };

  const parsed = parseCommand(req.command);

  if (parsed.opaque) {
    add('unparseable', `contains ${parsed.opaque}, so its full effect cannot be read`);
  }

  if (req.kind === 'elevate') {
    add('privileged-elevation', 'runs with elevated privileges');
  }

  // A write request's "command" is the path it would write.
  const pathsToCheck: string[] = req.kind === 'write' ? [req.command] : [];

  for (const segment of parsed.segments) {
    const name = commandName(segment);
    const tokens = tokenize(segment);
    const args = tokens.slice(1);

    for (const [re, label] of DESTRUCTIVE) {
      if (re.test(name)) add('destructive-filesystem', `${label} removes or relocates files`);
    }
    for (const [re, label] of CREDENTIAL_CMD) {
      if (re.test(name)) add('credential-access', `${label} exposes secrets`);
    }
    for (const [re, label] of POSTURE) {
      if (re.test(name)) add('security-posture', `${label} changes this machine's security posture`);
    }
    for (const [re, label] of ELEVATION) {
      if (re.test(name)) add('privileged-elevation', `${label} raises privileges`);
    }
    for (const [re, label] of CREDENTIAL_TEXT) {
      if (re.test(segment)) add('credential-access', `${label}`);
    }
    for (const [re, label] of ELEVATION_TEXT) {
      if (re.test(segment)) add('privileged-elevation', `${label} raises privileges`);
    }

    // `git` subcommands that discard work behave like `rm` even though git is benign.
    if (name === 'git') {
      const sub = args.map((a) => a.value);
      if (sub.includes('clean') && sub.some((a) => /^-[a-z]*[fd]/i.test(a))) {
        add('destructive-filesystem', '`git clean` deletes untracked files');
      }
      if (sub.includes('reset') && sub.includes('--hard')) {
        add('destructive-filesystem', '`git reset --hard` discards uncommitted work');
      }
      if (sub.includes('push') && sub.some((a) => /^(?:-f|--force)$/i.test(a))) {
        add('security-posture', '`git push --force` rewrites shared history');
      }
    }

    // Network: benign on its own, exfiltration when it carries a local file.
    if (NETWORK.test(name)) {
      if (UPLOAD_FLAG.test(segment)) {
        add('network-exfiltration', `${name} would upload a local file`);
      }
      if (/^(?:nc|ncat|netcat|telnet)$/i.test(name)) {
        add('network-exfiltration', `${name} opens a raw network channel`);
      }
      if (/^(?:scp|sftp|rsync)$/i.test(name) && args.some((a) => /@|:/.test(a.value))) {
        add('network-exfiltration', `${name} copies files to a remote host`);
      }
    }

    // Redirecting anything into a shell is download-and-execute regardless of source.
    if (/^(?:sh|bash|zsh|powershell|pwsh|cmd|node|python3?)$/i.test(name) && parsed.chained) {
      const idx = parsed.segments.indexOf(segment);
      const upstream = parsed.segments.slice(0, idx).join(' ');
      if (NETWORK.test(commandName(upstream)) || /https?:\/\//i.test(upstream)) {
        add('network-exfiltration', 'pipes downloaded content into an interpreter');
      }
    }

    // A pipeline that reads a file and then talks to the network is exfiltration
    // even when neither half looks dangerous alone.
    if (parsed.chained && /^(?:cat|type|get-content|gc)$/i.test(name)) {
      const idx = parsed.segments.indexOf(segment);
      const downstream = parsed.segments.slice(idx + 1);
      if (downstream.some((s) => NETWORK.test(commandName(s)))) {
        add('network-exfiltration', 'pipes local file contents to a network command');
      }
      for (const a of args) {
        if (CREDENTIAL_PATH.test(a.value)) add('credential-access', `reads ${a.value}`);
      }
    }

    for (const a of args) {
      if (isPathLike(a.value)) pathsToCheck.push(a.value);
      if (CREDENTIAL_PATH.test(a.value)) add('credential-access', `touches ${a.value}`);
    }
  }

  // Containment. Relative paths resolve against the request's cwd, which is
  // itself checked -- a cwd outside the workspace makes every relative path
  // outside it too.
  const root = opts.workspaceRoot;
  const cwdInside = isInside(root, req.cwd);
  if (!cwdInside) {
    add('outside-workspace', `runs in ${req.cwd}, outside the workspace root`);
  }

  for (const raw of pathsToCheck) {
    if (WINDOWS_SYSTEM_DIR.test(raw)) {
      add('outside-workspace', `touches the system directory ${raw}`);
      continue;
    }
    const f = flavour(raw);
    const absolute = f.isAbsolute(raw) ? raw : f.resolve(req.cwd, raw);
    if (!isInside(root, absolute)) {
      add('outside-workspace', `touches ${raw}, outside the workspace root`);
    }
    for (const protectedPath of opts.protectedPaths ?? []) {
      if (isInside(protectedPath, absolute)) {
        add('credential-access', `touches the protected path ${protectedPath}`);
      }
    }
  }

  return { hardBlocked: reasons.size > 0, reasons: [...reasons], notes };
}

/** Rendered in the UI so "what can never be auto-approved" is inspectable. */
export const HARD_REASON_LABELS: Record<HardReason, string> = {
  'destructive-filesystem': 'Destructive filesystem operation',
  'credential-access': 'Credential or secret access',
  'security-posture': 'Changes security posture',
  'network-exfiltration': 'Could send local data off this machine',
  'privileged-elevation': 'Runs with elevated privileges',
  'outside-workspace': 'Touches something outside the workspace',
  unparseable: 'Effect cannot be determined',
};
