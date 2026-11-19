// main.ts — the standalone bashme app.
//
// Same core as VIOLINET OS, its own database and its own window. The two are
// separate gates on purpose: VIOLINET OS gates its own agent tool loop, this one
// gates whatever else on this machine enrols with it (a CLI, a Claude Code
// session, a script). Sharing one database would mean two processes writing one
// WAL, and the audit log is the table that must not lose rows.
//
// No bundler: Electron 44 runs Node 24, which strips types on import, so the
// core's .ts files load directly. The renderer is plain JS because type
// stripping does not apply in a browser context.

// MUST STAY FIRST. It marks this process as having been launched as the app
// rather than as the library, which core/index.ts checks before refusing to be
// an Electron entry point. See entryMarker.ts for why that check exists.
import './entryMarker.ts';

import { app, BrowserWindow, ipcMain, shell, dialog } from 'electron';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { mkdirSync, appendFileSync, readFileSync, writeFileSync } from 'node:fs';

import { execFile } from 'node:child_process';
import { readClaudeStatus } from './claudeStatus.ts';

import {
  ActionService,
  parseActions,
  Gate,
  RelayTransport,
  newRelaySession,
  OFFICIAL_RELAY_URL,
  SqliteStore,
  previewRule,
  validateRule,
  parseDeviceKey,
  fingerprintOf,
  sendPushPing,
} from '../core/index.ts';
import type { ActionDef, AuditRow, Db, PresentedRequest, RelaySession, Rule } from '../core/index.ts';
import { startIpcServer, mintToken, hashToken, socketPath } from './ipcServer.ts';
import { LanServer } from './lanServer.ts';
import { encodeQr } from './qr.ts';

const here = dirname(fileURLToPath(import.meta.url));

// Set before any getPath('userData') call.
//
// An unpackaged `electron src/app/main.ts` otherwise names itself "Electron"
// and writes to the shared Electron profile, so a dev run and a packaged build
// would quietly use two different databases -- and the audit log would be
// missing exactly the entries someone went looking for.
app.setName('bashme');

let win: BrowserWindow | null = null;
let _store: SqliteStore | null = null;
let _gate: Gate | null = null;
let _lan: LanServer | null = null;
let _relay: RelayTransport | null = null;
let _actions: ActionService | null = null;

function dataDir(): string {
  const dir = app.getPath('userData');
  mkdirSync(dir, { recursive: true });
  return dir;
}

function store(): SqliteStore {
  if (!_store) _store = new SqliteStore(new DatabaseSync(join(dataDir(), 'bashme.db')) as unknown as Db);
  return _store;
}

/**
 * The workspace root for the standalone app.
 *
 * Unlike VIOLINET OS, this app does not own a workspace -- its callers run
 * wherever they run. The root is therefore configurable and defaults to the
 * user's home, which means "outside the workspace" only fires for paths outside
 * the profile entirely. That is a weaker boundary than VIOLINET OS's and the UI
 * says so rather than implying the two are equivalent.
 */
function workspaceRoot(): string {
  const rows = store().readToggles();
  void rows;
  return process.env.BASHME_ROOT?.trim() || app.getPath('home');
}

/**
 * The LAN listener.
 *
 * Constructed lazily and NOT started -- constructing it opens nothing. It only
 * listens after an explicit `lanStart`, which is the point: no code path here
 * can bring a port up as a side effect of something else.
 */
function lan(): LanServer {
  if (_lan) return _lan;
  const s = store();
  _lan = new LanServer({
    listDevices: () => s.listDevices(),
    pairDevice: (label: string, publicKey: string) => {
      const parsed = parseDeviceKey(publicKey);
      if (!parsed.ok) return { ok: false, error: parsed.error };
      const id = `device-${Date.now().toString(36)}`;
      s.pairDevice({
        id,
        label,
        publicKey: parsed.value.publicKey,
        pairedAt: new Date().toISOString(),
      });
      win?.webContents.send('bashme:changed', {});
      return { ok: true, id };
    },
    vapidPublicKey: () => s.vapidKeys().publicKey,
    setPushEndpoint: (deviceId: string, endpoint: string) => s.setPushEndpoint(deviceId, endpoint),
  });

  // An answer off the wire is not trusted here. It goes to the gate, which
  // verifies the signature against the paired key before it counts.
  _lan.onAnswer((answer) => {
    gate().respondDevice({
      requestId: answer.requestId,
      deviceId: answer.deviceId,
      decision: answer.decision,
      signatureBase64: answer.signatureBase64,
    });
  });

  return _lan;
}

/**
 * The relay session, kept on disk.
 *
 * A phone pairs against one session -- the mailbox name and the key are what
 * its browser stored -- so generating a fresh one on every launch would silently
 * unpair every device. This file is the reason relay mode survives a restart.
 *
 * It holds a secret, which is why it lives in userData beside the database
 * rather than anywhere a backup tool would sweep up by default.
 */
function relaySessionFile(): string {
  return join(dataDir(), 'relay-session.json');
}

function loadRelaySession(): RelaySession | null {
  try {
    const parsed = JSON.parse(readFileSync(relaySessionFile(), 'utf8')) as Partial<RelaySession>;
    if (!parsed.relayUrl || !parsed.sessionId || !parsed.key) return null;
    return parsed as RelaySession;
  } catch {
    return null; // absent or unreadable both mean "no session yet"
  }
}

/**
 * Where phone-initiated actions are defined.
 *
 * In userData, next to the database, because editing it is equivalent to
 * granting a remote capability and that should sit with the app's own state
 * rather than in a repo someone might clone. See core/actions.ts for why the
 * file -- and not the phone -- is what bounds this feature.
 */
function actionsFile(): string {
  return join(dataDir(), 'actions.json');
}

function loadActions(): { actions: ActionDef[]; errors: string[] } {
  let text: string;
  try {
    text = readFileSync(actionsFile(), 'utf8');
  } catch {
    return { actions: [], errors: [] }; // no file is not an error; it is the default
  }
  try {
    return parseActions(JSON.parse(text));
  } catch (err) {
    return { actions: [], errors: [err instanceof Error ? err.message : 'actions.json is not valid JSON'] };
  }
}

/**
 * Run one action.
 *
 * `execFile` with a shell, because the definitions are shell one-liners
 * written by the owner -- `schtasks /run /tn VioletNetFix` is the motivating
 * case and it is not an argv the phone composed. Nothing from the phone
 * reaches this string; see actions.ts.
 *
 * A timeout, because an action that hangs must not hold a poll loop, and the
 * phone is owed an answer either way.
 */
function runAction(action: ActionDef): Promise<{ ok: boolean; output: string }> {
  return new Promise((resolve) => {
    execFile(
      action.command,
      {
        shell: true,
        windowsHide: true,
        timeout: 60_000,
        cwd: action.cwd || workspaceRoot(),
        maxBuffer: 1024 * 1024,
      },
      (err, stdout, stderr) => {
        const output = `${stdout ?? ''}${stderr ?? ''}`.trim();
        resolve({
          ok: !err,
          output: output || (err ? err.message : 'Done. The command printed nothing.'),
        });
      },
    );
  });
}

function actions(): ActionService {
  if (_actions) return _actions;
  _actions = new ActionService(
    {
      devices: () => store().listDevices(),
      run: runAction,
      // Actions do not pass through the gate, so they would otherwise leave no
      // trace at all. A separate log, appended to, never rewritten.
      audit: (entry) => {
        try {
          appendFileSync(join(dataDir(), 'actions.log'), `${JSON.stringify(entry)}
`);
        } catch {
          // A log that cannot be written must not stop the action being
          // reported to the phone; the failure is visible in the file's absence.
        }
        win?.webContents.send('bashme:changed', {});
      },
    },
    loadActions().actions,
  );
  return _actions;
}

/**
 * The relay transport.
 *
 * Constructed lazily and NOT started, exactly like the LAN listener: making
 * the object opens nothing and reaches nothing. It only begins polling after
 * an explicit relayStart.
 */
function relay(): RelayTransport {
  if (_relay) return _relay;
  const s = store();
  _relay = new RelayTransport({
    pairDevice: (label: string, publicKey: string) => {
      const parsed = parseDeviceKey(publicKey);
      if (!parsed.ok) return { ok: false, error: parsed.error };
      const id = `device-${Date.now().toString(36)}`;
      s.pairDevice({
        id,
        label,
        publicKey: parsed.value.publicKey,
        pairedAt: new Date().toISOString(),
      });
      win?.webContents.send('bashme:changed', {});
      return { ok: true, id };
    },
    vapidPublicKey: () => s.vapidKeys().publicKey,
    setPushEndpoint: (deviceId: string, endpoint: string) => s.setPushEndpoint(deviceId, endpoint),
    actions: actions(),
    // Read-only, so unlike actions it needs no signature: it shows chat titles and
    // states from the Claude desktop app's own files and nothing else.
    status: () =>
      readClaudeStatus({
        sessionsDir: join(app.getPath('appData'), 'Claude', 'claude-code-sessions'),
        transcriptsDir: join(app.getPath('home'), '.claude', 'projects'),
      }),
  });

  // Same rule as the LAN listener: an answer off the wire is not trusted here.
  // The gate verifies the signature against the paired key before it counts.
  _relay.onAnswer((answer) => {
    gate().respondDevice({
      requestId: answer.requestId,
      deviceId: answer.deviceId,
      decision: answer.decision,
      signatureBase64: answer.signatureBase64,
    });
  });

  return _relay;
}

/** True when some paired phone could still answer, by any transport. */
function phoneReachable(): boolean {
  const anyTransport = _lan?.isAvailable() === true || _relay?.isAvailable() === true;
  return anyTransport && store().listDevices().some((d) => !d.revokedAt);
}

function gate(): Gate {
  if (_gate) return _gate;
  const s = store();
  _gate = new Gate(
    { ...s.readToggles(), workspaceRoot: workspaceRoot(), protectedPaths: [dataDir()] },
    {
      audit: { append: (row: AuditRow) => s.appendAudit(row) },
      rules: { list: () => s.listRules(), recordMatch: (id: string) => s.recordMatch(id) },
      present: (presented: PresentedRequest) => {
        // No window USED TO mean nobody can answer, and throwing made the gate
        // deny immediately rather than making the caller wait out the TTL. That
        // is still right when the window is the only approver -- but a running
        // LAN listener with a paired phone is a second one, so denying on the
        // window alone would now reject requests somebody is about to approve.
        const reachable = phoneReachable();
        if (!win || win.isDestroyed()) {
          if (!reachable) throw new Error('no window');
          return;
        }
        win.webContents.send('approval:request', presented);
        // A request that arrives while the app is in the background is the
        // normal case for a CLI caller, so surface the window rather than
        // waiting for someone to notice.
        if (!win.isVisible()) win.show();
        win.flashFrame(true);
      },
      withdraw: (id: string) => {
        win?.webContents.send('approval:withdraw', { id });
        // Stop offering it to the phone too, or a request settled at the PC
        // stays on screen there until the poll happens to miss it. Both
        // transports, because either may be the one holding it.
        _lan?.withdraw(id);
        _relay?.withdraw(id);
      },
      listDevices: () => s.listDevices(),
      pushToDevices: (presented: PresentedRequest, devices) => {
        // Both, when both are up. A phone that answers on either one settles
        // the request and the other is withdrawn, so this is not two prompts.
        _lan?.push(presented);
        _relay?.push(presented);
        // The Web Push ding, independent of either poll transport: it reaches
        // a device even if its tab is not open, which is the whole point of
        // pairing a second phone or an iPad. Best-effort, never awaited --
        // a dead subscription must never slow down or change the gate.
        for (const device of devices) {
          if (!device.pushEndpoint) continue;
          sendPushPing({ endpoint: device.pushEndpoint }, s.vapidKeys(), 'https://github.com/Violinet-tech/bashme')
            .then((res) => {
              if (res.gone) s.setPushEndpoint(device.id, '');
            })
            .catch(() => {
              /* a dead push endpoint must not affect the decision */
            });
        }
      },
    },
  );
  return _gate;
}

function createWindow(): void {
  win = new BrowserWindow({
    width: 940,
    height: 760,
    show: false,
    // Matches --bg in app.css. It was left at the old dark purple after the
    // palette was inverted, which showed as a dark flash before first paint.
    backgroundColor: '#ECE8F6',
    title: 'bashme',
    webPreferences: {
      preload: join(here, 'preload.cjs'),
      // A sandboxed renderer cannot load an ESM preload, and it fails silently:
      // the window opens and `window.bashme` is simply never defined. The
      // preload is .cjs for exactly this reason -- the two settings are one
      // decision, learned the hard way in violet-dev.
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
      webviewTag: false,
    },
  });

  win.once('ready-to-show', () => win?.show());
  void win.loadFile(join(here, 'renderer', 'index.html'));

  // Nothing in this app should navigate anywhere. A gate that can be steered to
  // a remote page is a gate with a rendering engine pointed at an attacker.
  win.webContents.on('will-navigate', (e) => e.preventDefault());
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:\/\//i.test(url)) void shell.openExternal(url);
    return { action: 'deny' };
  });

  win.on('closed', () => {
    // Deny anything outstanding, unless a paired phone can still answer. The
    // rule is "no approver means fail closed", not "no window means fail
    // closed" -- and with the LAN listener up those stopped being the same
    // statement.
    const reachable = _lan?.isAvailable() === true && store().listDevices().some((d) => !d.revokedAt);
    if (!reachable) _gate?.denyAll();
    win = null;
  });
}

// --- renderer surface -------------------------------------------------------

function status(): Record<string, unknown> {
  const g = gate();
  const s = store();
  return {
    ...s.readToggles(),
    workspaceRoot: g.config.workspaceRoot,
    pending: g.listPending().length,
    ruleCount: s.listRules().length,
    clientCount: s.listClients().filter((c) => !c.revokedAt).length,
    deviceCount: s.listDevices().filter((d) => !d.revokedAt).length,
    socketPath: socketPath(),
    lan: _lan ? _lan.status() : { running: false, available: [] },
    relay: relayStatus(),
  };
}

/**
 * The relay's status, with the pairing URL rendered as a scannable matrix.
 *
 * The QR is built here rather than in core/relay.ts because core has no
 * business knowing how its status will be drawn -- and because VIOLINET OS,
 * which imports core, will want to draw it differently.
 */
function relayStatus(): Record<string, unknown> {
  const saved = loadRelaySession();
  const base = _relay
    ? _relay.status()
    : {
        running: false,
        relayUrl: saved?.relayUrl ?? null,
        sessionId: saved?.sessionId ?? null,
        enrollCode: null,
        enrollExpiresAt: null,
        pairingUrl: null,
        lastError: null,
      };
  return {
    ...base,
    pairingQr: base.pairingUrl ? encodeQr(base.pairingUrl) : null,
    // Offered to the UI so it can put up a one-tap fill. It is a suggestion
    // the user has to accept, never a value anything starts with.
    officialRelayUrl: OFFICIAL_RELAY_URL,
  };
}

function registerIpc(): void {
  ipcMain.handle('status', () => status());

  // --- LAN listener ---------------------------------------------------------
  //
  // Four separate calls rather than one toggle, because "start listening on a
  // network interface" and "open a five-minute window in which a new device can
  // pair" are different grants and should not be spendable by one click.
  ipcMain.handle('lanStatus', () => lan().status());
  ipcMain.handle('lanStart', async (_e, address: string, port?: number) => {
    try {
      const s = await lan().start(String(address), Number(port) || 8787);
      win?.webContents.send('bashme:changed', {});
      return { ok: true, status: s };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : 'could not start' };
    }
  });
  ipcMain.handle('lanStop', async () => {
    await lan().stopAsync();
    win?.webContents.send('bashme:changed', {});
    return { ok: true, status: lan().status() };
  });
  ipcMain.handle('lanEnroll', () => {
    if (!lan().isAvailable()) return { ok: false, error: 'The listener is not running.' };
    return { ok: true, ...lan().openEnrollment() };
  });
  ipcMain.handle('lanCloseEnrollment', () => {
    lan().closeEnrollment();
    return { ok: true };
  });
  // --- relay ----------------------------------------------------------------
  //
  // Split the same way as the LAN calls: starting the transport and opening a
  // pairing window are different grants. The relay URL is asked for rather
  // than defaulted, because the whole security argument rests on the user
  // knowing which host they pointed this at.
  ipcMain.handle('relayStatus', () => relayStatus());
  ipcMain.handle('relayStart', async (_e, relayUrl?: string) => {
    const wanted = String(relayUrl ?? '').trim();
    const saved = loadRelaySession();
    try {
      // Reuse the stored session when the host has not changed. A new session
      // is a new mailbox and a new key, which unpairs every phone.
      const session =
        saved && (!wanted || saved.relayUrl === wanted.replace(/\/+$/, ''))
          ? saved
          : newRelaySession(wanted);
      if (!/^https?:\/\//.test(session.relayUrl)) {
        return { ok: false, error: 'Give the relay URL, e.g. https://bashme-relay.you.workers.dev' };
      }
      await relay().start(session);
      writeFileSync(relaySessionFile(), JSON.stringify(session, null, 2), { mode: 0o600 });
      win?.webContents.send('bashme:changed', {});
      return { ok: true, status: relayStatus() };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : 'could not reach the relay' };
    }
  });
  ipcMain.handle('relayStop', () => {
    relay().stop();
    win?.webContents.send('bashme:changed', {});
    return { ok: true, status: relayStatus() };
  });
  ipcMain.handle('relayEnroll', () => {
    if (!relay().isAvailable()) return { ok: false, error: 'Relay mode is not running.' };
    return { ok: true, ...relay().openEnrollment() };
  });
  // --- phone-initiated actions ---------------------------------------------

  ipcMain.handle('actionsGet', () => {
    const loaded = loadActions();
    actions().replace(loaded.actions);
    return { ...loaded, path: actionsFile() };
  });

  /**
   * Write the two actions this machine actually has a use for.
   *
   * A local click is the consent. The file is never seeded automatically,
   * because a capability that appears without anyone asking for it is the
   * thing actions.ts exists to prevent -- and `schtasks /run` in particular
   * is hard-blocked everywhere else in this app.
   */
  ipcMain.handle('actionsSeedExamples', () => {
    const existing = loadActions().actions;
    const examples: ActionDef[] = [
      {
        id: 'netfix',
        label: 'Fix the network',
        description: 'Runs the VioletNetFix scheduled task, which resets the Wi-Fi adapter.',
        command: 'schtasks /run /tn VioletNetFix',
      },
      {
        id: 'launch-claude',
        label: 'Launch Claude Code',
        description: 'Opens a Claude Code session in the workspace root.',
        command: 'start "" cmd /c claude',
      },
    ];
    const merged = [...existing, ...examples.filter((e) => !existing.some((a) => a.id === e.id))];
    writeFileSync(actionsFile(), JSON.stringify({ actions: merged }, null, 2), { mode: 0o600 });
    actions().replace(merged);
    return { ok: true, count: merged.length };
  });

  ipcMain.handle('actionsOpenFile', async () => {
    try {
      readFileSync(actionsFile());
    } catch {
      writeFileSync(actionsFile(), JSON.stringify({ actions: [] }, null, 2), { mode: 0o600 });
    }
    await shell.openPath(actionsFile());
    return { ok: true };
  });

  ipcMain.handle('relayCloseEnrollment', () => {
    relay().closeEnrollment();
    return { ok: true };
  });

  ipcMain.handle('setToggle', (_e, key: string, value: boolean) => {
    if (key !== 'enabled' && key !== 'rulesEnabled' && key !== 'devicesEnabled') return status();
    store().writeToggle(key, value === true);
    gate().setConfig({ [key]: value === true });
    return status();
  });

  ipcMain.handle('listRules', () => store().listRules());
  ipcMain.handle('saveRule', (_e, rule: Rule) => {
    const errors = validateRule(rule);
    if (errors.length) return { ok: false, errors };
    store().upsertRule(rule);
    return { ok: true };
  });
  ipcMain.handle('previewRule', (_e, rule: Rule) =>
    previewRule(rule, store().recentAudit(200), {
      workspaceRoot: gate().config.workspaceRoot,
      protectedPaths: [dataDir()],
    }),
  );
  ipcMain.handle('setRuleEnabled', (_e, id: string, enabled: boolean) =>
    store().setRuleEnabled(id, enabled === true),
  );
  ipcMain.handle('deleteRule', (_e, id: string) => store().deleteRule(id));
  ipcMain.handle('listOriginators', () => store().listOriginators());
  ipcMain.handle('recentAudit', (_e, limit?: number) => store().recentAudit(limit));

  // Pairing is two steps on purpose. The first only parses, so the fingerprint
  // can be compared against the device BEFORE anything is stored -- the risk in
  // a pasted key is not eavesdropping, it is pasting the wrong one.
  ipcMain.handle('previewDeviceKey', (_e, pasted: string) => {
    const parsed = parseDeviceKey(pasted);
    return parsed.ok
      ? { ok: true, fingerprint: parsed.value.fingerprint, publicKey: parsed.value.publicKey }
      : { ok: false, error: parsed.error };
  });
  ipcMain.handle('pairDevice', (_e, label: string, pasted: string) => {
    const parsed = parseDeviceKey(pasted);
    if (!parsed.ok) return { ok: false, error: parsed.error };
    const id = `device:${label.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 32) || 'unnamed'}-${Date.now()
      .toString(36)
      .slice(-4)}`;
    store().pairDevice({
      id,
      label: label.trim() || 'Unnamed device',
      publicKey: parsed.value.publicKey,
      pairedAt: new Date().toISOString(),
    });
    return { ok: true, id, fingerprint: parsed.value.fingerprint };
  });
  ipcMain.handle('listDevices', () =>
    store()
      .listDevices()
      .map((d) => ({ ...d, fingerprint: fingerprintOf(d.publicKey) })),
  );
  ipcMain.handle('revokeDevice', (_e, id: string) => store().revokeDevice(id));

  ipcMain.handle('listClients', () => store().listClients());
  ipcMain.handle('addClient', (_e, label: string) => {
    const token = mintToken();
    const id = `client:${label.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 32) || 'unnamed'}-${Date.now()
      .toString(36)
      .slice(-4)}`;
    store().addClient({ id, label: label.trim() || 'Unnamed', tokenSha256: hashToken(token) });
    // The plaintext token is returned exactly once and never stored.
    return { id, token };
  });
  ipcMain.handle('revokeClient', (_e, id: string) => store().revokeClient(id));

  ipcMain.handle('respond', (_e, id: string, approved: boolean, confirmToken: string) =>
    gate().respondLocal(id, approved === true, confirmToken),
  );
  ipcMain.handle('approveByKeyword', () => gate().respondKeyword());
  ipcMain.handle('pending', () => gate().listPending());
}

// One instance: two gates on one database would race, and two windows would
// mean a request rendered in one and answered in neither.
if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (win) {
      if (win.isMinimized()) win.restore();
      win.focus();
    }
  });

  void app
    .whenReady()
    .then(() => {
      registerIpc();
      createWindow();
      const ipc = startIpcServer({ gate, store });
      app.on('before-quit', () => {
        ipc.close();
        _relay?.stop();
        _gate?.denyAll();
      });
    })
    // Without this, a throw in here vanishes: the promise rejects, `void`
    // discards it, and the process stays alive with no window and an empty
    // log -- which is indistinguishable from the app simply not launching.
    // That cost a session. Startup failure must be loud.
    .catch((err: unknown) => {
      const detail = err instanceof Error ? (err.stack ?? err.message) : String(err);
      try {
        appendFileSync(join(app.getPath('userData'), 'startup-error.log'), `${new Date().toISOString()}
${detail}
`);
      } catch {
        // The log is a convenience; the dialog below is the part that matters.
      }
      dialog.showErrorBox('bashme failed to start', detail);
      app.exit(1);
    });

  app.on('window-all-closed', () => app.quit());
}
