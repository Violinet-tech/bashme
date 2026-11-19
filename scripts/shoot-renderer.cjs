// shoot-renderer.cjs — photograph the real window, without a consent dialog.
//
// This exists because readability is a question only a picture answers, and the
// two obvious ways to get one were both closed: a desktop screenshot needs a
// permission dialog someone has to click, and a hand-written mock-up of the
// markup answers the question about the wrong UI.
//
// So the app photographs itself. It loads the real index.html, which pulls in
// the real app.css and the real renderer.js; only `window.bashme` is replaced,
// by shoot-preload.cjs. What lands in the PNG is the actual renderer against
// known data.
//
//   node_modules/.bin/electron scripts/shoot-renderer.cjs [outDir]
//
// Four things here are load-bearing, each one a failure this already hit:
//
//   * CommonJS, not ESM. An .mjs main entry hung before the first line of
//     output with no error on either stream, which is close to undiagnosable.
//   * The window is shown, parked far off the desktop. Hiding it is the obvious
//     choice and the wrong one: Chromium throttles a window it believes nobody
//     is looking at, requestAnimationFrame never fires, and both the settle
//     step and capturePage wait forever.
//   * Progress is written to a log FILE. A packaged Electron process on Windows
//     has no console attached, so console.log goes nowhere and a hang looks
//     identical to a crash.
//   * Every await is bounded. An unbounded one here produces a silent hang
//     rather than a failure, and a silent hang cannot be told from success.

const { app, BrowserWindow } = require('electron');
const { writeFileSync, mkdirSync, appendFileSync } = require('node:fs');
const { join, resolve } = require('node:path');

const OUT = resolve(process.argv[2] ?? join(__dirname, '..', 'shots'));
const LOG = join(OUT, 'shoot.log');
const TABS = ['requests', 'rules', 'clients', 'devices', 'settings'];

const WIDTH = 1180;
const HEIGHT = 1500;

mkdirSync(OUT, { recursive: true });
writeFileSync(LOG, `shoot started ${new Date().toISOString()}\n`);
const log = (line) => {
  appendFileSync(LOG, `${line}\n`);
  console.log(line);
};

// `within` rethrows after calling this, and the rethrow lands on
// unhandledRejection, which calls it again -- so without the latch a single
// failure runs the exit path twice. The second pass is the one that used to
// leave Electron's GPU and network-service helpers behind, because app.exit
// had already torn down the main process's own bookkeeping.
let dying = false;
const die = (where, err) => {
  if (dying) return;
  dying = true;
  log(`FAILED at ${where}: ${err && err.stack ? err.stack : err}`);
  // Close the windows first. app.exit() skips every 'close' handler, and a
  // BrowserWindow still open at that point keeps its renderer alive as an
  // orphan with no parent to reap it.
  for (const w of BrowserWindow.getAllWindows()) w.destroy();
  app.exit(1);
};

process.on('uncaughtException', (err) => die('uncaughtException', err));
process.on('unhandledRejection', (err) => die('unhandledRejection', err));

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Anything that can hang gets a deadline, so a stall reports itself.
const within = (ms, where, promise) =>
  Promise.race([
    promise,
    sleep(ms).then(() => {
      throw new Error(`timed out after ${ms}ms`);
    }),
  ]).catch((err) => {
    die(where, err);
    throw err;
  });

app.setPath('userData', join(app.getPath('temp'), 'bashme-shoot'));
// NOT disabled: software compositing made capturePage return a uniformly
// darkened frame (white text came back at 0.30 of its value), which reads as
// "the UI is too dark" and is not.
// app.disableHardwareAcceleration();

app.whenReady().then(async () => {
  log('ready');

  const win = new BrowserWindow({
    width: WIDTH,
    height: HEIGHT,
    x: -32000,
    y: -32000,
    show: true,
    focusable: false,
    skipTaskbar: true,
    backgroundColor: '#150e28',
    webPreferences: {
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
      preload: join(__dirname, 'shoot-preload.cjs'),
    },
  });

  win.webContents.on('console-message', (_e, _level, message) => {
    log(`renderer: ${message}`);
  });
  win.webContents.on('preload-error', (_e, path, err) => {
    log(`preload-error in ${path}: ${err && err.message}`);
  });

  const page = join(__dirname, '..', 'src', 'app', 'renderer', 'index.html');
  await within(20000, 'loadFile', win.loadFile(page));
  log('loaded');

  // The renderer fills every tab from an async refresh(), so the first paint is
  // an empty shell. This waits for the data to land rather than for a frame.
  await sleep(1200);

  // Report what the page actually computed, not what app.css says. A PNG can be
  // darkened in capture by colour management, so the image alone cannot settle
  // whether the palette loaded — but these values can.
  const computed = await within(
    10000,
    'read computed colours',
    win.webContents.executeJavaScript(`(() => {
      const root = getComputedStyle(document.documentElement);
      const blurb = document.querySelector('.blurb');
      return {
        stylesheets: document.styleSheets.length,
        bg: root.getPropertyValue('--bg').trim(),
        panel: root.getPropertyValue('--panel').trim(),
        inkFaint: root.getPropertyValue('--ink-faint').trim(),
        blurbColor: blurb ? getComputedStyle(blurb).color : 'no .blurb found',
        panelBg: (() => {
          const el = document.querySelector('.panel');
          return el ? getComputedStyle(el).backgroundColor : 'no .panel found';
        })(),
        blurbSize: blurb ? getComputedStyle(blurb).fontSize : 'n/a',
      };
    })()`),
  );
  log(`computed: ${JSON.stringify(computed)}`);

  for (const tab of TABS) {
    // Click the real tab button rather than toggling classes by hand, so the
    // photograph goes through the same path a person would.
    await within(
      10000,
      `select ${tab}`,
      win.webContents.executeJavaScript(
        `document.querySelector('#tabs button[data-tab="${tab}"]').click(), true`,
      ),
    );
    await sleep(400);

    const image = await within(20000, `capture ${tab}`, win.webContents.capturePage());
    const file = join(OUT, `${tab}.png`);
    writeFileSync(file, image.toPNG());
    log(`wrote ${file} (${image.getSize().width}x${image.getSize().height})`);
  }

  log(`done — ${TABS.length} shots in ${OUT}`);
  app.quit();
});
