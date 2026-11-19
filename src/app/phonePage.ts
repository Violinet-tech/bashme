// phonePage.ts — the page the phone loads. One file, no build step, no assets.
//
// It is a string rather than a file on disk because it is served by the LAN
// listener and nothing else ever reads it; keeping it inline means there is no
// second path from which the listener could be made to serve something.
//
// The phone's private key is generated HERE and never leaves the device:
// generateKey is called with extractable=false, so the browser will not hand
// the key material back even to this page's own code, and only the public key
// is ever sent to the PC. That is the whole reason the listener has to speak
// TLS — WebCrypto is unavailable outside a secure context, and without it the
// alternative is generating the key on the PC and shipping the private half
// over the network, which would be worse than not having a phone at all.
//
// The key is stored in IndexedDB as a live CryptoKey object. localStorage would
// mean serialising it, which cannot be done to a non-extractable key and should
// not be done to an extractable one.

export const PHONE_PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#150e28">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<link rel="manifest" href="/manifest.webmanifest">
<title>bashme</title>
<style>
:root {
  --bg: #150e28; --panel: #241a42; --line: rgba(255,255,255,0.18);
  --ink: #f4f1fc; --ink-dim: #d3cbe8; --ink-faint: #b3a8cf;
  --accent: #cdb4ff; --danger: #ff8a8a; --warn: #ffd075;
  color-scheme: dark;
}
* { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
body {
  margin: 0; padding: 16px; background: var(--bg); color: var(--ink);
  font: 16px/1.5 -apple-system, "Segoe UI", system-ui, sans-serif;
}
h1 { font-size: 13px; letter-spacing: .3em; text-transform: uppercase; color: var(--ink-faint); margin: 0 0 16px; }
.panel { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 16px; margin-bottom: 14px; }
.blurb { color: var(--ink-faint); font-size: 14px; margin: 8px 0 0; }
.mono { font-family: ui-monospace, Consolas, monospace; word-break: break-all; }
pre { background: rgba(0,0,0,.45); border-radius: 6px; padding: 12px; margin: 10px 0 0; white-space: pre-wrap; word-break: break-all; font-size: 14px; }
label { display: block; margin-bottom: 14px; }
label span { display: block; font-size: 14px; color: var(--ink-dim); margin-bottom: 6px; }
input {
  width: 100%; background: rgba(0,0,0,.4); border: 1px solid var(--line);
  border-radius: 6px; color: var(--ink); font: inherit; padding: 12px;
}
button {
  background: transparent; border: 1px solid var(--line); border-radius: 8px;
  color: var(--ink); font: inherit; padding: 14px 18px; cursor: pointer; min-height: 48px;
}
button.primary { background: var(--accent); border-color: var(--accent); color: #1a1030; }
button.danger { border-color: rgba(255,138,138,.55); color: #ffd4d4; }
button:disabled { opacity: .45; }
.actions { display: flex; gap: 10px; margin-top: 16px; }
.actions button { flex: 1; }
.warnbox { background: rgba(255,200,87,.1); border: 1px solid rgba(255,200,87,.4); border-radius: 6px; padding: 12px; margin-top: 12px; }
.warnbox .k { color: var(--warn); font-size: 12px; letter-spacing: .2em; text-transform: uppercase; }
.errbox { background: rgba(255,107,107,.1); border: 1px solid rgba(255,107,107,.4); border-radius: 6px; padding: 12px; margin-top: 12px; font-size: 14px; }
.hidden { display: none; }
ul { margin: 8px 0 0; padding-left: 20px; } li { font-size: 14px; }
.statushead { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
.pill { font-size: 12px; letter-spacing: .08em; text-transform: uppercase; border-radius: 999px; padding: 3px 10px; border: 1px solid var(--line); color: var(--ink-dim); white-space: nowrap; }
.pill.on { border-color: rgba(120,230,170,.6); color: #b9f5d4; }
.pill.working { border-color: rgba(205,180,255,.7); color: var(--accent); }
.pill.needs-you { border-color: rgba(255,208,117,.7); color: var(--warn); }
.pill.review { border-color: rgba(125,200,255,.6); color: #bfe3ff; }
.chat { padding: 10px 0; border-top: 1px solid var(--line); }
.chat:first-of-type { border-top: 0; }
.chat .t { font-size: 15px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.chat .m { display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-top: 4px; }
</style>
</head>
<body>
<h1>bashme</h1>
<div id="app"></div>
<script>
const REASONS = {
  'destructive-filesystem': 'Destructive filesystem operation',
  'credential-access': 'Credential or secret access',
  'security-posture': 'Changes security posture',
  'network-exfiltration': 'Could send local data off that machine',
  'privileged-elevation': 'Runs with elevated privileges',
  'outside-workspace': 'Touches something outside the workspace',
  'unparseable': 'Effect cannot be determined'
};

const app = document.getElementById('app');
let deviceId = localStorage.getItem('bashme.deviceId');
let signingKey = null;
let polling = null;
let showing = null;

function el(tag, opts, kids) {
  const n = document.createElement(tag);
  if (opts && opts.class) n.className = opts.class;
  if (opts && opts.text !== undefined) n.textContent = String(opts.text);
  if (opts && opts.type) n.type = opts.type;
  if (opts && opts.value !== undefined) n.value = opts.value;
  if (opts && opts.placeholder) n.placeholder = opts.placeholder;
  if (opts && opts.inputmode) n.inputMode = opts.inputmode;
  if (opts && opts.onClick) n.addEventListener('click', opts.onClick);
  for (const k of kids || []) if (k) n.appendChild(k);
  return n;
}
function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); }

// --- key storage ------------------------------------------------------------
// IndexedDB holds the live CryptoKey. A non-extractable key cannot be
// serialised, which is the point: nothing here can read the private half.

function db() {
  return new Promise((res, rej) => {
    const open = indexedDB.open('bashme', 1);
    open.onupgradeneeded = () => open.result.createObjectStore('keys');
    open.onsuccess = () => res(open.result);
    open.onerror = () => rej(open.error);
  });
}
async function putKey(key) {
  const d = await db();
  return new Promise((res, rej) => {
    const tx = d.transaction('keys', 'readwrite');
    tx.objectStore('keys').put(key, 'signing');
    tx.oncomplete = res; tx.onerror = () => rej(tx.error);
  });
}
async function getKey() {
  const d = await db();
  return new Promise((res) => {
    const tx = d.transaction('keys', 'readonly');
    const q = tx.objectStore('keys').get('signing');
    q.onsuccess = () => res(q.result || null);
    q.onerror = () => res(null);
  });
}

const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (text) => Uint8Array.from(atob(text), (c) => c.charCodeAt(0));

// --- push notifications -------------------------------------------------------
//
// Best-effort and silent on failure: a phone with notifications denied, an
// unsupported browser, or a service-worker registration that fails must still
// be able to approve requests by having the page open, which is the original
// and still-primary path. This only adds the "ding" on top.

async function setupPush() {
  try {
    if (!('serviceWorker' in navigator) || !('PushManager' in window)) return;
    const reg = await navigator.serviceWorker.register('/sw.js');
    const key = await link.vapidKey();
    if (!key) return;
    const perm = await Notification.requestPermission();
    if (perm !== 'granted') return;
    let sub = await reg.pushManager.getSubscription();
    if (!sub) {
      sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: unb64(key.replace(/-/g, '+').replace(/_/g, '/')) });
    }
    await link.subscribe(deviceId, sub.endpoint);
  } catch (err) {
    // No path here should ever block approving; this is a convenience.
  }
}

// --- how this page reaches the PC -------------------------------------------
//
// Two transports, one page. On a LAN the PC is serving this file and every
// call is same-origin. Through a relay the PC is unreachable, so both ends
// dial out to a forwarder and this page talks to a mailbox instead.
//
// The relay's key arrives in the URL FRAGMENT, which browsers never send to
// the server. That is the whole reason relay mode can use a host it does not
// trust with the contents: the forwarder sees an opaque blob and a session id.
// It is stored afterwards because a reload would otherwise need a fresh scan,
// and the fragment is cleared from the address bar either way.

const RELAY_STORE = 'bashme.relay';

function lanLink() {
  const post = (path, body) => fetch(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body)
  }).then((r) => r.json());

  return {
    mode: 'lan',
    enroll: (body) => post('/api/enroll', body),
    answer: (body) => post('/api/answer', body),
    pending: (id) => fetch('/api/pending?deviceId=' + encodeURIComponent(id)).then((r) => r.json()),
    // Actions are relay-only for now. The LAN listener would have to grow an
    // inbound route for them, and that route is the one thing SECURITY.md
    // spends the most words on -- so it stays unbuilt until it is wanted.
    actions: () => Promise.resolve({ ok: true, actions: [], nonce: '' }),
    // Status is relay-only too, for the same reason: no new inbound route.
    status: () => Promise.resolve({ ok: true, status: null }),
    invoke: () => Promise.resolve({ ok: false, error: 'Actions need relay mode.' }),
    vapidKey: () => fetch('/api/vapid-key').then((r) => r.json()).then((j) => j.key),
    subscribe: (deviceId, endpoint) => post('/api/subscribe', { deviceId, endpoint })
  };
}

function relayLink(session, rawKey, storedVapidKey) {
  const base = location.origin + '/s/' + session + '/';
  let aes = null;
  const requests = new Map();
  const waiting = new Map();

  const key = async () => {
    if (!aes) aes = await crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    return aes;
  };

  // A fresh 12-byte nonce per message, carried in front of the ciphertext.
  // Reusing one under AES-GCM loses both confidentiality and integrity, so it
  // is generated here and never derived from anything.
  async function send(message) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = new TextEncoder().encode(JSON.stringify(message));
    const sealed = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await key(), data);
    const body = new Uint8Array(12 + sealed.byteLength);
    body.set(iv, 0);
    body.set(new Uint8Array(sealed), 12);
    await fetch(base + 'pc', { method: 'POST', body });
  }

  async function receive() {
    let payload;
    try {
      payload = await fetch(base + 'phone').then((r) => r.json());
    } catch (err) {
      return; // a dropped poll on a phone is ordinary; the next one recovers
    }
    for (const text of payload.messages || []) {
      let message;
      try {
        const raw = unb64(text);
        const plain = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: raw.slice(0, 12) }, await key(), raw.slice(12)
        );
        message = JSON.parse(new TextDecoder().decode(plain));
      } catch (err) {
        // Anything that does not decrypt was not written by the paired PC.
        // The relay is allowed to be hostile; this is what that looks like.
        continue;
      }
      if (message.t === 'request') requests.set(message.request.id, message.request);
      else if (message.t === 'withdraw') requests.delete(message.id);
      else if (message.rid && waiting.has(message.rid)) {
        waiting.get(message.rid)(message);
        waiting.delete(message.rid);
      }
    }
  }

  // Request and reply, over a pipe with no notion of either.
  async function call(message, timeoutMs) {
    const rid = b64(crypto.getRandomValues(new Uint8Array(9)));
    const reply = new Promise((resolve) => waiting.set(rid, resolve));
    await send(Object.assign({ rid }, message));
    const deadline = Date.now() + (timeoutMs || 25000);
    while (Date.now() < deadline) {
      await receive();
      const settled = await Promise.race([reply, new Promise((r) => setTimeout(() => r(null), 900))]);
      if (settled) return settled;
    }
    waiting.delete(rid);
    return { ok: false, error: 'The PC did not answer. Check bashme is open and relay mode is on.' };
  }

  let lastVapidKey = storedVapidKey || null;

  return {
    mode: 'relay',
    enroll: async (body) => {
      const res = await call({ t: 'enroll', body });
      if (res && res.vapidKey) {
        lastVapidKey = res.vapidKey;
        try {
          const saved = JSON.parse(localStorage.getItem(RELAY_STORE) || 'null') || { s: session };
          saved.vk = res.vapidKey;
          localStorage.setItem(RELAY_STORE, JSON.stringify(saved));
        } catch (err) { /* private mode */ }
      }
      return res;
    },
    // Fire and forget: the PC verifies the signature and there is nothing
    // useful to say back that the next poll does not already show.
    answer: (body) => send({ t: 'answer', body }),
    pending: async () => {
      await receive();
      return { requests: [...requests.values()] };
    },
    drop: (id) => requests.delete(id),
    actions: () => call({ t: 'actions?' }),
    status: () => call({ t: 'status?' }, 15000),
    invoke: (body) => call({ t: 'action', body }, 70000),
    vapidKey: () => Promise.resolve(lastVapidKey),
    // Fire and forget, same reasoning as answer: nothing useful to say back.
    subscribe: (deviceId, endpoint) => send({ t: 'subscribe', body: { deviceId, endpoint } })
  };
}

const link = (() => {
  const fromHash = new URLSearchParams(location.hash.slice(1));
  let session = fromHash.get('s');
  let keyText = fromHash.get('k');
  let vapidKey = null;
  if (session && keyText) {
    try { localStorage.setItem(RELAY_STORE, JSON.stringify({ s: session, k: keyText })); } catch (err) { /* private mode */ }
    // The enrolment code rides along in the same fragment so a scan fills the
    // field. sessionStorage rather than localStorage: it is single-use and
    // expires in five minutes, so it has no business outliving the tab.
    const scannedCode = fromHash.get('c');
    if (/^[0-9]{6}$/.test(scannedCode || '')) {
      try { sessionStorage.setItem('bashme.code', scannedCode); } catch (err) { /* private mode */ }
    }
    history.replaceState(null, '', location.pathname);
  } else {
    try {
      const saved = JSON.parse(localStorage.getItem(RELAY_STORE) || 'null');
      if (saved) { session = saved.s; keyText = saved.k; vapidKey = saved.vk || null; }
    } catch (err) { /* nothing stored */ }
  }
  if (!session || !keyText) return lanLink();
  return relayLink(session, unb64(keyText.replace(/-/g, '+').replace(/_/g, '/')), vapidKey);
})();


// --- screens ----------------------------------------------------------------

function renderUnsupported(why) {
  clear(app);
  app.appendChild(el('div', { class: 'panel' }, [
    el('div', { text: 'This browser cannot be used' }),
    el('p', { class: 'blurb', text: why })
  ]));
}

function renderEnroll(error) {
  clear(app);
  const label = el('input', { placeholder: 'Phone' });
  const code = el('input', { placeholder: '000000', inputmode: 'numeric' });
  const go = el('button', { class: 'primary', text: 'Pair this phone' });

  // A scanned QR arrives as ?code=NNNNNN, so the field is already filled and
  // the digits below the code on the PC are only the fallback. Six digits or
  // nothing: a query string is attacker-controllable in general, and while a
  // wrong code here only fails to pair, there is no reason to put anything
  // else into the field. The code is stripped from the address bar afterwards
  // so a screenshot or a shared tab does not carry a live enrollment code.
  const scanned = /^[0-9]{6}$/.exec(
    new URLSearchParams(location.search).get('code') || sessionStorage.getItem('bashme.code') || ''
  );
  if (scanned) {
    code.value = scanned[0];
    history.replaceState(null, '', location.pathname);
  }

  go.addEventListener('click', async () => {
    go.disabled = true;
    try {
      const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
      const spki = await crypto.subtle.exportKey('spki', pair.publicKey);
      const res = await link.enroll({ code: code.value.trim(), label: label.value.trim() || 'Phone', publicKey: b64(spki) });
      if (!res.ok) { renderEnroll(res.error || 'Pairing failed.'); return; }
      await putKey(pair.privateKey);
      deviceId = res.deviceId;
      localStorage.setItem('bashme.deviceId', deviceId);
      signingKey = pair.privateKey;
      start();
    } catch (err) {
      renderEnroll('Could not generate a key on this device: ' + err.message);
    }
  });

  app.appendChild(el('div', { class: 'panel' }, [
    el('div', { text: 'Pair this phone' }),
    el('p', { class: 'blurb', text: 'Scan the QR that bashme shows on the PC, or type the six digits under it. The signing key is created here and never leaves this phone.' }),
    el('label', {}, [el('span', { text: 'Name for this phone' }), label]),
    el('label', {}, [el('span', { text: 'Code from the PC' }), code]),
    error ? el('div', { class: 'errbox', text: error }) : null,
    el('div', { class: 'actions' }, [go])
  ]));
}

function renderIdle() {
  clear(app);
  renderStatus();
  app.appendChild(el('div', { class: 'panel' }, [
    el('div', { text: 'Waiting' }),
    el('p', { class: 'blurb', text: 'Nothing is waiting for approval. This page checks every couple of seconds — leave it open.' }),
    el('p', { class: 'blurb mono', text: 'paired as ' + deviceId })
  ]));
  renderActions();
}

var STATE_LABEL = { 'working': 'Working', 'needs-you': 'Needs you', 'review': 'Ready to review', 'done': 'Done', 'idle': 'Idle' };

function ago(seconds) {
  if (seconds < 90) return seconds + 's ago';
  if (seconds < 5400) return Math.round(seconds / 60) + ' min ago';
  if (seconds < 172800) return Math.round(seconds / 3600) + ' h ago';
  return Math.round(seconds / 86400) + ' d ago';
}

/**
 * The Claude panel: is the desktop app open, and what is each chat doing.
 *
 * Read-only. It shows titles and one-word states the PC chose to send, and nothing
 * on this page can act on a chat. It refreshes itself while it is on screen and
 * stops the moment it is not, so a request that takes over the page does not leave
 * a timer polling behind it.
 */
var statusTimer = null;
function renderStatus() {
  if (statusTimer) clearInterval(statusTimer);
  var panel = el('div', { class: 'panel' }, [el('div', { text: 'Claude' }), el('p', { class: 'blurb', text: 'Checking…' })]);
  app.appendChild(panel);

  async function refresh() {
    if (!document.body.contains(panel) || showing) { clearInterval(statusTimer); statusTimer = null; return; }
    var res = null;
    try { res = await link.status(); } catch (err) { res = null; }
    if (!document.body.contains(panel)) return;
    clear(panel);
    var st = res && res.ok ? res.status : null;
    if (!st) {
      panel.appendChild(el('div', { text: 'Claude' }));
      panel.appendChild(el('p', {
        class: 'blurb',
        text: res && res.ok === false
          ? (res.error || 'Status is not available right now.')
          : 'Status needs relay mode and a PC that shares it.'
      }));
      return;
    }
    panel.appendChild(el('div', { class: 'statushead' }, [
      el('div', { text: st.app.name + ' desktop app' }),
      el('span', { class: 'pill' + (st.app.running ? ' on' : ''), text: st.app.running ? 'Open' : 'Closed' })
    ]));
    if (!st.chats.length) {
      panel.appendChild(el('p', { class: 'blurb', text: 'No recent chats.' }));
      return;
    }
    st.chats.forEach(function (c) {
      var meta = [ago(c.ageSeconds), c.model].filter(Boolean).join(' · ');
      panel.appendChild(el('div', { class: 'chat' }, [
        el('div', { class: 't', text: c.title }),
        el('div', { class: 'm' }, [
          el('span', { class: 'blurb', text: meta }),
          el('span', { class: 'pill ' + c.state, text: STATE_LABEL[c.state] || 'Idle' })
        ]),
        c.detail ? el('p', { class: 'blurb', text: c.detail }) : null
      ]));
    });
  }

  refresh();
  statusTimer = setInterval(refresh, 5000);
}

/**
 * The buttons that run something, rather than answer something.
 *
 * Every label here was written on the PC. This page sends an id and a
 * signature over a nonce the PC issued; it has never seen a command string and
 * cannot compose one. See core/actions.ts.
 */
async function renderActions() {
  var panel = el('div', { class: 'panel' }, [el('div', { text: 'Run something' })]);
  app.appendChild(panel);

  var offer;
  try {
    offer = await link.actions();
  } catch (err) {
    offer = { ok: false };
  }
  var list = (offer && offer.actions) || [];
  if (!list.length) {
    panel.appendChild(el('p', {
      class: 'blurb',
      text: 'No actions are set up. Add them on the PC: bashme → Devices → Run from the phone.'
    }));
    return;
  }

  list.forEach(function (a) {
    var btn = el('button', { text: a.label });
    var row = el('div', { class: 'row' }, [
      el('div', { class: 'grow' }, [
        el('div', { text: a.label }),
        a.description ? el('p', { class: 'blurb', text: a.description }) : null
      ]),
      btn
    ]);
    // Two taps, because one tap in a pocket should not restart the network.
    btn.onclick = function () {
      btn.disabled = true;
      var go = el('button', { class: 'on', text: 'Run it' });
      var no = el('button', { text: 'Cancel' });
      var confirm = el('div', { class: 'actions' }, [no, go]);
      row.appendChild(confirm);
      no.onclick = function () { row.removeChild(confirm); btn.disabled = false; };
      go.onclick = async function () {
        go.disabled = true;
        no.disabled = true;
        go.textContent = 'Running…';
        var res = await runAction(a, offer.nonce);
        row.removeChild(confirm);
        btn.disabled = false;
        row.appendChild(el('div', {
          class: res.ok ? 'okbox' : 'errbox',
          text: res.ok ? (res.output || 'Done.') : (res.error || 'That did not run.')
        }));
        // The nonce is spent either way, so the next tap needs a fresh list.
        renderIdleSoon();
      };
    };
    panel.appendChild(row);
  });
}

async function runAction(a, nonce) {
  var key = await getKey();
  if (!key) return { ok: false, error: 'The signing key for this phone is gone. Pair it again.' };
  var message = new TextEncoder().encode('action|' + a.id + '|' + nonce);
  var signature = await crypto.subtle.sign({ name: 'Ed25519' }, key, message);
  return link.invoke({ actionId: a.id, deviceId: deviceId, nonce: nonce, signature: b64(signature) });
}

var idleTimer = null;
function renderIdleSoon() {
  if (idleTimer) clearTimeout(idleTimer);
  idleTimer = setTimeout(function () { if (!showing) renderIdle(); }, 6000);
}

function renderRequest(r) {
  clear(app);
  const title = r.kind === 'shell' ? 'Run this command?'
    : r.kind === 'write' ? 'Write this file?'
    : r.kind === 'elevate' ? 'Run this with elevated privileges?' : 'Allow this?';

  const answer = async (decision) => {
    const key = signingKey || await getKey();
    if (!key) { renderEnroll('The signing key for this phone is gone. Pair it again.'); return; }
    const message = new TextEncoder().encode(r.hash + '|' + r.nonce + '|' + decision);
    const signature = await crypto.subtle.sign({ name: 'Ed25519' }, key, message);
    await link.answer({ requestId: r.id, deviceId, decision, signature: b64(signature) });
    if (link.drop) link.drop(r.id);
    showing = null;
    renderIdle();
  };

  const kids = [
    el('div', { text: title }),
    el('p', { class: 'blurb', text: 'Asked by ' + r.originator }),
    el('pre', { class: 'mono', text: r.summary || r.command }),
    el('p', { class: 'blurb mono', text: 'in ' + r.cwd })
  ];

  if (r.hardBlocked) {
    kids.push(el('div', { class: 'warnbox' }, [
      el('div', { class: 'k', text: 'Never auto-approved' }),
      el('ul', {}, (r.reasons || []).map((x) => el('li', { text: REASONS[x] || x })))
    ]));
  }

  kids.push(el('div', { class: 'actions' }, [
    el('button', { text: 'Deny', onClick: () => answer('deny') }),
    el('button', { class: 'danger', text: r.kind === 'shell' ? 'Run it' : 'Allow it', onClick: () => answer('approve') })
  ]));

  app.appendChild(el('div', { class: 'panel' }, kids));
}

async function poll() {
  try {
    const res = await link.pending(deviceId);
    const next = (res.requests || [])[0] || null;
    // Only re-render on a change, so tapping is not interrupted mid-decision.
    if (!next) { if (showing) { showing = null; renderIdle(); } return; }
    if (!showing || showing !== next.id) { showing = next.id; renderRequest(next); }
  } catch (err) {
    /* a dropped poll is normal on a phone; the next one recovers */
  }
}

function start() {
  renderIdle();
  if (polling) clearInterval(polling);
  polling = setInterval(poll, 2000);
  poll();
  setupPush();
}

(async () => {
  if (!crypto.subtle) {
    renderUnsupported('WebCrypto is unavailable. This usually means the page was opened over http:// rather than https://.');
    return;
  }
  try {
    // Ed25519 support varies by browser version, and failing here with a clear
    // message beats failing later inside pairing.
    await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
  } catch (err) {
    renderUnsupported('This browser does not support Ed25519 signing keys. Try a current Chrome, Safari or Firefox.');
    return;
  }
  signingKey = await getKey();
  if (deviceId && signingKey) start(); else renderEnroll(null);
})();
</script>
</body>
</html>
`;
