// renderer.js — the standalone app's UI. Plain JS, no framework, no deps.
//
// One rule runs through all of it: every string that came from a request, a
// rule, or the audit log is written with textContent, never innerHTML. This
// window's entire job is displaying text a model proposed, and the CSP in
// index.html is the second layer rather than the only one.

const api = window.bashme;

const REASON_LABEL = {
  'destructive-filesystem': 'Destructive filesystem operation',
  'credential-access': 'Credential or secret access',
  'security-posture': 'Changes security posture',
  'network-exfiltration': 'Could send local data off this machine',
  'privileged-elevation': 'Runs with elevated privileges',
  'outside-workspace': 'Touches something outside the workspace',
  unparseable: 'Effect cannot be determined',
};

const NEVER = [
  ['Destructive filesystem', 'rm, del, Remove-Item, format, dd, git reset --hard, git clean -fd'],
  ['Credentials and secrets', '.env, .ssh, id_rsa, .aws, .npmrc, *.pem, environment dumps'],
  ['Security posture', 'netsh, bcdedit, reg, icacls, schtasks, Set-ExecutionPolicy, Defender'],
  ['Elevation', 'sudo, runas, -Verb RunAs'],
  ['Possible exfiltration', 'uploading a local file, piping a file to the network, downloads piped to a shell'],
  ['Outside the root', 'any path resolving outside the configured root'],
  ['Unreadable', '$(...), backticks, eval, Invoke-Expression, -EncodedCommand, base64 decode'],
];

// --- tiny DOM helpers -------------------------------------------------------

function el(tag, opts = {}, kids = []) {
  const node = document.createElement(tag);
  if (opts.class) node.className = opts.class;
  if (opts.text !== undefined) node.textContent = String(opts.text);
  if (opts.title) node.title = String(opts.title);
  if (opts.type) node.type = opts.type;
  if (opts.value !== undefined) node.value = opts.value;
  if (opts.placeholder) node.placeholder = opts.placeholder;
  if (opts.onClick) node.addEventListener('click', opts.onClick);
  if (opts.onInput) node.addEventListener('input', opts.onInput);
  if (opts.disabled) node.disabled = true;
  for (const k of kids) if (k) node.appendChild(k);
  return node;
}

/**
 * Draw a QR matrix onto a canvas.
 *
 * A canvas rather than an <img src="data:..."> because the CSP here is strict
 * and this keeps the picture out of the markup entirely -- nothing is parsed,
 * only painted. The quiet zone is four modules on every side, which is what
 * the specification asks for and what phone cameras actually need to lock on;
 * drawing the matrix edge-to-edge produces a code that looks right on screen
 * and refuses to scan.
 *
 * Light modules are painted explicitly rather than left transparent. The panel
 * behind this is translucent over a moving background plate, and a QR with the
 * artwork showing through its light modules is not a QR.
 */
function qrCanvas(matrix, scale = 6) {
  const quiet = 4;
  const side = (matrix.size + quiet * 2) * scale;
  const canvas = el('canvas', { class: 'qr' });
  canvas.width = side;
  canvas.height = side;
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0, 0, side, side);
  ctx.fillStyle = '#000000';
  for (let y = 0; y < matrix.size; y++) {
    const row = matrix.rows[y];
    for (let x = 0; x < matrix.size; x++) {
      if (row[x] === '1') ctx.fillRect((x + quiet) * scale, (y + quiet) * scale, scale, scale);
    }
  }
  return canvas;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function panel(labelText, blurbText, kids) {
  return el('div', { class: 'panel' }, [
    el('div', { class: 'label', text: labelText }),
    blurbText ? el('p', { class: 'blurb', text: blurbText }) : null,
    ...kids,
  ]);
}

function toggleRow(labelText, blurbText, value, disabled, onChange) {
  return el('div', { class: 'row' }, [
    el('div', { class: 'grow' }, [
      el('div', { text: labelText }),
      el('p', { class: 'blurb', text: blurbText }),
    ]),
    el('button', {
      class: value ? 'on' : '',
      text: value ? 'On' : 'Off',
      disabled,
      onClick: () => onChange(!value),
    }),
  ]);
}

// --- state ------------------------------------------------------------------

let state = { status: null, rules: [], audit: [], clients: [], devices: [], tab: 'requests' };
let draftSeed = null;
let editorOpen = false;

async function refresh() {
  const [status, rules, audit, clients, devices, actions] = await Promise.all([
    api.status(),
    api.listRules(),
    api.recentAudit(150),
    api.listClients(),
    api.listDevices(),
    api.actionsGet(),
  ]);
  state = { ...state, status, rules, audit, clients, devices, actions };
  render();
}

// --- approval modal ---------------------------------------------------------

const queue = [];
const modal = document.getElementById('modal');

function renderModal() {
  clear(modal);
  const current = queue[0];
  if (!current) {
    modal.classList.add('hidden');
    return;
  }
  modal.classList.remove('hidden');

  const { request, verdict } = current;
  const title =
    request.kind === 'shell' ? 'Run this command?'
      : request.kind === 'write' ? 'Write this file?'
        : request.kind === 'elevate' ? 'Run this with elevated privileges?'
          : 'Allow this?';

  const answer = async (approved) => {
    await api.respond(request.id, approved, current.confirmToken);
    queue.shift();
    renderModal();
    void refresh();
  };

  const body = [
    el('p', { class: 'blurb', text: `Asked by ${request.originator.label}` }),
    el('pre', { text: request.summary || request.command }),
    el('p', { class: 'faint truncate', text: `in ${request.cwd}`, title: request.cwd }),
  ];

  if (verdict.hardBlocked) {
    body.push(
      el('div', { class: 'warnbox' }, [
        el('div', { class: 'label', text: 'Never auto-approved' }),
        el('ul', {}, verdict.reasons.map((r) => el('li', { text: REASON_LABEL[r] || r }))),
        verdict.notes.length ? el('p', { class: 'blurb', text: verdict.notes.join('; ') }) : null,
      ]),
    );
  }

  if (queue.length > 1) {
    body.push(el('p', { class: 'faint', text: `${queue.length - 1} more waiting` }));
  }

  const deny = el('button', { text: 'Deny', onClick: () => void answer(false) });
  body.push(
    el('div', { class: 'actions' }, [
      deny,
      el('button', {
        class: 'danger',
        text: request.kind === 'shell' ? 'Run it' : 'Allow it',
        onClick: () => void answer(true),
      }),
    ]),
  );

  modal.appendChild(el('div', { class: 'panel' }, [el('div', { class: 'label', text: title }), ...body]));
  // Deny is the default action, so it is what Enter lands on.
  deny.focus();
}

api.on('approval:request', (p) => {
  if (!p || !p.request || queue.some((q) => q.request.id === p.request.id)) return;
  queue.push(p);
  renderModal();
});

// Main tells the renderer when something it did not initiate changed the state
// -- a phone pairing itself, for instance, which no click here would show.
api.on('bashme:changed', () => {
  void refresh();
});

api.on('approval:withdraw', (p) => {
  const i = queue.findIndex((q) => q.request.id === p.id);
  if (i >= 0) {
    queue.splice(i, 1);
    renderModal();
  }
});

// --- tabs -------------------------------------------------------------------

function renderRequests() {
  const root = document.getElementById('tab-requests');
  clear(root);
  const s = state.status;

  root.appendChild(
    panel(
      'Recent requests',
      'Append-only. This is what makes "what did I actually let run last week" answerable.',
      state.audit.length === 0
        ? [el('p', { class: 'faint', text: 'Nothing recorded yet.' })]
        : state.audit.map((a) => {
            const res = a.resolution || {};
            const label =
              res.type === 'approved' ? (res.by === 'keyword' ? 'approved (keyword)' : 'approved')
                : res.type === 'approved-by-rule' ? 'auto-approved by rule'
                  : res.type === 'approved-by-device' ? 'approved on a device'
                    : res.type === 'denied' ? 'denied'
                      : res.type === 'timeout' ? 'timed out — denied'
                        : res.type === 'no-approver' ? 'nobody could be asked — denied'
                          : res.type;
            const meta = [new Date(a.settledAt).toLocaleString(), a.originatorLabel];
            if (a.hardReasons.length) {
              meta.push(a.hardReasons.map((r) => REASON_LABEL[r] || r).join(', '));
            }
            const canRule = a.hardReasons.length === 0 && res.type !== 'approved-by-rule';
            return el('div', { class: 'row' }, [
              el('div', { class: 'grow' }, [
                el('div', { class: 'mono truncate', text: a.command, title: a.command }),
                el('div', { class: 'faint' }, [
                  el('span', { text: meta.join('  ·  ') + (canRule ? '  ·  ' : '') }),
                  canRule
                    ? el('button', {
                        class: 'link',
                        text: 'always allow this',
                        onClick: () => {
                          draftSeed = { originatorId: a.originatorId, kind: a.kind, prefix: a.command };
                          editorOpen = true;
                          selectTab('rules');
                        },
                      })
                    : null,
                ]),
              ]),
              el('span', { class: 'faint', text: label }),
            ]);
          }),
    ),
  );

  if (s) {
    root.appendChild(
      panel('Never auto-approved', 'Checked before any rule, so a rule cannot widen past it.',
        NEVER.map(([k, v]) =>
          el('div', { class: 'row' }, [
            el('div', { class: 'grow' }, [
              el('div', { text: k }),
              el('div', { class: 'faint mono', text: v }),
            ]),
          ]),
        ),
      ),
    );
  }
}

function renderRuleEditor(container) {
  const originatorsBox = el('select');
  const kindWrap = el('div', {});
  const prefixBox = el('textarea', {
    placeholder: 'npm run build\nnpm test',
    value: draftSeed ? draftSeed.prefix : '',
  });
  const noteBox = el('input', { placeholder: 'why this is routine' });
  const previewBox = el('div', {});
  let kind = draftSeed ? draftSeed.kind : 'shell';

  for (const k of ['shell', 'write', 'network', 'elevate']) {
    kindWrap.appendChild(
      el('button', {
        class: k === kind ? 'on' : '',
        text: k,
        onClick: () => {
          kind = k;
          for (const b of kindWrap.children) b.className = b.textContent === k ? 'on' : '';
          schedule();
        },
      }),
    );
  }

  void api.listOriginators().then((list) => {
    clear(originatorsBox);
    if (!list.length) {
      originatorsBox.appendChild(el('option', { value: '', text: 'nothing has asked yet' }));
    }
    for (const o of list) {
      const opt = el('option', { value: o.id, text: `${o.label} — ${o.id}` });
      originatorsBox.appendChild(opt);
    }
    if (draftSeed) originatorsBox.value = draftSeed.originatorId;
    schedule();
  });

  const draft = () => ({
    id: `rule-${Date.now()}`,
    enabled: true,
    originatorId: originatorsBox.value,
    kind,
    prefixes: prefixBox.value.split('\n').map((l) => l.trim()).filter(Boolean),
    createdAt: new Date().toISOString(),
    matchCount: 0,
    note: noteBox.value.trim() || undefined,
  });

  let timer = null;
  function schedule() {
    clearTimeout(timer);
    timer = setTimeout(() => void runPreview(), 250);
  }

  async function runPreview() {
    const d = draft();
    clear(previewBox);
    if (!d.originatorId || d.prefixes.length === 0) return;
    const p = await api.previewRule(d);
    if (p.errors.length) {
      previewBox.appendChild(
        el('div', { class: 'errbox' }, [
          el('div', { text: 'This rule cannot be saved' }),
          el('ul', {}, p.errors.map((e) => el('li', { text: e }))),
        ]),
      );
      saveBtn.disabled = true;
      return;
    }
    saveBtn.disabled = false;
    const kids = [
      el('div', {
        text: `Against your last ${p.sampled} request${p.sampled === 1 ? '' : 's'}, this rule would have auto-approved ${p.matches.length}.`,
      }),
    ];
    for (const m of p.matches.slice(0, 20)) {
      kids.push(el('div', { class: 'faint mono truncate', text: m.command, title: m.command }));
    }
    if (p.hardBlocked > 0) {
      kids.push(
        el('p', {
          class: 'blurb',
          text: `${p.hardBlocked} more matched the prefix but would still have prompted — they fall in a never-auto-approve category.`,
        }),
      );
    }
    if (p.matches.length === 0 && p.sampled > 0) {
      kids.push(
        el('p', {
          class: 'blurb',
          text: 'Nothing in recent history matches. Fine for a rule written ahead of time, but worth re-reading the prefix if you expected it to catch something.',
        }),
      );
    }
    previewBox.appendChild(el('div', { class: 'okbox' }, kids));
  }

  prefixBox.addEventListener('input', schedule);
  noteBox.addEventListener('input', schedule);
  originatorsBox.addEventListener('change', schedule);

  const saveBtn = el('button', {
    text: 'Add rule',
    disabled: true,
    onClick: async () => {
      const res = await api.saveRule(draft());
      if (res && !res.ok) {
        clear(previewBox);
        previewBox.appendChild(
          el('div', { class: 'errbox' }, [
            el('div', { text: 'Rejected' }),
            el('ul', {}, (res.errors || []).map((e) => el('li', { text: e }))),
          ]),
        );
        return;
      }
      editorOpen = false;
      draftSeed = null;
      void refresh();
    },
  });

  container.appendChild(
    el('div', { class: 'panel' }, [
      el('div', { class: 'label', text: 'New rule' }),
      el('label', {}, [
        el('span', { text: 'Asked by' }),
        originatorsBox,
        el('p', {
          class: 'blurb',
          text: 'Picked, not typed: a rule matches this id exactly, so a typo is a rule that never fires.',
        }),
      ]),
      el('label', {}, [el('span', { text: 'Kind' }), kindWrap]),
      el('label', {}, [
        el('span', { text: 'Command prefixes, one per line' }),
        prefixBox,
        el('p', {
          class: 'blurb',
          text: 'Literal text only. No wildcards, and a prefix cannot itself chain commands. Matching requires a word boundary, so "npm run build" does not match "npm run build-prod".',
        }),
      ]),
      el('label', {}, [el('span', { text: 'Note (optional)' }), noteBox]),
      previewBox,
      el('div', { class: 'actions' }, [
        el('button', {
          text: 'Cancel',
          onClick: () => {
            editorOpen = false;
            draftSeed = null;
            render();
          },
        }),
        saveBtn,
      ]),
    ]),
  );
}

function renderRules() {
  const root = document.getElementById('tab-rules');
  clear(root);
  const s = state.status;

  const header = el('div', { class: 'panel' }, [
    el('div', { class: 'label', text: 'Standing rules' }),
    el('p', {
      class: 'blurb',
      text: 'A rule is a standing grant of execution. It names one originator exactly, takes no wildcards, and never matches a chained command.',
    }),
    s && !s.rulesEnabled && state.rules.length
      ? el('p', { class: 'blurb', text: 'Standing rules are switched off, so none of these are in effect right now.' })
      : null,
    el('div', { class: 'actions' }, [
      el('button', {
        text: 'Add rule',
        disabled: editorOpen,
        onClick: () => {
          draftSeed = null;
          editorOpen = true;
          render();
        },
      }),
    ]),
  ]);
  root.appendChild(header);

  if (editorOpen) renderRuleEditor(root);

  if (state.rules.length === 0) {
    root.appendChild(
      panel('Configured', null, [
        el('p', {
          class: 'faint',
          text: 'No rules. Day one behaves exactly like every request prompting, which is the intended starting state.',
        }),
      ]),
    );
    return;
  }

  root.appendChild(
    panel('Configured', null,
      state.rules.map((r) =>
        el('div', { class: 'row' }, [
          el('div', { class: 'grow' }, [
            el('div', { class: 'mono', text: r.prefixes.join('   ·   ') }),
            el('div', {
              class: 'faint',
              text: `${r.kind} · from ${r.originatorId} · matched ${r.matchCount}×${r.note ? ' · ' + r.note : ''}`,
            }),
          ]),
          el('div', {}, [
            el('button', {
              class: r.enabled ? 'on' : '',
              text: r.enabled ? 'On' : 'Off',
              onClick: async () => {
                await api.setRuleEnabled(r.id, !r.enabled);
                void refresh();
              },
            }),
            el('button', {
              class: 'danger',
              text: 'Remove',
              onClick: async () => {
                await api.deleteRule(r.id);
                void refresh();
              },
            }),
          ]),
        ]),
      ),
    ),
  );
}

function renderClients() {
  const root = document.getElementById('tab-clients');
  clear(root);
  const s = state.status;

  const nameBox = el('input', { placeholder: 'Claude Code' });
  const out = el('div', {});

  root.appendChild(
    panel(
      'Enrolled programs',
      'A program must be enrolled before it can ask. Its token is what identifies it — an unknown token is refused outright, so nothing on this machine can raise a dialog or claim an originator a rule trusts without being added here first.',
      [
        s
          ? el('p', { class: 'faint mono truncate', text: `socket: ${s.socketPath}`, title: s.socketPath })
          : null,
        el('label', {}, [el('span', { text: 'Name' }), nameBox]),
        el('div', { class: 'actions' }, [
          el('button', {
            text: 'Enrol and show token',
            onClick: async () => {
              const res = await api.addClient(nameBox.value);
              clear(out);
              out.appendChild(
                el('div', { class: 'warnbox' }, [
                  el('div', { class: 'label', text: 'Copy this now' }),
                  el('p', {
                    class: 'blurb',
                    text: 'Only a hash is stored, so this token cannot be shown again. If it is lost, revoke the client and enrol a new one.',
                  }),
                  el('pre', { text: res.token }),
                  el('p', { class: 'blurb', text: `Set BASHME_TOKEN to this value for: ${res.id}` }),
                ]),
              );
              nameBox.value = '';
              void refresh();
            },
          }),
        ]),
        out,
      ],
    ),
  );

  root.appendChild(
    panel('Enrolled', null,
      state.clients.length === 0
        ? [el('p', { class: 'faint', text: 'Nothing enrolled yet.' })]
        : state.clients.map((c) =>
            el('div', { class: 'row' }, [
              el('div', { class: 'grow' }, [
                el('div', { text: c.label + (c.revokedAt ? '  (revoked)' : '') }),
                el('div', {
                  class: 'faint mono',
                  text: `${c.id} · ${c.lastSeen ? 'last seen ' + new Date(c.lastSeen).toLocaleString() : 'never used'}`,
                }),
              ]),
              c.revokedAt
                ? null
                : el('button', {
                    class: 'danger',
                    text: 'Revoke',
                    onClick: async () => {
                      await api.revokeClient(c.id);
                      void refresh();
                    },
                  }),
            ]),
          ),
    ),
  );
}

// The LAN listener's panel.
//
// The copy here is blunt on purpose. This is the only control in the app that
// opens a port, and a user who does not understand that is a user who leaves it
// on. So the switch says what it does, the address is chosen explicitly rather
// than defaulted to "all interfaces", and the certificate fingerprint sits next
// to the URL because comparing it on the phone is the only thing standing
// between the user and a machine on the same subnet answering instead.
function renderLan(root) {
  const s = state.status;
  const lan = (s && s.lan) || { running: false, available: [] };

  const kids = [];

  if (!lan.running) {
    const picker = el('select');
    for (const a of lan.available || []) {
      picker.appendChild(el('option', { value: a.address, text: `${a.address}  (${a.label})` }));
    }
    if (!(lan.available || []).length) {
      picker.appendChild(el('option', { value: '', text: 'no network interface found' }));
    }

    kids.push(
      el('label', {}, [el('span', { text: 'Listen on' }), picker]),
      el('p', {
        class: 'blurb',
        text: 'Turning this on opens a port on the chosen address. Only that address — never all of them. Nothing outside your local network can reach it, and reaching it is not enough to approve anything: an answer still has to be signed by a paired device.',
      }),
      el('div', { class: 'actions' }, [
        el('button', {
          text: 'Start listening',
          disabled: !(lan.available || []).length,
          onClick: async () => {
            const res = await api.lanStart(picker.value);
            if (!res.ok) {
              alert(res.error);
              return;
            }
            void refresh();
          },
        }),
      ]),
    );
  } else {
    kids.push(
      el('div', { class: 'okbox' }, [
        el('div', { text: 'Open this on the phone' }),
        el('pre', { text: lan.url }),
        el('p', {
          class: 'blurb',
          text: 'The browser will warn that the certificate is not trusted. That is expected — the certificate is self-signed because no authority will issue one for a home network address. Check the fingerprint below matches before continuing past the warning.',
        }),
        el('div', { class: 'label', text: 'Certificate fingerprint' }),
        el('pre', { text: lan.certFingerprint || '' }),
      ]),
    );

    if (lan.enrollCode) {
      kids.push(
        el('div', { class: 'warnbox' }, [
          el('div', { class: 'label', text: 'Scan this with the phone' }),
          lan.enrollQr ? qrCanvas(lan.enrollQr) : null,
          el('p', {
            class: 'blurb',
            text: 'The camera app will do. It opens the pairing page with the code already filled in — the address, the port and the code are all in the picture, which is the part that goes wrong when it is typed.',
          }),
          el('div', { class: 'label', text: 'Or type this' }),
          el('pre', { text: lan.enrollCode }),
          el('p', {
            class: 'blurb',
            text: 'Good for five minutes, and for one device. It is consumed the moment a phone pairs with it.',
          }),
          el('div', { class: 'actions' }, [
            el('button', {
              text: 'Cancel',
              onClick: async () => {
                await api.lanCloseEnrollment();
                void refresh();
              },
            }),
          ]),
        ]),
      );
    } else {
      kids.push(
        el('div', { class: 'actions' }, [
          el('button', {
            text: 'Pair a new phone',
            onClick: async () => {
              const res = await api.lanEnroll();
              if (!res.ok) alert(res.error);
              void refresh();
            },
          }),
          el('button', {
            class: 'danger',
            text: 'Stop listening',
            onClick: async () => {
              await api.lanStop();
              void refresh();
            },
          }),
        ]),
      );
    }
  }

  root.appendChild(
    panel(
      'Approve from a phone',
      lan.running
        ? 'The listener is running.'
        : 'Off. No port is open and nothing can reach this machine.',
      kids,
    ),
  );
}

// --- relay ------------------------------------------------------------------
//
// The second way to reach a phone, and the one that works on this network.
// The LAN listener needs the two devices to see each other; behind CGNAT with
// client isolation on an access point nobody here controls, they never do.
// Relay mode has both ends dial out to a forwarder instead.
//
// It is presented as the weaker option even though it is the one that works,
// and that ordering is deliberate: the forwarder serves the phone's page, so
// it is trusted with the code even though it cannot read the traffic. Where a
// LAN pairing is possible it is the better answer.
function renderRelay(root) {
  const r = (state.status && state.status.relay) || { running: false };
  const kids = [];

  if (!r.running) {
    const urlBox = el('input', {
      placeholder: 'https://bashme-relay.your-name.workers.dev',
      value: r.relayUrl || '',
    });

    // Deliberately empty until someone types or taps. The field is not
    // prefilled with the Violinet relay, because relay mode's security
    // argument is that the operator was CHOSEN -- see OFFICIAL_RELAY_URL in
    // src/core/relay.ts. A host that arrived on its own was not chosen.
    kids.push(
      el('label', {}, [el('span', { text: 'Relay address' }), urlBox]),
      el('p', {
        class: 'blurb',
        text: 'Both this machine and the phone connect outward to this address and leave messages for each other. Nothing connects in, so no port opens here and no router setting has to change.',
      }),
      el('p', {
        class: 'blurb',
        text: 'The relay cannot read what it carries — commands and approvals are encrypted with a key that only ever exists here and on the paired phone. It does serve the page the phone loads, so run one you control; the worker to deploy is in bashme-relay/.',
      }),
      r.officialRelayUrl
        ? el('p', {
            class: 'blurb',
            text: `${r.officialRelayUrl} is the relay Violinet Tech runs. It is not switched on yet, so it will not connect — it is here so the address is in one place when it is.`,
          })
        : null,
      el('div', { class: 'actions' }, [
        r.officialRelayUrl
          ? el('button', {
              text: 'Use the Violinet relay',
              class: 'link',
              onClick: () => {
                urlBox.value = r.officialRelayUrl;
                urlBox.focus();
              },
            })
          : null,
        el('button', {
          text: 'Start relay mode',
          onClick: async () => {
            const res = await api.relayStart(urlBox.value.trim());
            if (!res.ok) {
              alert(res.error);
              return;
            }
            void refresh();
          },
        }),
      ]),
    );
  } else if (r.enrollCode) {
    kids.push(
      el('div', { class: 'warnbox' }, [
        el('div', { class: 'label', text: 'Scan this with the phone' }),
        r.pairingQr ? qrCanvas(r.pairingQr) : null,
        el('p', {
          class: 'blurb',
          text: 'Everything the phone needs is in this picture, and the part that matters — the encryption key — is in the URL fragment, which no browser sends to a server. It cannot be typed instead, so this one has to be scanned.',
        }),
        el('p', {
          class: 'blurb',
          text: 'Good for five minutes, and for one device.',
        }),
        el('div', { class: 'actions' }, [
          el('button', {
            text: 'Cancel',
            onClick: async () => {
              await api.relayCloseEnrollment();
              void refresh();
            },
          }),
        ]),
      ]),
    );
  } else {
    kids.push(
      el('div', { class: 'okbox' }, [
        el('div', { class: 'label', text: 'Relay' }),
        el('pre', { text: r.relayUrl || '' }),
        el('p', {
          class: 'blurb',
          text: r.lastError
            ? 'Last attempt failed: ' + r.lastError
            : 'Connected. A paired phone can answer from anywhere with a connection.',
        }),
      ]),
      el('div', { class: 'actions' }, [
        el('button', {
          text: 'Pair a new phone',
          onClick: async () => {
            const res = await api.relayEnroll();
            if (!res.ok) alert(res.error);
            void refresh();
          },
        }),
        el('button', {
          class: 'danger',
          text: 'Stop relay mode',
          onClick: async () => {
            await api.relayStop();
            void refresh();
          },
        }),
      ]),
    );
  }

  root.appendChild(
    panel(
      'Approve from anywhere',
      r.running
        ? 'Relay mode is on.'
        : 'Off. Use this when the phone and this machine cannot see each other on the network.',
      kids,
    ),
  );
}

/**
 * Actions the phone may start.
 *
 * Deliberately plainer than it could be: this is a list and a link to the file
 * that defines it. Editing happens in the file because the file is the
 * boundary -- a GUI that composes commands would put a command builder one
 * step from a device that is only supposed to send an id.
 */
function renderActions(root) {
  const kids = [];
  const a = state.actions || { actions: [], errors: [], path: '' };

  kids.push(
    el('p', {
      class: 'blurb',
      text: 'Everything else here is the phone answering. This is the phone asking: buttons you write on this machine, which a paired phone can start from anywhere. It sends the name of one, never a command, so the list below is the whole of what it can do.',
    }),
  );

  if (!a.actions.length) {
    kids.push(
      el('p', { class: 'blurb', text: 'Nothing is set up, so the phone sees an empty list.' }),
    );
  }

  for (const action of a.actions) {
    kids.push(
      el('div', { class: 'row' }, [
        el('div', { class: 'grow' }, [
          el('div', { text: action.label }),
          el('p', { class: 'blurb mono truncate', text: action.command }),
        ]),
      ]),
    );
  }

  for (const err of a.errors) {
    kids.push(el('div', { class: 'errbox', text: err }));
  }

  kids.push(
    el('div', { class: 'actions' }, [
      el('button', {
        text: 'Add the two for this machine',
        onClick: async () => {
          // Named rather than "Add examples": these run a scheduled task and
          // launch a shell, and the button should say so before it is pressed.
          if (!window.confirm('Add "Fix the network" (runs the VioletNetFix task) and "Launch Claude Code"? A paired phone will be able to start both.')) return;
          await api.actionsSeedExamples();
          void refresh();
        },
      }),
      el('button', {
        text: 'Edit the file',
        onClick: async () => {
          await api.actionsOpenFile();
        },
      }),
    ]),
    el('p', { class: 'blurb mono truncate', text: a.path }),
  );

  root.appendChild(panel('RUN FROM THE PHONE', null, kids));
}

function renderDevices() {
  const root = document.getElementById('tab-devices');
  clear(root);
  const s = state.status;

  renderLan(root);
  renderRelay(root);
  renderActions(root);

  const labelBox = el('input', { placeholder: 'Phone' });
  const keyBox = el('textarea', { placeholder: 'MCowBQYDK2VwAyEA...' });
  const confirmArea = el('div', {});

  const pairBtn = el('button', {
    text: 'Check key',
    onClick: async () => {
      clear(confirmArea);
      const res = await api.previewDeviceKey(keyBox.value);
      if (!res.ok) {
        confirmArea.appendChild(el('div', { class: 'errbox' }, [el('div', { text: res.error })]));
        return;
      }
      // Nothing is stored until the fingerprint is confirmed. A pasted key is
      // not secret, so the only thing that can go wrong is pasting the wrong
      // one — and only a human comparing both screens can catch that.
      confirmArea.appendChild(
        el('div', { class: 'warnbox' }, [
          el('div', { class: 'label', text: 'Compare before pairing' }),
          el('pre', { text: res.fingerprint }),
          el('p', {
            class: 'blurb',
            text: 'This must match the fingerprint the device is showing. If it does not, the key you pasted is not that device.',
          }),
          el('div', { class: 'actions' }, [
            el('button', {
              text: 'Does not match',
              onClick: () => {
                clear(confirmArea);
                keyBox.value = '';
              },
            }),
            el('button', {
              text: 'Matches — pair it',
              onClick: async () => {
                const done = await api.pairDevice(labelBox.value, keyBox.value);
                clear(confirmArea);
                if (!done.ok) {
                  confirmArea.appendChild(el('div', { class: 'errbox' }, [el('div', { text: done.error })]));
                  return;
                }
                labelBox.value = '';
                keyBox.value = '';
                void refresh();
              },
            }),
          ]),
        ]),
      );
    },
  });

  root.appendChild(
    panel(
      'Pair a device',
      'On the device, run "bashme device keygen". It keeps the private key and prints a public key and a fingerprint. Paste the public key here, then compare the fingerprint on both screens.',
      [
        el('label', {}, [el('span', { text: 'Name' }), labelBox]),
        el('label', {}, [el('span', { text: 'Public key from the device' }), keyBox]),
        el('div', { class: 'actions' }, [pairBtn]),
        confirmArea,
      ],
    ),
  );

  if (s && !s.devicesEnabled) {
    root.appendChild(
      panel('Not in use', null, [
        el('p', {
          class: 'blurb',
          text: 'Paired devices are switched off in Settings, so none of these are consulted.',
        }),
      ]),
    );
  }

  root.appendChild(
    panel(
      'Paired',
      'A paired device can sign approvals. Requests reach it over the local network listener above, which has to be running — pairing alone delivers nothing.',
      state.devices.length === 0
        ? [el('p', { class: 'faint', text: 'No devices paired.' })]
        : state.devices.map((d) =>
            el('div', { class: 'row' }, [
              el('div', { class: 'grow' }, [
                el('div', { text: d.label + (d.revokedAt ? '  (revoked)' : '') }),
                el('div', { class: 'faint mono', text: d.fingerprint || 'unreadable key' }),
                el('div', { class: 'faint', text: `${d.id} · paired ${new Date(d.pairedAt).toLocaleString()}` }),
              ]),
              d.revokedAt
                ? null
                : el('button', {
                    class: 'danger',
                    text: 'Revoke',
                    onClick: async () => {
                      await api.revokeDevice(d.id);
                      void refresh();
                    },
                  }),
            ]),
          ),
    ),
  );
}

function renderSettings() {
  const root = document.getElementById('tab-settings');
  clear(root);
  const s = state.status;
  if (!s) return;

  const set = async (key, value) => {
    state.status = await api.setToggle(key, value);
    render();
  };

  root.appendChild(
    panel(
      'Approvals',
      'Nothing a program proposes runs until someone agrees. Turning bashme off does not turn that off — it makes standing rules and paired devices inert and sends every request to the dialog. There is no setting that stops the prompt.',
      [
        toggleRow('bashme', 'Enables the rule and device layers below. Off = prompt every time.', s.enabled, false, (v) => set('enabled', v)),
        toggleRow('Standing rules', `Auto-approve commands you have explicitly listed. ${s.ruleCount} configured.`, s.rulesEnabled, !s.enabled, (v) => set('rulesEnabled', v)),
        toggleRow('Paired devices', `${s.deviceCount} paired. Requests reach them only while the local network listener on the Devices tab is running.`, s.devicesEnabled, !s.enabled, (v) => set('devicesEnabled', v)),
      ],
    ),
  );

  root.appendChild(
    panel('Containment root', null, [
      el('p', { class: 'mono truncate', text: s.workspaceRoot, title: s.workspaceRoot }),
      el('p', {
        class: 'blurb',
        text: 'Anything resolving outside this directory is never auto-approved. Unlike VIOLINET OS, this app does not own a workspace — its callers run wherever they run — so this defaults to your home directory and is a weaker boundary. Set BASHME_ROOT to narrow it.',
      }),
    ]),
  );
}

// --- shell ------------------------------------------------------------------

function selectTab(tab) {
  state.tab = tab;
  for (const b of document.querySelectorAll('#tabs button')) {
    b.className = b.dataset.tab === tab ? 'on' : '';
  }
  for (const sec of document.querySelectorAll('.tab')) {
    sec.classList.toggle('hidden', sec.id !== `tab-${tab}`);
  }
  render();
}

function render() {
  renderRequests();
  renderRules();
  renderClients();
  renderDevices();
  renderSettings();
}

for (const b of document.querySelectorAll('#tabs button')) {
  b.addEventListener('click', () => selectTab(b.dataset.tab));
}

void api.pending().then((list) => {
  for (const p of list) queue.push(p);
  renderModal();
});
void refresh();

// --- background plate -------------------------------------------------------
//
// `autoplay` alone is not enough: it is refused before the page has user
// activation, and the refusal is silent -- the poster stays up and the result
// looks like a still nobody animated. So retry on canplay and on the first real
// input, and honour prefers-reduced-motion by leaving the poster in place.
(() => {
  const plate = document.getElementById('plate');
  if (!plate) return;

  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    plate.removeAttribute('autoplay');
    plate.pause();
    return;
  }

  const play = () => {
    const attempt = plate.play();
    if (attempt && typeof attempt.catch === 'function') attempt.catch(() => {});
  };

  plate.addEventListener('canplay', play, { once: true });
  for (const evt of ['pointerdown', 'keydown', 'wheel', 'touchstart']) {
    window.addEventListener(evt, play, { once: true, passive: true });
  }
  play();
})();
