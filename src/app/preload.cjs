// preload.cjs — the renderer's only way to reach main.
//
// CommonJS, and .cjs because package.json is "type": "module". This is not a
// preference: a SANDBOXED preload must be CommonJS, and an ESM one fails
// SILENTLY — the window opens normally and `window.bashme` is simply never
// defined, so every panel renders empty and it looks like a broken app rather
// than a broken preload.
//
// The surface is explicit rather than a generic `invoke(channel, ...)`: a
// passthrough bridge lets the renderer reach any handler main ever registers,
// and this renderer's whole job is displaying things a model proposed.

const { contextBridge, ipcRenderer } = require('electron');

const ALLOWED_EVENTS = ['approval:request', 'approval:withdraw', 'bashme:changed'];

contextBridge.exposeInMainWorld('bashme', {
  status: () => ipcRenderer.invoke('status'),
  setToggle: (key, value) => ipcRenderer.invoke('setToggle', key, value),

  listRules: () => ipcRenderer.invoke('listRules'),
  saveRule: (rule) => ipcRenderer.invoke('saveRule', rule),
  previewRule: (rule) => ipcRenderer.invoke('previewRule', rule),
  setRuleEnabled: (id, enabled) => ipcRenderer.invoke('setRuleEnabled', id, enabled),
  deleteRule: (id) => ipcRenderer.invoke('deleteRule', id),
  listOriginators: () => ipcRenderer.invoke('listOriginators'),

  recentAudit: (limit) => ipcRenderer.invoke('recentAudit', limit),

  previewDeviceKey: (pasted) => ipcRenderer.invoke('previewDeviceKey', pasted),
  pairDevice: (label, pasted) => ipcRenderer.invoke('pairDevice', label, pasted),
  listDevices: () => ipcRenderer.invoke('listDevices'),
  revokeDevice: (id) => ipcRenderer.invoke('revokeDevice', id),

  lanStatus: () => ipcRenderer.invoke('lanStatus'),
  lanStart: (address, port) => ipcRenderer.invoke('lanStart', address, port),
  lanStop: () => ipcRenderer.invoke('lanStop'),
  lanEnroll: () => ipcRenderer.invoke('lanEnroll'),
  lanCloseEnrollment: () => ipcRenderer.invoke('lanCloseEnrollment'),

  relayStatus: () => ipcRenderer.invoke('relayStatus'),
  relayStart: (relayUrl) => ipcRenderer.invoke('relayStart', relayUrl),
  relayStop: () => ipcRenderer.invoke('relayStop'),
  relayEnroll: () => ipcRenderer.invoke('relayEnroll'),
  relayCloseEnrollment: () => ipcRenderer.invoke('relayCloseEnrollment'),

  actionsGet: () => ipcRenderer.invoke('actionsGet'),
  actionsSeedExamples: () => ipcRenderer.invoke('actionsSeedExamples'),
  actionsOpenFile: () => ipcRenderer.invoke('actionsOpenFile'),

  listClients: () => ipcRenderer.invoke('listClients'),
  addClient: (label) => ipcRenderer.invoke('addClient', label),
  revokeClient: (id) => ipcRenderer.invoke('revokeClient', id),

  pending: () => ipcRenderer.invoke('pending'),
  respond: (id, approved, confirmToken) => ipcRenderer.invoke('respond', id, approved, confirmToken),
  approveByKeyword: () => ipcRenderer.invoke('approveByKeyword'),

  on: (channel, handler) => {
    if (!ALLOWED_EVENTS.includes(channel)) return () => {};
    const listener = (_e, payload) => handler(payload);
    ipcRenderer.on(channel, listener);
    return () => ipcRenderer.off(channel, listener);
  },
});
