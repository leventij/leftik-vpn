const { contextBridge, ipcRenderer } = require('electron');

const unwrap = (p) => p.catch((e) => {
  // Electron оборачивает текст ошибки: "Error invoking remote method 'x': Error: текст"
  throw new Error(String(e.message).replace(/^Error invoking remote method '[^']+': (Error: )?/, ''));
});
const call = (ch, ...args) => unwrap(ipcRenderer.invoke(ch, ...args));
const on = (ch) => (cb) => {
  const fn = (_e, v) => cb(v);
  ipcRenderer.on(ch, fn);
  return () => ipcRenderer.removeListener(ch, fn);
};

contextBridge.exposeInMainWorld('leftik', {
  init: () => call('app:init'),
  relaunchAdmin: () => call('app:relaunchAdmin'),
  install: (params) => call('server:install', params),
  importKey: (link) => call('server:import', link),
  remove: (id) => call('server:remove', id),
  rename: (id, name) => call('server:rename', id, name),
  select: (id) => call('server:select', id),
  share: (id) => call('server:share', id),
  ping: (id) => call('server:ping', id),
  setSettings: (patch) => call('settings:set', patch),
  setKillSwitch: (ks) => call('killswitch:set', ks),
  runningApps: () => call('apps:running'),
  browseApps: () => call('apps:browse'),
  connect: () => call('vpn:connect'),
  disconnect: () => call('vpn:disconnect'),
  onState: on('core:state'),
  onLog: on('core:log'),
  onTraffic: on('core:traffic'),
  onInstallLog: on('install:log'),
});
