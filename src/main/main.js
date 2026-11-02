const path = require('path');
const net = require('net');
const { execFile, spawn } = require('child_process');
const { app, BrowserWindow, ipcMain, clipboard, shell, dialog } = require('electron');
const { Store } = require('./store');
const { Core, buildConfig } = require('./singbox');
const { installServer } = require('./installer');
const { parseVless, buildVless } = require('./vless');
const killSwitch = require('./killswitch');

const APP_RE = /^[^\\/:*?"<>|]+\.exe$/i;
const SITE_RE = /^(([a-z0-9-]+\.)+[a-z0-9-]+|[0-9.]+\/\d+|[0-9a-f:]+\/\d+)$/i;

function sanitizeSplit(split) {
  const part = (p, re) => ({
    mode: ['off', 'only', 'except'].includes(p?.mode) ? p.mode : 'off',
    list: [...new Set((p?.list || []).map((v) => String(v).trim().toLowerCase()).filter((v) => re.test(v)))].slice(0, 500),
  });
  return { apps: part(split?.apps, APP_RE), sites: part(split?.sites, SITE_RE) };
}

const EXE_PATH_RE = /^[a-z]:\\[^:*?"<>|]+\.exe$/i;

function sanitizeKillSwitch(ks, prev) {
  const ex = ks?.exceptions || prev.exceptions || {};
  return {
    enabled: !!ks?.enabled,
    allowLan: ks?.allowLan !== false,
    exceptions: {
      apps: [...new Set((ex.apps || []).map((v) => String(v).trim()).filter((v) => EXE_PATH_RE.test(v)))].slice(0, 200),
      sites: [...new Set((ex.sites || []).map((v) => String(v).trim().toLowerCase()).filter((v) => SITE_RE.test(v)))].slice(0, 200),
    },
  };
}

function listRunningApps() {
  const script = 'Get-Process | Where-Object { $_.Path } | Select-Object @{n="n";e={$_.Path | Split-Path -Leaf}}, @{n="p";e={$_.Path}} | Sort-Object n -Unique | ConvertTo-Json -Compress';
  return new Promise((resolve) => execFile('powershell.exe', ['-NoProfile', '-Command', script], { windowsHide: true, maxBuffer: 8 << 20 },
    (err, out) => {
      try {
        resolve([].concat(JSON.parse(out))
          .filter((x) => x && APP_RE.test(x.n) && !/\\Windows\\/i.test(x.p))
          .map((x) => ({ name: x.n.toLowerCase(), path: x.p })));
      } catch {
        resolve([]);
      }
    }));
}

if (!app.requestSingleInstanceLock()) {
  app.quit();
  process.exit(0);
}

let win = null;
let store = null;
let core = null;
let quitting = false;

const coreExe = () => (app.isPackaged
  ? path.join(process.resourcesPath, 'core', 'sing-box.exe')
  : path.join(__dirname, '..', '..', 'core', 'sing-box.exe'));

const send = (channel, payload) => win && !win.isDestroyed() && win.webContents.send(channel, payload);

function isAdmin() {
  if (process.platform !== 'win32') return Promise.resolve(process.getuid && process.getuid() === 0);
  return new Promise((resolve) => execFile('net', ['session'], { windowsHide: true }, (err) => resolve(!err)));
}

function relaunchAsAdmin() {
  const args = app.isPackaged ? [] : [app.getAppPath()];
  const argList = args.length ? `-ArgumentList '${args.map((a) => `"${a}"`).join(' ')}'` : '';
  spawn('powershell.exe', ['-NoProfile', '-WindowStyle', 'Hidden', '-Command',
    `Start-Process -FilePath '${process.execPath}' ${argList} -Verb RunAs`], { detached: true, stdio: 'ignore' }).unref();
  quitting = true;
  core.disconnect().finally(() => app.quit());
}

function tcpPing(host, port, timeout = 3000) {
  return new Promise((resolve) => {
    const start = process.hrtime.bigint();
    const sock = net.connect({ host, port: Number(port), timeout });
    const done = (ms) => {
      sock.destroy();
      resolve(ms);
    };
    sock.once('connect', () => done(Number(process.hrtime.bigint() - start) / 1e6));
    sock.once('timeout', () => done(null));
    sock.once('error', () => done(null));
  });
}

function createWindow() {
  win = new BrowserWindow({
    width: 420,
    height: 780,
    minWidth: 380,
    minHeight: 640,
    backgroundColor: '#0b0d12',
    title: 'Leftik VPN',
    icon: path.join(__dirname, '..', 'renderer', 'assets', 'icon.png'),
    titleBarStyle: 'hidden',
    titleBarOverlay: { color: '#0b0d12', symbolColor: '#9aa3b2', height: 40 },
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, '..', 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  win.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https:\/\//.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
}

app.on('second-instance', () => {
  if (win) {
    if (win.isMinimized()) win.restore();
    win.focus();
  }
});

app.whenReady().then(() => {
  store = new Store(app.getPath('userData'));
  core = new Core(coreExe(), path.join(app.getPath('userData'), 'core'));
  core.on('state', (s) => send('core:state', s));
  core.on('log', (l) => send('core:log', l));
  core.on('traffic', (t) => send('core:traffic', t));

  ipcMain.handle('app:init', async () => ({
    store: store.state(),
    core: { state: core.state, logs: core.logs },
    admin: await isAdmin(),
    version: app.getVersion(),
  }));
  ipcMain.handle('app:relaunchAdmin', () => relaunchAsAdmin());

  ipcMain.handle('server:install', async (_e, params) => {
    const server = await installServer(params, (line) => send('install:log', line));
    const state = store.addServer(server);
    refreshKillSwitch();
    return state;
  });
  ipcMain.handle('server:import', (_e, link) => {
    const state = store.addServer(parseVless(link));
    refreshKillSwitch();
    return state;
  });
  ipcMain.handle('server:remove', async (_e, id) => {
    if (store.data.selected === id && core.state !== 'disconnected') await core.disconnect();
    const state = store.removeServer(id);
    refreshKillSwitch();
    return state;
  });
  ipcMain.handle('server:rename', (_e, id, name) => store.renameServer(id, name));
  ipcMain.handle('server:select', (_e, id) => store.select(id));
  ipcMain.handle('server:share', (_e, id) => {
    const s = store.data.servers.find((x) => x.id === id);
    if (!s) throw new Error('Сервер не найден');
    const link = buildVless(s);
    clipboard.writeText(link);
    return link;
  });
  ipcMain.handle('server:ping', (_e, id) => {
    const s = store.data.servers.find((x) => x.id === id);
    return s ? tcpPing(s.host, s.port) : null;
  });
  ipcMain.handle('settings:set', async (_e, patch) => {
    const clean = {};
    if (typeof patch.dns === 'string') clean.dns = patch.dns;
    if (patch.split) clean.split = sanitizeSplit(patch.split);
    const state = store.setSettings(clean);
    // Маршруты меняются только при перезапуске ядра — переподключаемся сами
    if (core.state === 'connected') connect().catch(() => {});
    return state;
  });

  ipcMain.handle('killswitch:set', async (_e, patch) => {
    const prev = store.data.settings.killSwitch;
    const ks = sanitizeKillSwitch(patch, prev);
    // Правку исключений при выключенном kill switch можно сохранить и без прав администратора
    if ((ks.enabled || prev.enabled) && !(await isAdmin())) throw new Error('NEED_ADMIN');
    let unresolved = [];
    if (ks.enabled) unresolved = (await applyKillSwitch(ks)).unresolved;
    else if (prev.enabled) await killSwitch.disable();
    return { store: store.setSettings({ killSwitch: ks }), unresolved };
  });

  ipcMain.handle('apps:running', () => listRunningApps());
  ipcMain.handle('apps:browse', async () => {
    const r = await dialog.showOpenDialog(win, {
      title: 'Выберите программу',
      filters: [{ name: 'Программы', extensions: ['exe'] }],
      properties: ['openFile', 'multiSelections'],
    });
    return r.canceled ? [] : r.filePaths;
  });

  ipcMain.handle('vpn:connect', () => connect());
  ipcMain.handle('vpn:disconnect', () => core.disconnect());

  createWindow();

  // Чистим ядро, оставшееся от упавшего прошлого запуска, и обновляем правила kill switch
  // (пути к программам могли смениться: установленная версия против npm start)
  core.disconnect();
  refreshKillSwitch();
});

function applyKillSwitch(ks = store.data.settings.killSwitch) {
  return killSwitch.enable({
    coreExe: coreExe(),
    appExe: process.execPath,
    allowLan: ks.allowLan,
    servers: store.data.servers.map((s) => s.host),
    exceptions: ks.exceptions,
  });
}

// Фоновое обновление правил: поменялся список серверов или приложение перезапущено
async function refreshKillSwitch() {
  if (!store.data.settings.killSwitch.enabled || !(await isAdmin())) return;
  try {
    const { unresolved } = await applyKillSwitch();
    if (unresolved.length) core.log(`[leftik] kill switch: не удалось найти IP для ${unresolved.join(', ')}`);
  } catch (e) {
    core.log(`[leftik] kill switch: ${e.message}`);
  }
}

async function connect() {
  const server = store.selectedServer();
  if (!server) throw new Error('Сначала добавьте сервер');
  if (!(await isAdmin())) throw new Error('NEED_ADMIN');
  const config = buildConfig(server, store.data.settings, { appExe: process.execPath });
  await core.connect(server, config);
  return true;
}

app.on('before-quit', (e) => {
  if (quitting || !core || !core.proc) return;
  e.preventDefault();
  quitting = true;
  core.disconnect().finally(() => app.quit());
});

app.on('window-all-closed', () => app.quit());
