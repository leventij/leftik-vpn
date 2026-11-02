// Kill switch на брандмауэре Windows: исходящий трафик по умолчанию запрещён,
// разрешены только ядро Leftik, само приложение, туннель, серверы VPN и исключения.
// Правила живут в Windows, поэтому блокировка держится, даже если Leftik закрыт или упал.
// Всё делается через netsh: он отрабатывает мгновенно и не лезет в сеть
// (PowerShell без интернета может подвисать на проверке подписей).
const fs = require('fs');
const path = require('path');
const dns = require('dns');
const { spawn, execFile } = require('child_process');
const { TUN_V4, TUN_V6 } = require('./singbox');

const RULE = 'Leftik VPN Kill Switch';
const PROFILES = ['domain', 'private', 'public'];
const DATA_DIR = path.join(process.env.ProgramData || 'C:\\ProgramData', 'LeftikVPN');
const RESTORE = path.join(DATA_DIR, 'restore-firewall.cmd');
const LEGACY_RESTORE = path.join(DATA_DIR, 'restore-firewall.ps1');
const LAN = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16', '224.0.0.0/4', '255.255.255.255', 'fe80::/10', 'ff00::/8'];

const isIp = (v) => /^[0-9.]+(\/\d+)?$/.test(v) || (v.includes(':') && /^[0-9a-f:]+(\/\d+)?$/i.test(v));
const net = (cidr) => cidr.replace(/\.1\/30$/, '.0/30').replace(/::1\/126$/, '::/126');

// Аргументы собираем сами (key="value"), поэтому windowsVerbatimArguments
function netsh(args) {
  return new Promise((resolve) => {
    const p = spawn('netsh', args, { windowsHide: true, windowsVerbatimArguments: true });
    let out = '';
    p.stdout.on('data', (d) => { out += d; });
    p.stderr.on('data', (d) => { out += d; });
    p.on('error', (e) => resolve({ code: -1, out: e.message }));
    p.on('close', (code) => resolve({ code, out: out.trim() }));
  });
}

async function mustNetsh(args) {
  const r = await netsh(args);
  if (r.code !== 0) throw new Error(`netsh ${args.slice(0, 4).join(' ')}: ${r.out.split(/\r?\n/)[0] || `код ${r.code}`}`);
  return r.out;
}

// Текущее состояние профилей читаем из реестра: вывод netsh локализован
// («Состояние ВЫКЛЮЧИТЬ»), а значения в реестре от языка Windows не зависят
const REG_KEYS = { domain: 'DomainProfile', private: 'StandardProfile', public: 'PublicProfile' };
function regDword(text, name) {
  const m = text.match(new RegExp(`${name}\\s+REG_DWORD\\s+0x([0-9a-f]+)`, 'i'));
  return m ? parseInt(m[1], 16) : null;
}
function readProfiles() {
  return Promise.all(PROFILES.map((name) => new Promise((resolve) => {
    const key = `HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\${REG_KEYS[name]}`;
    execFile('reg', ['query', key], { windowsHide: true }, (_err, out = '') => {
      const enabled = regDword(out, 'EnableFirewall');
      const inbound = regDword(out, 'DefaultInboundAction');
      const outbound = regDword(out, 'DefaultOutboundAction');
      resolve({
        name,
        state: enabled === 0 ? 'off' : 'on',
        inbound: inbound === 0 ? 'allowinbound' : 'blockinbound',
        outbound: outbound === 1 ? 'blockoutbound' : 'allowoutbound',
      });
    });
  })));
}

// Текст restore-firewall.cmd. Исходящий трафик всегда возвращаем в «разрешён» (так в Windows
// по умолчанию): иначе, если снимок сделан при уже действующей блокировке, интернет не вернётся.
// legacyText — резерв первой версии (.ps1), там записано, был ли брандмауэр включён.
function restoreScript(profiles, legacyText = '') {
  const lines = [
    '@echo off',
    'rem Leftik VPN: restore Windows Firewall to its state before kill switch',
    `netsh advfirewall firewall delete rule name="${RULE}" >nul 2>&1`,
  ];
  for (const p of profiles) {
    const m = legacyText.match(new RegExp(`-Name '${p.name}' -Enabled (\\w+)`, 'i'));
    const state = m ? (/false/i.test(m[1]) ? 'off' : 'on') : p.state;
    lines.push(`netsh advfirewall set ${p.name}profile firewallpolicy ${p.inbound},allowoutbound >nul`);
    lines.push(`netsh advfirewall set ${p.name}profile state ${state} >nul`);
  }
  return `${lines.join('\r\n')}\r\n`;
}

// Файл возврата брандмауэра «как было». Создаётся один раз при первом включении,
// его же запускает деинсталлятор.
async function ensureRestoreScript() {
  if (fs.existsSync(RESTORE)) return;
  const legacy = fs.existsSync(LEGACY_RESTORE) ? fs.readFileSync(LEGACY_RESTORE, 'utf8') : '';
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(RESTORE, restoreScript(await readProfiles(), legacy));
  fs.rmSync(LEGACY_RESTORE, { force: true });
}

// Домены исключений и серверов -> IP. Резолвим напрямую через публичные DNS:
// системный DNS при включённом kill switch заблокирован, а приложению Leftik выход разрешён.
async function resolveAll(hosts) {
  const resolver = new dns.promises.Resolver({ timeout: 3000, tries: 1 });
  resolver.setServers(['1.1.1.1', '8.8.8.8']);
  const ips = [];
  const failed = [];
  await Promise.all(hosts.map(async (h) => {
    if (isIp(h)) return ips.push(h);
    const found = (await Promise.allSettled([resolver.resolve4(h), resolver.resolve6(h)]))
      .flatMap((r) => (r.status === 'fulfilled' ? r.value : []));
    if (found.length) ips.push(...found);
    else failed.push(h);
  }));
  return { ips: [...new Set(ips)], failed };
}

// Список команд netsh (чистая функция — удобно проверять)
function ruleCommands({ coreExe, appExe, allowLan, serverIps = [], exceptionApps = [], exceptionIps = [], allowDns = false }) {
  const add = (extra) => ['advfirewall', 'firewall', 'add', 'rule', `name="${RULE}"`, 'dir=out', 'action=allow', 'enable=yes', 'profile=any', ...extra];
  const cmds = [
    add([`program="${coreExe}"`]),
    add([`program="${appExe}"`]),
    add([`localip=${net(TUN_V4)},${net(TUN_V6)}`]),
    add(['protocol=udp', 'localport=68', 'remoteport=67']),
    add(['protocol=udp', 'localport=546', 'remoteport=547']),
  ];
  if (serverIps.length) cmds.push(add([`remoteip=${serverIps.join(',')}`]));
  if (allowLan) cmds.push(add([`remoteip=${LAN.join(',')}`]));
  for (const exe of exceptionApps) cmds.push(add([`program="${exe}"`]));
  if (exceptionIps.length) cmds.push(add([`remoteip=${exceptionIps.join(',')}`]));
  if (allowDns) {
    cmds.push(add(['protocol=udp', 'remoteport=53']));
    cmds.push(add(['protocol=tcp', 'remoteport=53']));
  }
  return cmds;
}

async function enable({ coreExe, appExe, allowLan, servers = [], exceptions = {} }) {
  await ensureRestoreScript();
  const sites = exceptions.sites || [];
  const [srv, ex] = await Promise.all([resolveAll(servers), resolveAll(sites)]);
  const cmds = ruleCommands({
    coreExe,
    appExe,
    allowLan,
    serverIps: srv.ips,
    exceptionApps: (exceptions.apps || []).filter((p) => fs.existsSync(p)),
    exceptionIps: ex.ips,
    allowDns: sites.some((s) => !isIp(s)),
  });

  await netsh(['advfirewall', 'firewall', 'delete', 'rule', `name="${RULE}"`]); // «нет правил» — не ошибка
  await removeLegacyRules();
  for (const c of cmds) await mustNetsh(c);
  const inbound = Object.fromEntries((await readProfiles()).map((p) => [p.name, p.inbound]));
  for (const p of PROFILES) {
    await mustNetsh(['advfirewall', 'set', `${p}profile`, 'firewallpolicy', `${inbound[p]},blockoutbound`]);
    await mustNetsh(['advfirewall', 'set', `${p}profile`, 'state', 'on']);
  }
  return { unresolved: [...srv.failed, ...ex.failed] };
}

async function disable() {
  if (!fs.existsSync(RESTORE) && fs.existsSync(LEGACY_RESTORE)) await ensureRestoreScript();
  if (fs.existsSync(RESTORE)) {
    await new Promise((resolve) => spawn('cmd.exe', ['/d', '/c', RESTORE], { windowsHide: true }).on('close', resolve).on('error', resolve));
    fs.rmSync(RESTORE, { force: true });
  } else {
    await netsh(['advfirewall', 'firewall', 'delete', 'rule', `name="${RULE}"`]);
    for (const p of PROFILES) await netsh(['advfirewall', 'set', `${p}profile`, 'firewallpolicy', 'blockinbound,allowoutbound']);
  }
  await removeLegacyRules();
}

// Правила первой версии kill switch (создавались через PowerShell под другими именами)
const LEGACY_NAMES = ['ядро', 'приложение', 'туннель', 'DHCP', 'DHCPv6', 'локальная сеть'].map((n) => `Leftik VPN: ${n}`);
async function removeLegacyRules() {
  for (const n of LEGACY_NAMES) await netsh(['advfirewall', 'firewall', 'delete', 'rule', `name="${n}"`]);
}

module.exports = { enable, disable, ruleCommands, resolveAll, readProfiles, restoreScript, RESTORE, RULE };
