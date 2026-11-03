// Самопроверка без сервера: разбор ключей, сборка конфига и проверка его ядром sing-box
const fs = require('fs');
const os = require('os');
const path = require('path');
const assert = require('assert');
const { execFileSync } = require('child_process');
const { parseVless, buildVless } = require('../src/main/vless');
const { buildConfig, splitRouting } = require('../src/main/singbox');
const { ruleCommands, restoreScript, RULE } = require('../src/main/killswitch');
const { serverScript, installError } = require('../src/main/installer');
const { probeScript, parseProbe, analyzeProbe, realityPublicKey, MARK: PROBE_MARK } = require('../src/main/probe');

const link = 'vless://0f9a2b3c-1d2e-4f50-8a9b-0c1d2e3f4a5b@203.0.113.10:443'
  + '?type=tcp&security=reality&flow=xtls-rprx-vision&sni=www.microsoft.com&fp=chrome'
  + '&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw&sid=6ba85179e30d4fc2#%D0%A1%D0%A8%D0%90';

const s = parseVless(link);
assert.strictEqual(s.name, 'США');
assert.strictEqual(s.security, 'reality');
assert.strictEqual(s.port, 443);
assert.deepStrictEqual(parseVless(buildVless(s)), s, 'build -> parse должен давать то же самое');
assert.throws(() => parseVless('vmess://abc'));
assert.throws(() => parseVless('vless://not-a-uuid@1.2.3.4:443'));
console.log('ok  разбор и сборка vless://');

const ws = parseVless('vless://0f9a2b3c-1d2e-4f50-8a9b-0c1d2e3f4a5b@example.com:8443?type=ws&security=tls&path=%2Fws&host=example.com#ws');
assert.strictEqual(ws.transport, 'ws');
assert.strictEqual(ws.path, '/ws');
console.log('ok  ws + tls');

const script = serverScript({ port: 443, sni: 'www.microsoft.com; rm -rf /' });
assert(!script.includes('rm -rf'), 'SNI должен очищаться от спецсимволов');
console.log('ok  скрипт сервера экранирует SNI');

// ---- Проверка сервера перед установкой ----
// Эталонные пары ключей сгенерированы `sing-box generate reality-keypair`
assert.strictEqual(realityPublicKey('WDxy2M_JDeTsLOciGh-G8Zp2juXNH-R6370JB7fzomA'), 'sv74lU1d4sTeKgmlYdxiMX-1A9sZl1kmgEF7eXYQok4');
assert.strictEqual(realityPublicKey('6IRAFVBn_nQCUbxMJvNIw4seE9hmqhg6ZpAvIbIK13E'), 'OIV3qd9MeafJWxKfzrGoORndgNLkoaFNdpKr4JG1b2Q');
assert.strictEqual(realityPublicKey('мусор'), null);
console.log('ok  публичный ключ Reality из приватного');

const UUID = '0f9a2b3c-1d2e-4f50-8a9b-0c1d2e3f4a5b';
const PRIV = 'WDxy2M_JDeTsLOciGh-G8Zp2juXNH-R6370JB7fzomA';
const PUB = 'sv74lU1d4sTeKgmlYdxiMX-1A9sZl1kmgEF7eXYQok4';
const xrayConfig = ({ port = 443, uuid = UUID, listen = '0.0.0.0', security = 'reality', protocol = 'vless' } = {}) => JSON.stringify({
  inbounds: [{
    listen, port, protocol,
    settings: { clients: [{ id: uuid, flow: 'xtls-rprx-vision' }], decryption: 'none' },
    streamSettings: { network: 'tcp', security, realitySettings: { dest: 'www.microsoft.com:443', serverNames: ['www.microsoft.com'], privateKey: PRIV, shortIds: ['', 'ab12cd34'] } },
  }],
});
// Вывод probe-скрипта собираем так же, как его печатает сервер: «LEFTIK_PROBE ключ base64»
const probeOut = (items) => Object.entries(items)
  .map(([k, v]) => `${PROBE_MARK}${k} ${Buffer.from(v).toString('base64')}`).concat(`${PROBE_MARK}done x`).join('\n');
const decide = (items, opts = {}) => analyzeProbe(parseProbe(probeOut(items)), { port: 443, force: false, ...opts });

let d = decide({ native: xrayConfig(), env: `UUID=${UUID}\nPRIV=${PRIV}\nPUB=${PUB}\nSID=ab12cd34`, native_active: 'active', port: 'LISTEN 0 4096 *:443 *:* users:(("xray",pid=812,fd=3))' });
assert.strictEqual(d.action, 'reuse', 'Leftik уже стоит — не переустанавливаем');
assert.deepStrictEqual({ src: d.found.source, pbk: d.found.pbk, sid: d.found.sid, sni: d.found.sni, port: d.found.port },
  { src: 'leftik', pbk: PUB, sid: 'ab12cd34', sni: 'www.microsoft.com', port: 443 });

d = decide({ native: xrayConfig({ port: 8443 }), native_active: 'active' });
assert.strictEqual(d.action, 'reuse', 'чужой Xray с VLESS Reality тоже берём');
assert.strictEqual(d.found.source, 'xray');
assert.strictEqual(d.found.pbk, PUB, 'публичный ключ выведен из приватного');
assert.strictEqual(d.found.port, 8443);

d = decide({ native: xrayConfig(), native_active: 'inactive', port: '' });
assert.strictEqual(d.action, 'error', 'остановленный чужой Xray не используем и не затираем');

d = decide({
  'docker:amnezia-xray': xrayConfig({ uuid: '11111111-2222-4333-8444-555555555555' }),
  'dockerkey:amnezia-xray:uuid': 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
  'dockerkey:amnezia-xray:public': 'PUBFROMFILE',
  'dockerkey:amnezia-xray:short_id': 'f00dbabe',
  port: 'LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("docker-proxy",pid=99,fd=4))',
});
assert.strictEqual(d.action, 'reuse', 'VLESS от Amnezia в Docker берём готовым');
assert.deepStrictEqual({ src: d.found.source, uuid: d.found.uuid, pbk: d.found.pbk, sid: d.found.sid },
  { src: 'amnezia', uuid: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', pbk: 'PUBFROMFILE', sid: 'f00dbabe' }, 'ключи из файлов Amnezia важнее конфига');

d = decide({ 'docker:amnezia-xray': xrayConfig(), port: 'LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("docker-proxy",pid=99,fd=4))' }, { force: true });
assert.strictEqual(d.action, 'error', 'переустановка поверх занятого Amnezia порта невозможна');
assert(/docker-proxy/.test(d.message) && /Amnezia/.test(d.message));

d = decide({ native: xrayConfig({ listen: '127.0.0.1' }), native_active: 'active' });
assert.strictEqual(d.action, 'error', 'вход только на localhost (за nginx) не годится, а чужой конфиг не трогаем');

d = decide({ native: xrayConfig({ protocol: 'vmess' }), native_active: 'active' });
assert.strictEqual(d.action, 'error');
assert(/Переустановить заново/.test(d.message));
assert.strictEqual(decide({ native: xrayConfig({ protocol: 'vmess' }), native_active: 'active' }, { force: true }).action, 'install');

assert.strictEqual(decide({ port: '' }).action, 'install', 'чистый сервер — ставим');
d = decide({ port: 'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=1,fd=6))' });
assert.strictEqual(d.action, 'error');
assert(/nginx/.test(d.message));
d = decide({ native: xrayConfig(), env: `UUID=${UUID}\nPUB=${PUB}`, native_active: 'active', port: 'LISTEN 0 4096 *:443 *:* users:(("xray",pid=812,fd=3))' }, { force: true });
assert.strictEqual(d.action, 'install', 'переустановка Leftik поверх своего же Xray разрешена');
console.log('ok  проверка сервера: Leftik, Xray, Amnezia, занятый порт, переустановка');

// Синтаксис bash-скриптов для сервера (если есть bash — на Windows берём из Git)
const bash = process.platform !== 'win32'
  ? 'bash'
  : ['C:\\Git\\bin\\bash.exe', 'C:\\Program Files\\Git\\bin\\bash.exe'].find((b) => fs.existsSync(b));
if (bash) {
  for (const [name, text] of [['probe', probeScript({ port: 443 })], ['install', serverScript({ port: 443, sni: 'www.microsoft.com' })]]) {
    execFileSync(bash, ['-n'], { input: text, stdio: ['pipe', 'inherit', 'inherit'] });
    if (name === 'probe') {
      // Прогон «вхолостую»: файлов Xray тут нет, но формат вывода должен разбираться
      const probe = parseProbe(execFileSync(bash, ['-s'], { input: text }).toString());
      assert.strictEqual(typeof probe.port, 'string');
      assert.strictEqual(probe.done, '');
    }
  }
  console.log('ok  bash-скрипты сервера (синтаксис и формат вывода проверки)');

  // Прогон установки с заглушками вместо системных команд и Xray
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'leftik-inst-'));
  const px = (p) => (process.platform === 'win32' ? p.replace(/\\/g, '/').replace(/^([A-Za-z]):/, (_, dr) => `/${dr.toLowerCase()}`) : p);
  const dir = (n) => { const p = path.join(tmp, n); fs.mkdirSync(p); return p; };
  const [bin, sysd, xdir, conf] = ['bin', 'systemd', 'xray', 'conf'].map(dir);
  const put = (file, body) => fs.writeFileSync(file, `#!/bin/bash\n${body}\n`, { mode: 0o755 });
  put(path.join(bin, 'id'), 'echo 0');
  put(path.join(bin, 'systemctl'), 'exit 0');
  put(path.join(bin, 'pgrep'), 'exit 1');
  put(path.join(bin, 'curl'), 'exit 0');
  put(path.join(xdir, 'xray'), [
    'case "$1" in',
    '  uuid) echo 0f9a2b3c-1d2e-4f50-8a9b-0c1d2e3f4a5b ;;',
    // Формат вывода Xray 26: «Password (PublicKey):» вместо «Public key:»
    `  x25519) printf 'PrivateKey: ${PRIV}\\nPassword (PublicKey): ${PUB}\\nHash32: x\\n' ;;`,
    '  run) grep -q \'"decryption": "none"\' "$4" ;;',
    'esac',
  ].join('\n'));
  const sandboxed = (xrayInstalled) => serverScript({ port: 443, sni: 'www.microsoft.com' })
    .replace('set -e\n', `set -e\nexport PATH="${px(bin)}:/usr/bin:/bin"\n`)
    .replace('/run/systemd/system', px(sysd))
    .replace('CONF_DIR=/usr/local/etc/xray', `CONF_DIR=${px(conf)}`)
    .replace('for p in curl unzip;', 'for p in curl;')
    .replace(/\/usr\/local\/bin\/xray/g, xrayInstalled ? px(path.join(xdir, 'xray')) : px(path.join(tmp, 'none', 'xray')));
  const runInstall = (text) => {
    const r = require('child_process').spawnSync(bash, ['-s'], { input: text });
    return { code: r.status, out: r.stdout.toString() + r.stderr.toString() };
  };

  let res = runInstall(sandboxed(true));
  assert.strictEqual(res.code, 0, res.out);
  const result = JSON.parse(res.out.split('\n').find((l) => l.startsWith('LEFTIK_RESULT ')).slice(14));
  assert.deepStrictEqual([result.uuid, result.pbk], ['0f9a2b3c-1d2e-4f50-8a9b-0c1d2e3f4a5b', PUB], 'ключи из вывода Xray 26');
  assert.strictEqual(JSON.parse(fs.readFileSync(path.join(conf, 'config.json'), 'utf8')).inbounds[0].streamSettings.realitySettings.privateKey, PRIV);

  // Официальный установщик Xray падает: его «error: …» должна попасть в сообщение пользователю
  put(path.join(bin, 'curl'), 'while [ $# -gt 0 ]; do [ "$1" = -o ] && printf \'echo "error: Download failed! Please check your network or try again."\\nexit 1\\n\' > "$2"; shift; done');
  res = runInstall(sandboxed(false));
  assert.strictEqual(res.code, 1);
  assert.strictEqual(installError(res), 'Установка не удалась: официальный установщик Xray: Download failed! Please check your network or try again.');
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log('ok  установка на сервер: успешный прогон и понятная причина ошибки');
} else {
  console.log('--  bash не найден, проверка скриптов сервера пропущена');
}

const split = (apps, sites) => ({
  apps: { mode: apps, list: ['chrome.exe', 'telegram.exe'] },
  sites: { mode: sites, list: ['youtube.com', '203.0.113.0/24'] },
});
let r = splitRouting(split('only', 'off'));
assert.strictEqual(r.final, 'direct');
assert.deepStrictEqual(r.rules, [{ process_name: ['chrome.exe', 'telegram.exe'], outbound: 'proxy' }]);
r = splitRouting(split('except', 'except'));
assert.strictEqual(r.final, 'proxy');
assert.strictEqual(r.rules.length, 2);
assert(r.rules.every((x) => x.outbound === 'direct'));
assert.deepStrictEqual(r.rules[1], { domain_suffix: ['youtube.com'], ip_cidr: ['203.0.113.0/24'], outbound: 'direct' });
r = splitRouting(split('except', 'only'));
assert.deepStrictEqual(r.rules.map((x) => x.outbound), ['direct', 'proxy'], 'исключения идут раньше включений');
assert.strictEqual(r.final, 'direct');
assert.strictEqual(splitRouting({ apps: { mode: 'only', list: [] } }).final, 'proxy', 'пустой список не включает режим');
console.log('ok  правила раздельного туннелирования');

const base = { coreExe: 'C:\\Program Files\\Leftik VPN\\core\\sing-box.exe', appExe: 'C:\\Program Files\\Leftik VPN\\Leftik VPN.exe' };
const flat = (cmds) => cmds.map((c) => c.join(' '));
let ks = flat(ruleCommands({ ...base, allowLan: true, serverIps: ['198.51.100.7'] }));
assert(ks.every((c) => c.includes(`name="${RULE}"`) && c.includes('dir=out') && c.includes('action=allow')));
assert(ks.some((c) => c.includes('program="C:\\Program Files\\Leftik VPN\\core\\sing-box.exe"')), 'путь с пробелами в кавычках');
assert(ks.some((c) => c.includes('localip=172.19.0.0/30,fdfe:dcba:9876::/126')), 'туннель');
assert(ks.some((c) => c.endsWith('remoteip=198.51.100.7')), 'IP VPN-сервера разрешён всегда');
assert(ks.some((c) => c.includes('192.168.0.0/16')), 'локальная сеть');
assert(!ks.some((c) => c.includes('remoteport=53')), 'без доменных исключений DNS закрыт');
ks = flat(ruleCommands({ ...base, allowLan: false, exceptionApps: ['C:\\Games\\game.exe'], exceptionIps: ['203.0.113.5'], allowDns: true }));
assert(!ks.some((c) => c.includes('192.168.0.0/16')));
assert(ks.some((c) => c.includes('program="C:\\Games\\game.exe"')), 'программа-исключение');
assert(ks.some((c) => c.endsWith('remoteip=203.0.113.5')), 'IP-исключение');
assert.strictEqual(ks.filter((c) => c.includes('remoteport=53')).length, 2, 'DNS по UDP и TCP');
console.log('ok  правила kill switch и исключения');

const polluted = ['domain', 'private', 'public'].map((name) => ({ name, state: 'off', inbound: 'blockinbound', outbound: 'blockoutbound' }));
const legacyPs1 = ['Domain', 'Private', 'Public'].map((n) => `Set-NetFirewallProfile -Name '${n}' -Enabled True -DefaultOutboundAction NotConfigured`).join('\r\n');
const restore = restoreScript(polluted, legacyPs1);
assert(!restore.includes('blockoutbound'), 'восстановление всегда разрешает исходящий трафик');
assert.strictEqual((restore.match(/state on/g) || []).length, 3, 'из старого резерва берём «брандмауэр был включён»');
assert(restoreScript(polluted).includes('domainprofile state off'), 'без резерва — текущее состояние');
console.log('ok  файл восстановления брандмауэра');

const exe = path.join(__dirname, '..', 'core', 'sing-box.exe');
if (fs.existsSync(exe)) {
  const cases = [
    [s, {}],
    [ws, {}],
    [s, { split: split('only', 'off') }],
    [s, { split: split('except', 'except') }],
    [s, { split: split('only', 'only') }],
    [s, { split: split('except', 'only'), dns: '8.8.8.8' }],
  ];
  cases.forEach(([server, settings], i) => {
    const file = path.join(os.tmpdir(), `leftik-check-${i}.json`);
    fs.writeFileSync(file, JSON.stringify(buildConfig(server, settings, { appExe: process.execPath })));
    execFileSync(exe, ['check', '-c', file], { stdio: 'inherit' });
    fs.rmSync(file);
  });
  console.log(`ok  sing-box check принял ${cases.length} конфигов`);
} else {
  console.log('--  sing-box.exe не найден, проверка конфига пропущена');
}
