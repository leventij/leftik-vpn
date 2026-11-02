// Самопроверка без сервера: разбор ключей, сборка конфига и проверка его ядром sing-box
const fs = require('fs');
const os = require('os');
const path = require('path');
const assert = require('assert');
const { execFileSync } = require('child_process');
const { parseVless, buildVless } = require('../src/main/vless');
const { buildConfig, splitRouting } = require('../src/main/singbox');
const { ruleCommands, restoreScript, RULE } = require('../src/main/killswitch');
const { serverScript } = require('../src/main/installer');

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
