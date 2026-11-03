// Проверка сервера перед установкой: есть ли уже рабочий VLESS + Reality
// (наш, чужой Xray или Amnezia в Docker) и свободен ли порт.
// Скрипт на сервере только читает, всё решение принимается здесь — так его можно проверить тестами.
const crypto = require('crypto');

const MARK = 'LEFTIK_PROBE ';

// Сайт маскировки REALITY по умолчанию: маленький сертификат (~3,2 КБ), TLS 1.3, h2.
// www.microsoft.com не годится: его запись с сертификатом ~8270 байт больше лимита
// REALITY в Xray 26.6.27 (8192), и рукопожатие обрывается — клиент видит EOF (Xray-core#6356).
const DEFAULT_SNI = 'gateway.icloud.com';
const MAX_TARGET_RECORD = 8192;
const BAD_MASK_SITES = ['www.microsoft.com', 'microsoft.com'];

function probeScript({ port }) {
  return `#!/bin/bash
PORT=${Number(port)}
CONF_DIR=/usr/local/etc/xray
b64() { base64 -w0 2>/dev/null || base64 | tr -d '\\n'; }
emit() { echo "${MARK}$1 $(printf '%s' "$2" | b64)"; }

[ -f $CONF_DIR/config.json ] && emit native "$(cat $CONF_DIR/config.json)"
[ -f $CONF_DIR/leftik.env ] && emit env "$(cat $CONF_DIR/leftik.env)"
[ -x /usr/local/bin/xray ] && emit native_version "$(/usr/local/bin/xray version 2>/dev/null | head -n 1)"
command -v systemctl >/dev/null 2>&1 && emit native_active "$(systemctl is-active xray 2>/dev/null)"

# Amnezia держит Xray в Docker-контейнере, ключи и конфиг — в /opt/amnezia/xray
if command -v docker >/dev/null 2>&1; then
  for c in $(docker ps --format '{{.Names}}' 2>/dev/null | grep -i xray); do
    cfg=$(docker exec "$c" cat /opt/amnezia/xray/server.json 2>/dev/null) && emit "docker:$c" "$cfg"
    for k in uuid public short_id; do
      v=$(docker exec "$c" cat /opt/amnezia/xray/xray_$k.key 2>/dev/null) && emit "dockerkey:$c:$k" "$v"
    done
    v=$(docker exec "$c" xray version 2>/dev/null | head -n 1) && emit "dockerkey:$c:version" "$v"
  done
fi

if command -v ss >/dev/null 2>&1; then
  emit port "$(ss -ltnp 2>/dev/null | grep -E "[:.]$PORT[[:space:]]")"
else
  emit port "$(netstat -ltnp 2>/dev/null | grep -E "[:.]$PORT[[:space:]]")"
fi
echo "${MARK}done x"
`;
}

// Вывод скрипта -> { native, env, native_active, port, docker: { name: { config, uuid, public, short_id } } }
function parseProbe(out) {
  const r = { docker: {} };
  for (const line of String(out).split(/\r?\n/)) {
    if (!line.startsWith(MARK)) continue;
    const [key, b64 = ''] = line.slice(MARK.length).trim().split(' ');
    const val = Buffer.from(b64, 'base64').toString('utf8').trim();
    if (key.startsWith('docker:')) {
      const name = key.slice(7);
      (r.docker[name] ||= {}).config = val;
    } else if (key.startsWith('dockerkey:')) {
      const [, name, k] = key.split(':');
      (r.docker[name] ||= {})[k] = val;
    } else {
      r[key] = val;
    }
  }
  return r;
}

// Публичный ключ Reality из приватного (X25519, base64url без паддинга — как у Xray)
function realityPublicKey(privateKey) {
  const raw = Buffer.from(String(privateKey).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  if (raw.length !== 32) return null;
  const der = Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), raw]);
  const pub = crypto.createPublicKey(crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' }));
  return pub.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64url');
}

function parseEnv(text) {
  return Object.fromEntries(String(text || '').split(/\r?\n/)
    .map((l) => l.match(/^(\w+)=(.*)$/)).filter(Boolean).map((m) => [m[1], m[2].trim()]));
}

// Все входящие VLESS + Reality из конфига Xray, доступные снаружи
function realityInbounds(configText) {
  let cfg;
  try {
    cfg = JSON.parse(configText);
  } catch {
    return [];
  }
  return (cfg.inbounds || []).flatMap((ib) => {
    const st = ib.streamSettings || {};
    const rs = st.realitySettings || {};
    const client = (ib.settings?.clients || [])[0];
    const local = /^(127\.|::1$|localhost$)/.test(ib.listen || '');
    if (ib.protocol !== 'vless' || st.security !== 'reality' || !client?.id || local) return [];
    if ((st.network || 'tcp') !== 'tcp') return [];
    return [{
      port: Number(ib.port),
      uuid: client.id,
      flow: client.flow || '',
      privateKey: rs.privateKey || '',
      sid: (rs.shortIds || []).find((s) => s) || '',
      sni: (rs.serverNames || [])[0] || '',
    }];
  });
}

// Версия Xray из «Xray 26.10.21 (Xray, Penetrates Everything.) …» → [26, 10, 21] или null
function xrayVersion(line) {
  const m = String(line || '').match(/Xray\s+v?(\d+)\.(\d+)\.(\d+)/i);
  return m ? m.slice(1).map(Number) : null;
}

// Совместим ли сервер с клиентом sing-box: Xray 26.7+ отвергает его REALITY (см. XRAY_VERSION в installer.js).
// Неизвестную версию считаем совместимой — проверка связи при подключении всё равно покажет проблему.
function compatibleXray(version) {
  if (!version) return true;
  const [major, minor] = version;
  return major < 26 || (major === 26 && minor < 7);
}

// Решение по результатам проверки: reuse (взять готовый ключ), install или error
function analyzeProbe(probe, { port, force, sni = DEFAULT_SNI }) {
  const found = [];
  const env = parseEnv(probe.env);
  const nativeActive = probe.native_active === 'active';
  const nativeVer = xrayVersion(probe.native_version);

  if (probe.native && nativeActive) {
    for (const ib of realityInbounds(probe.native)) {
      const ours = env.UUID && env.UUID === ib.uuid;
      found.push({
        ...ib,
        pbk: (ours && env.PUB) || realityPublicKey(ib.privateKey),
        source: ours ? 'leftik' : 'xray',
        version: nativeVer,
      });
    }
  }
  for (const [name, d] of Object.entries(probe.docker || {})) {
    for (const ib of realityInbounds(d.config)) {
      found.push({
        ...ib,
        uuid: d.uuid || ib.uuid,
        sid: d.short_id || ib.sid,
        pbk: d.public || realityPublicKey(ib.privateKey),
        source: 'amnezia',
        container: name,
        version: xrayVersion(d.version),
      });
    }
  }
  const usable = found.filter((f) => f.pbk && f.uuid && f.port && f.sni);
  const order = { leftik: 0, amnezia: 1, xray: 2 };
  usable.sort((a, b) => order[a.source] - order[b.source]);
  const badMask = (f) => BAD_MASK_SITES.includes(String(f.sni).toLowerCase());
  const working = usable.filter((f) => compatibleXray(f.version) && !badMask(f));
  const tooNew = usable.filter((f) => !compatibleXray(f.version));
  const ver = (f) => f.version.join('.');

  if (!force && working.length) return { action: 'reuse', found: working[0] };

  // Своя установка с проблемной маскировкой — переставляем с новой (ключи сохранятся)
  const ownBadMask = usable.find((f) => f.source === 'leftik' && badMask(f));
  if (!force && ownBadMask && !BAD_MASK_SITES.includes(sni)) {
    return { action: 'install', note: `Маскировка ${ownBadMask.sni} обрывает подключения (слишком большой сертификат) — меняю её на ${sni}, ключи сохранятся` };
  }

  // Свой Xray слишком новый — переставляем совместимую версию, ключи сохраняются
  const ownTooNew = tooNew.find((f) => f.source === 'leftik');
  if (!force && ownTooNew) {
    return { action: 'install', note: `На сервере Xray ${ver(ownTooNew)} — он несовместим с Leftik, ставлю совместимую версию (ключи сохранятся)` };
  }

  // Чужой Xray (не Leftik) не трогаем без явного «переустановить»
  if (probe.native && !probe.env && !force) {
    const foreign = tooNew.find((f) => f.source === 'xray');
    return {
      action: 'error',
      message: foreign
        ? `На сервере уже есть VLESS Reality на Xray ${ver(foreign)}, но эта версия несовместима с Leftik (новые Xray отвергают его подключение). Включите «Переустановить заново» в разделе «Дополнительно» — Leftik поставит совместимую версию, а прежний конфиг сохранит в копии.`
        : 'На сервере уже есть Xray с другой настройкой. Чтобы её не сломать, Leftik ничего не менял. Если её можно заменить, включите «Переустановить заново» в разделе «Дополнительно».',
    };
  }
  // Порт должен быть свободен или занят нашим же Xray (его перезапустим)
  const busy = String(probe.port || '').split(/\r?\n/).filter((l) => l.trim() && !/"xray"/.test(l));
  if (busy.length) {
    const proc = (busy[0].match(/users:\(\("([^"]+)"/) || [])[1] || 'другая программа';
    const amnezia = tooNew.find((f) => f.source === 'amnezia' && f.port === port);
    if (amnezia) {
      return { action: 'error', message: `На сервере есть VLESS от Amnezia, но его Xray ${ver(amnezia)} несовместим с Leftik. Amnezia занимает порт ${port}: укажите в разделе «Дополнительно» другой порт VPN (например, 8443) — Leftik поставит рядом свой совместимый Xray, Amnezia продолжит работать.` };
    }
    const hint = proc === 'docker-proxy' ? ' (похоже, Docker-контейнер, например Amnezia)' : '';
    return { action: 'error', message: `Порт ${port} на сервере уже занят: ${proc}${hint}. Укажите другой порт в разделе «Дополнительно».` };
  }
  return { action: 'install' };
}

module.exports = {
  probeScript, parseProbe, analyzeProbe, realityInbounds, realityPublicKey, xrayVersion, compatibleXray,
  MARK, DEFAULT_SNI, MAX_TARGET_RECORD, BAD_MASK_SITES,
};
