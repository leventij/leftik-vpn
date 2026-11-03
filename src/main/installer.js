// Установка Xray (VLESS + Reality + Vision) на свой сервер по SSH: IP, логин, пароль
const { Client } = require('ssh2');
const { probeScript, parseProbe, analyzeProbe } = require('./probe');

const MARK = 'LEFTIK_RESULT ';

function serverScript({ port, sni }) {
  return `#!/bin/bash
set -e
PORT=${Number(port)}
SNI='${sni.replace(/[^a-zA-Z0-9.-]/g, '')}'
CONF_DIR=/usr/local/etc/xray
STATE=$CONF_DIR/leftik.env
LOG=/tmp/leftik-xray-install.log
export DEBIAN_FRONTEND=noninteractive

say() { echo "[leftik] $*"; }
fail() { say "ОШИБКА: $*"; exit 1; }
# Любая неожиданная ошибка — с понятной причиной, а не просто «код 1»
trap 'rc=$?; say "ОШИБКА: команда «$BASH_COMMAND» завершилась с кодом $rc"' ERR

[ "$(id -u)" = 0 ] || fail "нужны права root"
command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] \\
  || fail "на сервере нет systemd — Xray так не установить (нужна обычная Ubuntu/Debian/CentOS, не контейнер OpenVZ/LXC)"

# На свежем VPS система часто сама ставит обновления и держит apt/dpkg — ждём до 5 минут
wait_pkg_lock() {
  for i in $(seq 1 60); do
    pgrep -x 'apt|apt-get|dpkg|unattended-upgr|yum|dnf' >/dev/null 2>&1 || return 0
    [ "$i" = 1 ] && say "система сейчас обновляет пакеты — жду, пока закончит"
    sleep 5
  done
  fail "менеджер пакетов занят больше 5 минут — попробуйте позже"
}

# curl и unzip нужны установщику Xray; ставим сами, чтобы видеть ошибки
NEED=""
for p in curl unzip; do command -v $p >/dev/null 2>&1 || NEED="$NEED $p"; done
if [ -n "$NEED" ]; then
  say "ставлю:$NEED"
  wait_pkg_lock
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y >$LOG 2>&1 && apt-get install -y --no-install-recommends $NEED >>$LOG 2>&1
  elif command -v dnf >/dev/null 2>&1; then dnf install -y $NEED >$LOG 2>&1
  elif command -v yum >/dev/null 2>&1; then yum install -y $NEED >$LOG 2>&1
  else false; fi || {
    tail -n 6 $LOG
    ERR=$(grep -E '^(E|Error):' $LOG | tail -n 1)
    fail "не удалось установить$NEED\${ERR:+: $ERR}"
  }
fi

if [ ! -x /usr/local/bin/xray ]; then
  say "скачиваю установщик Xray с GitHub"
  curl -fsSL --retry 3 --connect-timeout 15 -o /tmp/leftik-xray-release.sh \\
    https://github.com/XTLS/Xray-install/raw/main/install-release.sh \\
    || fail "не удалось скачать установщик Xray — у сервера нет доступа к github.com?"
  say "устанавливаю Xray"
  wait_pkg_lock
  # Установщик Xray пишет причину ошибки в обычный вывод — сохраняем и показываем её
  if ! bash /tmp/leftik-xray-release.sh install >$LOG 2>&1; then
    tail -n 6 $LOG
    ERR=$(grep -i '^error' $LOG | tail -n 1 | sed 's/^error: *//I')
    fail "официальный установщик Xray: \${ERR:-завершился с ошибкой (журнал выше)}"
  fi
  rm -f /tmp/leftik-xray-release.sh
fi
XRAY=/usr/local/bin/xray
[ -x $XRAY ] || fail "Xray не установился ($XRAY не найден)"
mkdir -p $CONF_DIR

# Чужой конфиг Xray (при «Переустановить заново») не удаляем, а откладываем в копию
if [ -f $CONF_DIR/config.json ] && [ ! -f "$STATE" ]; then
  BAK=$CONF_DIR/config.json.bak.$(date +%Y%m%d-%H%M%S)
  cp $CONF_DIR/config.json "$BAK"
  say "прежний конфиг Xray сохранён в $BAK"
fi

if [ -f "$STATE" ]; then
  say "найдена прошлая установка Leftik — использую её ключи"
  . "$STATE"
else
  say "генерирую ключи"
  UUID=$($XRAY uuid)
  KEYS=$($XRAY x25519)
  PRIV=$(echo "$KEYS" | awk -F': *' '/^Private/{print $2; exit}')
  PUB=$(echo "$KEYS" | awk -F': *' '/^(Public|Password)/{print $2; exit}')
  SID=$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \\n')
fi
if [ -z "$UUID" ] || [ -z "$PRIV" ] || [ -z "$PUB" ]; then say "не удалось сгенерировать ключи"; exit 1; fi
cat > "$STATE" <<EOF
UUID=$UUID
PRIV=$PRIV
PUB=$PUB
SID=$SID
EOF
chmod 600 "$STATE"

say "пишу конфиг: порт $PORT, маскировка $SNI"
cat > $CONF_DIR/config.json <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [{
    "listen": "0.0.0.0",
    "port": $PORT,
    "protocol": "vless",
    "settings": {
      "clients": [{ "id": "$UUID", "flow": "xtls-rprx-vision" }],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "dest": "$SNI:443",
        "serverNames": ["$SNI"],
        "privateKey": "$PRIV",
        "shortIds": ["$SID"]
      }
    },
    "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] }
  }],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "block" }
  ]
}
EOF

TEST=$($XRAY run -test -config $CONF_DIR/config.json 2>&1) || { echo "$TEST" | tail -n 8; fail "Xray отклонил конфиг"; }

# Брандмауэр: открываем порт, но его ошибки установку не роняют
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow $PORT/tcp >/dev/null 2>&1 || say "не удалось открыть порт $PORT в ufw — откройте вручную"
fi
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  { firewall-cmd --permanent --add-port=$PORT/tcp && firewall-cmd --reload; } >/dev/null 2>&1 || say "не удалось открыть порт $PORT в firewalld"
fi

systemctl enable xray >/dev/null 2>&1 || true
systemctl restart xray || true
sleep 2
systemctl is-active --quiet xray || { journalctl -u xray -n 15 --no-pager; fail "Xray не запустился (журнал выше)"; }

say "готово"
echo "${MARK}{\\"uuid\\":\\"$UUID\\",\\"pbk\\":\\"$PUB\\",\\"sid\\":\\"$SID\\"}"
`;
}

function exec(conn, cmd, { stdin, onLine } = {}) {
  return new Promise((resolve, reject) => {
    conn.exec(cmd, (err, stream) => {
      if (err) return reject(err);
      let out = '';
      let buf = '';
      const push = (chunk) => {
        const s = chunk.toString();
        out += s;
        buf += s;
        const lines = buf.split(/\r?\n/);
        buf = lines.pop();
        lines.forEach((l) => onLine && l.trim() && onLine(l));
      };
      stream.on('data', push);
      stream.stderr.on('data', push);
      stream.on('close', (code) => {
        if (buf.trim() && onLine) onLine(buf);
        resolve({ code, out });
      });
      if (stdin) stream.end(stdin);
    });
  });
}

function connectSsh({ host, sshPort, username, password }) {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    conn
      .on('ready', () => resolve(conn))
      .on('error', (e) => {
        const msg = /authentication/i.test(e.message)
          ? 'Неверный логин или пароль'
          : /ETIMEDOUT|timed out/i.test(e.message)
            ? 'Сервер не отвечает (проверьте IP и порт SSH)'
            : /ECONNREFUSED/.test(e.message)
              ? 'Порт SSH закрыт'
              : e.message;
        reject(new Error(msg));
      })
      .connect({
        host,
        port: Number(sshPort) || 22,
        username,
        password,
        readyTimeout: 20000,
        tryKeyboard: true,
      })
      .on('keyboard-interactive', (_n, _i, _l, prompts, finish) => finish(prompts.map(() => password)));
  });
}

// Заливает скрипт во /tmp и выполняет от root (через sudo, если вошли не под root)
async function runRemote(conn, { username, password }, name, script, onLine) {
  const scriptPath = `/tmp/leftik-${name}.sh`;
  await exec(conn, `cat > ${scriptPath} && chmod 700 ${scriptPath}`, { stdin: script });
  const cmd = username === 'root'
    ? `bash ${scriptPath}; R=$?; rm -f ${scriptPath}; exit $R`
    : `sudo -k -S -p '' bash ${scriptPath}; R=$?; rm -f ${scriptPath}; exit $R`;
  const res = await exec(conn, cmd, { stdin: username === 'root' ? undefined : `${password}\n`, onLine });
  if (res.code !== 0 && /sudo|not in the sudoers/i.test(res.out)) {
    throw new Error('Нет прав sudo у этого пользователя — войдите как root');
  }
  return res;
}

// Текст ошибки установки: причина из скрипта («[leftik] ОШИБКА: …»), а не просто код выхода
function installError({ code, out }) {
  const lines = String(out).split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const reason = lines.filter((l) => l.startsWith('[leftik] ОШИБКА:')).pop();
  if (reason) return `Установка не удалась: ${reason.slice('[leftik] ОШИБКА:'.length).trim()}`;
  const last = lines.filter((l) => !l.startsWith(MARK)).pop();
  return `Установка не удалась (код ${code})${last ? `: ${last}` : ''}. Подробности в журнале выше.`;
}

const SOURCE_NAMES = {
  leftik: 'VLESS Reality, установленный Leftik',
  amnezia: 'VLESS Reality от Amnezia',
  xray: 'VLESS Reality (Xray)',
};

// Возвращает { server, reused }: reused — откуда взят уже работающий VLESS, если ставить не пришлось
async function installServer(params, onLog = () => {}) {
  const { host, username, password } = params;
  const port = Number(params.port) || 443;
  const sni = (params.sni || 'www.microsoft.com').trim();
  const force = params.force === true || params.force === 'on';
  if (!host || !username || !password) throw new Error('Заполните IP, логин и пароль');

  const serverFrom = (r) => ({
    name: params.name || `Leftik · ${host}`,
    host,
    port: r.port,
    uuid: r.uuid,
    security: 'reality',
    transport: 'tcp',
    flow: r.flow,
    sni: r.sni,
    fp: 'chrome',
    pbk: r.pbk,
    sid: r.sid,
    selfHosted: true,
  });

  onLog(`Подключаюсь по SSH к ${host}...`);
  const conn = await connectSsh(params);
  try {
    onLog('SSH подключён, проверяю, что уже есть на сервере');
    const probeRes = await runRemote(conn, params, 'probe', probeScript({ port }));
    const decision = analyzeProbe(parseProbe(probeRes.out), { port, force });

    if (decision.action === 'reuse') {
      const f = decision.found;
      onLog(`Найден работающий ${SOURCE_NAMES[f.source]} на порту ${f.port} — устанавливать заново не нужно`);
      if (f.port !== port || f.sni !== sni) {
        onLog(`Порт и маскировка взяты с сервера (${f.port}, ${f.sni}). Чтобы поменять их, включите «Переустановить заново».`);
      }
      return { server: serverFrom(f), reused: f.source };
    }
    if (decision.action === 'error') throw new Error(decision.message);

    onLog(force ? 'Переустанавливаю по запросу' : 'VLESS на сервере нет — устанавливаю');
    const res = await runRemote(conn, params, 'install', serverScript({ port, sni }), (l) => !l.startsWith(MARK) && onLog(l));
    const line = res.out.split(/\r?\n/).find((l) => l.startsWith(MARK));
    if (res.code !== 0 || !line) throw new Error(installError(res));
    const r = JSON.parse(line.slice(MARK.length));
    onLog('Сервер готов');
    return { server: serverFrom({ ...r, port, sni, flow: 'xtls-rprx-vision' }), reused: null };
  } finally {
    conn.end();
  }
}

module.exports = { installServer, serverScript, installError };
