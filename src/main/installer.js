// Установка Xray (VLESS + Reality + Vision) на свой сервер по SSH: IP, логин, пароль
const { Client } = require('ssh2');

const MARK = 'LEFTIK_RESULT ';

function serverScript({ port, sni }) {
  return `#!/bin/bash
set -e
PORT=${Number(port)}
SNI='${sni.replace(/[^a-zA-Z0-9.-]/g, '')}'
CONF_DIR=/usr/local/etc/xray
STATE=$CONF_DIR/leftik.env
export DEBIAN_FRONTEND=noninteractive

say() { echo "[leftik] $*"; }

if ! command -v curl >/dev/null 2>&1; then
  say "ставлю curl"
  if command -v apt-get >/dev/null 2>&1; then apt-get update -y >/dev/null && apt-get install -y curl >/dev/null
  elif command -v dnf >/dev/null 2>&1; then dnf install -y curl >/dev/null
  elif command -v yum >/dev/null 2>&1; then yum install -y curl >/dev/null
  else say "не удалось установить curl"; exit 1; fi
fi

if [ ! -x /usr/local/bin/xray ]; then
  say "скачиваю и устанавливаю Xray"
  bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null
fi
XRAY=/usr/local/bin/xray
mkdir -p $CONF_DIR

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

$XRAY run -test -config $CONF_DIR/config.json >/dev/null

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q active; then ufw allow $PORT/tcp >/dev/null; fi
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd --permanent --add-port=$PORT/tcp >/dev/null && firewall-cmd --reload >/dev/null
fi

systemctl enable xray >/dev/null 2>&1 || true
systemctl restart xray
sleep 1
systemctl is-active --quiet xray || { say "Xray не запустился"; journalctl -u xray -n 20 --no-pager; exit 1; }

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

async function installServer(params, onLog = () => {}) {
  const { host, username, password } = params;
  const port = Number(params.port) || 443;
  const sni = (params.sni || 'www.microsoft.com').trim();
  if (!host || !username || !password) throw new Error('Заполните IP, логин и пароль');

  onLog(`Подключаюсь по SSH к ${host}...`);
  const conn = await connectSsh(params);
  try {
    onLog('SSH подключён, загружаю скрипт установки');
    const scriptPath = '/tmp/leftik-install.sh';
    await exec(conn, `cat > ${scriptPath} && chmod 700 ${scriptPath}`, { stdin: serverScript({ port, sni }) });

    const cmd = username === 'root'
      ? `bash ${scriptPath}; R=$?; rm -f ${scriptPath}; exit $R`
      : `sudo -k -S -p '' bash ${scriptPath}; R=$?; rm -f ${scriptPath}; exit $R`;
    const res = await exec(conn, cmd, {
      stdin: username === 'root' ? undefined : `${password}\n`,
      onLine: (l) => !l.startsWith(MARK) && onLog(l),
    });

    const line = res.out.split(/\r?\n/).find((l) => l.startsWith(MARK));
    if (res.code !== 0 || !line) {
      if (/sudo|password|not in the sudoers/i.test(res.out)) {
        throw new Error('Нет прав sudo у этого пользователя — войдите как root');
      }
      throw new Error(`Установка не удалась (код ${res.code}). Подробности в журнале.`);
    }
    const r = JSON.parse(line.slice(MARK.length));
    onLog('Сервер готов');
    return {
      name: params.name || `Leftik · ${host}`,
      host,
      port,
      uuid: r.uuid,
      security: 'reality',
      transport: 'tcp',
      flow: 'xtls-rprx-vision',
      sni,
      fp: 'chrome',
      pbk: r.pbk,
      sid: r.sid,
      selfHosted: true,
    };
  } finally {
    conn.end();
  }
}

module.exports = { installServer, serverScript };
