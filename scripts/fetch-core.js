// Скачивает ядро sing-box (VLESS + TUN) с официального GitHub SagerNet в ./core
const fs = require('fs');
const path = require('path');
const https = require('https');
const { execFileSync } = require('child_process');

const VERSION = '1.14.3';
const NAME = `sing-box-${VERSION}-windows-amd64`;
const URL = `https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/${NAME}.zip`;
const coreDir = path.join(__dirname, '..', 'core');
const exe = path.join(coreDir, 'sing-box.exe');

if (process.platform !== 'win32') {
  console.log('[fetch-core] не Windows — пропускаю загрузку sing-box');
  process.exit(0);
}
if (fs.existsSync(exe)) {
  console.log('[fetch-core] sing-box уже есть:', exe);
  process.exit(0);
}

function download(url, dest, redirects = 0) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { 'User-Agent': 'leftik-vpn' } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location && redirects < 5) {
        res.resume();
        return resolve(download(res.headers.location, dest, redirects + 1));
      }
      if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode} для ${url}`));
      const out = fs.createWriteStream(dest);
      res.pipe(out);
      out.on('finish', () => out.close(resolve));
      out.on('error', reject);
    }).on('error', reject);
  });
}

(async () => {
  fs.mkdirSync(coreDir, { recursive: true });
  const zip = path.join(coreDir, `${NAME}.zip`);
  console.log('[fetch-core] скачиваю', URL);
  await download(URL, zip);
  const tmp = path.join(coreDir, 'tmp');
  execFileSync('powershell.exe', ['-NoProfile', '-Command',
    `Expand-Archive -LiteralPath '${zip}' -DestinationPath '${tmp}' -Force`], { stdio: 'inherit' });
  fs.copyFileSync(path.join(tmp, NAME, 'sing-box.exe'), exe);
  fs.rmSync(tmp, { recursive: true, force: true });
  fs.rmSync(zip, { force: true });
  console.log('[fetch-core] готово:', exe);
})().catch((e) => {
  console.error('[fetch-core] ошибка:', e.message);
  process.exit(1);
});
