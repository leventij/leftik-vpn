// Ядро подключения: собирает конфиг sing-box (TUN -> VLESS) и управляет процессом
const fs = require('fs');
const path = require('path');
const http = require('http');
const { spawn, execFile } = require('child_process');
const { EventEmitter } = require('events');

const API_PORT = 9095;
const TUN_V4 = '172.19.0.1/30';
const TUN_V6 = 'fdfe:dcba:9876::1/126';

function buildOutbound(s) {
  const out = {
    type: 'vless',
    tag: 'proxy',
    server: s.host,
    server_port: Number(s.port),
    uuid: s.uuid,
  };
  if (s.flow) out.flow = s.flow;
  if (s.security === 'tls' || s.security === 'reality') {
    out.tls = {
      enabled: true,
      server_name: s.sni || s.host,
      utls: { enabled: true, fingerprint: s.fp || 'chrome' },
    };
    if (s.alpn) out.tls.alpn = s.alpn.split(',').map((a) => a.trim()).filter(Boolean);
    if (s.security === 'reality') {
      out.tls.reality = { enabled: true, public_key: s.pbk, short_id: s.sid || '' };
    }
  }
  if (s.transport === 'ws') {
    out.transport = { type: 'ws', path: s.path || '/' };
    if (s.hostHeader) out.transport.headers = { Host: s.hostHeader };
  } else if (s.transport === 'httpupgrade') {
    out.transport = { type: 'httpupgrade', path: s.path || '/' };
    if (s.hostHeader) out.transport.host = s.hostHeader;
  } else if (s.transport === 'grpc') {
    out.transport = { type: 'grpc', service_name: s.serviceName || '' };
  }
  return out;
}

const isCidr = (v) => /^[0-9.]+\/\d+$/.test(v) || (v.includes(':') && /^[0-9a-f:]+\/\d+$/i.test(v));

// Поля правила sing-box для списка сайтов: домены (с поддоменами) и IP/подсети
function siteMatch(list) {
  const match = {};
  const domains = list.filter((v) => !isCidr(v));
  const cidrs = list.filter(isCidr);
  if (domains.length) match.domain_suffix = domains;
  if (cidrs.length) match.ip_cidr = cidrs;
  return match;
}

// Раздельное туннелирование. Исключения важнее включений; если включён хоть один
// режим «только эти», всё остальное идёт напрямую.
function splitRouting(split = {}) {
  const apps = split.apps || {};
  const sites = split.sites || {};
  const on = (x) => x.mode && x.mode !== 'off' && Array.isArray(x.list) && x.list.length > 0;
  const rules = [];
  const dnsRules = [];

  if (on(apps) && apps.mode === 'except') rules.push({ process_name: apps.list, outbound: 'direct' });
  if (on(sites) && sites.mode === 'except') {
    rules.push({ ...siteMatch(sites.list), outbound: 'direct' });
    if (siteMatch(sites.list).domain_suffix) dnsRules.push({ domain_suffix: sites.list.filter((v) => !isCidr(v)), server: 'local' });
  }
  if (on(apps) && apps.mode === 'only') rules.push({ process_name: apps.list, outbound: 'proxy' });
  if (on(sites) && sites.mode === 'only') {
    rules.push({ ...siteMatch(sites.list), outbound: 'proxy' });
    if (siteMatch(sites.list).domain_suffix) dnsRules.push({ domain_suffix: sites.list.filter((v) => !isCidr(v)), server: 'remote' });
  }
  const onlyMode = (on(apps) && apps.mode === 'only') || (on(sites) && sites.mode === 'only');
  return { rules, dnsRules, final: onlyMode ? 'direct' : 'proxy' };
}

function buildConfig(server, settings = {}, ctx = {}) {
  const split = splitRouting(settings.split);
  const rules = [
    { action: 'sniff' },
    { protocol: 'dns', action: 'hijack-dns' },
    { ip_is_private: true, outbound: 'direct' },
  ];
  // Собственные соединения Leftik (SSH-установка, пинг) идут мимо туннеля
  if (ctx.appExe) rules.push({ process_path: [ctx.appExe], outbound: 'direct' });
  rules.push(...split.rules);

  return {
    log: { level: 'info', timestamp: true },
    dns: {
      servers: [
        { type: 'https', tag: 'remote', server: settings.dns || '1.1.1.1', detour: 'proxy' },
        { type: 'local', tag: 'local' },
      ],
      rules: split.dnsRules,
      final: split.final === 'direct' ? 'local' : 'remote',
      strategy: 'prefer_ipv4',
    },
    inbounds: [
      {
        type: 'tun',
        tag: 'tun-in',
        interface_name: 'LeftikVPN',
        address: [TUN_V4, TUN_V6],
        mtu: 9000,
        auto_route: true,
        strict_route: true,
        stack: 'mixed',
      },
    ],
    outbounds: [buildOutbound(server), { type: 'direct', tag: 'direct' }],
    route: {
      rules,
      final: split.final,
      auto_detect_interface: true,
      default_domain_resolver: 'local',
    },
    experimental: {
      clash_api: { external_controller: `127.0.0.1:${API_PORT}` },
    },
  };
}

// Добивает «осиротевшее» ядро (например, если окно Leftik упало). PID последнего запуска
// хранится в core.pid; tasklist/taskkill работают мгновенно и без сети — в отличие от PowerShell,
// который при включённом kill switch мог подвисать и срывать подключение.
function killStrayCores(workDir) {
  const pidFile = path.join(workDir, 'core.pid');
  let pid;
  try {
    pid = Number(fs.readFileSync(pidFile, 'utf8'));
  } catch {
    return Promise.resolve();
  }
  const drop = () => fs.rmSync(pidFile, { force: true });
  if (!pid || process.platform !== 'win32') return Promise.resolve(drop());
  return new Promise((resolve) => {
    execFile('tasklist', ['/FI', `PID eq ${pid}`, '/FO', 'CSV', '/NH'], { windowsHide: true }, (err, out) => {
      if (err || !/"sing-box\.exe"/i.test(out)) return resolve(drop());
      execFile('taskkill', ['/PID', String(pid), '/T', '/F'], { windowsHide: true }, () => resolve(drop()));
    });
  });
}

class Core extends EventEmitter {
  constructor(exePath, workDir) {
    super();
    this.exePath = exePath;
    this.workDir = workDir;
    this.proc = null;
    this.state = 'disconnected';
    this.logs = [];
    this.trafficReq = null;
    this.stopping = false;
    this.gen = 0;
  }

  log(line) {
    const text = line.replace(/\x1b\[[0-9;]*m/g, '').trimEnd();
    if (!text) return;
    this.logs.push(text);
    if (this.logs.length > 500) this.logs.shift();
    this.emit('log', text);
  }

  setState(state, error) {
    this.state = state;
    this.emit('state', { state, error: error || null });
  }

  async connect(server, config) {
    if (this.proc || this.state === 'connecting') await this.disconnect();
    if (!fs.existsSync(this.exePath)) {
      throw new Error(`Не найдено ядро sing-box: ${this.exePath}. Запустите npm install.`);
    }
    // Каждый disconnect() увеличивает gen — так отменяется подключение, ядро которого ещё не запущено
    const gen = ++this.gen;
    this.stopping = false;
    this.setState('connecting');
    this.log(`[leftik] подключение к ${server.host}:${server.port}`);
    await killStrayCores(this.workDir);
    if (gen !== this.gen) throw new Error('CANCELLED');
    fs.mkdirSync(this.workDir, { recursive: true });
    const cfgPath = path.join(this.workDir, 'config.json');
    fs.writeFileSync(cfgPath, JSON.stringify(config, null, 2));

    return new Promise((resolve, reject) => {
      const proc = spawn(this.exePath, ['run', '-c', cfgPath, '-D', this.workDir], {
        windowsHide: true,
      });
      this.proc = proc;
      if (proc.pid) fs.writeFileSync(path.join(this.workDir, 'core.pid'), String(proc.pid));
      let settled = false;
      const finish = (err) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (err) reject(err);
        else resolve();
      };
      const timer = setTimeout(() => {
        finish(new Error('Ядро не запустилось за 20 секунд'));
        this.disconnect();
      }, 20000);

      let buf = '';
      const onData = (chunk) => {
        buf += chunk.toString();
        const lines = buf.split(/\r?\n/);
        buf = lines.pop();
        for (const l of lines) {
          this.log(l);
          if (this.state === 'connecting' && /sing-box started/i.test(l)) {
            this.setState('connected');
            this.startTraffic();
            finish();
          }
        }
      };
      proc.stdout.on('data', onData);
      proc.stderr.on('data', onData);
      proc.on('error', (e) => {
        if (this.proc !== proc) return finish(e);
        this.proc = null;
        this.setState('disconnected', e.message);
        finish(e);
      });
      proc.on('exit', (code) => {
        // Запоздавший exit старого ядра не должен сбивать состояние нового
        if (this.proc !== proc && this.proc) return finish(new Error('CANCELLED'));
        this.proc = null;
        this.stopTraffic();
        const fatal = this.logs.slice(-8).reverse().find((l) => /FATAL|ERROR/i.test(l));
        const error = this.stopping ? null : fatal || `Ядро завершилось (код ${code})`;
        this.log('[leftik] ядро остановлено');
        this.setState('disconnected', error);
        finish(error ? new Error(error) : null);
      });
    });
  }

  async disconnect() {
    this.gen++;
    const proc = this.proc;
    if (!proc) {
      if (this.state === 'connecting') this.setState('disconnecting');
      await killStrayCores(this.workDir);
      this.setState('disconnected');
      return;
    }
    this.stopping = true;
    this.setState('disconnecting');
    this.log('[leftik] отключение');
    await new Promise((resolve) => {
      const done = () => {
        clearTimeout(hard);
        clearTimeout(giveUp);
        resolve();
      };
      proc.once('exit', done);
      try { proc.kill(); } catch { /* уже завершён */ }
      const hard = setTimeout(() => {
        execFile('taskkill', ['/pid', String(proc.pid), '/t', '/f'], { windowsHide: true }, () => {});
      }, 1500);
      const giveUp = setTimeout(done, 5000);
    });
    if (this.proc === proc) {
      // exit так и не пришёл — считаем остановленным и добиваем по пути к exe
      this.proc = null;
      this.stopTraffic();
      await killStrayCores(this.workDir);
      this.setState('disconnected');
    }
  }

  startTraffic() {
    this.stopTraffic();
    const req = http.get({ host: '127.0.0.1', port: API_PORT, path: '/traffic' }, (res) => {
      let buf = '';
      res.on('data', (chunk) => {
        buf += chunk.toString();
        const lines = buf.split('\n');
        buf = lines.pop();
        for (const l of lines) {
          try {
            const t = JSON.parse(l);
            this.emit('traffic', { up: t.up || 0, down: t.down || 0 });
          } catch { /* неполная строка */ }
        }
      });
    });
    req.on('error', () => {
      if (this.state === 'connected') setTimeout(() => this.state === 'connected' && this.startTraffic(), 2000);
    });
    this.trafficReq = req;
  }

  stopTraffic() {
    if (this.trafficReq) {
      this.trafficReq.destroy();
      this.trafficReq = null;
    }
  }
}

module.exports = { Core, buildConfig, splitRouting, killStrayCores, TUN_V4, TUN_V6 };
