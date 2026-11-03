const api = window.leftik;
const $ = (id) => document.getElementById(id);

const state = {
  store: { servers: [], selected: null, settings: {} },
  core: 'disconnected',
  connectedAt: null,
  pings: {},
  openMenu: null,
};

const STATUS = {
  disconnected: 'Не подключено',
  connecting: 'Подключение…',
  connected: 'Подключено',
  disconnecting: 'Отключение…',
};

function toast(text) {
  const t = $('toast');
  t.textContent = text;
  t.classList.add('show');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.remove('show'), 2200);
}

function showError(el, msg) {
  if (msg === 'CANCELLED') msg = ''; // подключение отменили кнопкой — это не ошибка
  el.textContent = msg || '';
  el.classList.toggle('hidden', !msg);
  if (msg) el.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
}

function go(view) {
  document.querySelectorAll('.view').forEach((v) => v.classList.toggle('active', v.id === `view-${view}`));
  const tab = view === 'add' ? 'servers' : view;
  document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t.dataset.go === tab));
  if (view === 'servers') pingAll();
}

function fmtSpeed(bytes) {
  const units = ['Б/с', 'КБ/с', 'МБ/с', 'ГБ/с'];
  let v = bytes;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v < 10 && i ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}

function selected() {
  return state.store.servers.find((s) => s.id === state.store.selected) || null;
}

function describe(s) {
  const proto = s.security === 'reality' ? 'VLESS Reality' : s.security === 'tls' ? 'VLESS TLS' : 'VLESS';
  return `${proto} · ${s.host}:${s.port}`;
}

// ---------- Главная ----------
function renderHome() {
  const busy = state.core === 'connecting' || state.core === 'disconnecting';
  document.body.classList.toggle('connected', state.core === 'connected');
  document.body.classList.toggle('busy', busy);
  $('statusText').textContent = STATUS[state.core];
  $('powerBtn').setAttribute('aria-label', state.core === 'connected' ? 'Отключить' : 'Подключить');
  const { killSwitch: ks, split } = state.store.settings;
  const badges = $('badges');
  badges.textContent = '';
  const badge = (text, cls = '') => {
    const b = document.createElement('span');
    b.className = `badge ${cls}`;
    b.textContent = text;
    if (cls === 'ks') {
      b.title = 'Открыть настройки kill switch';
      b.addEventListener('click', () => go('settings'));
    }
    badges.appendChild(b);
  };
  if (ks?.enabled) badge(state.core === 'connected' ? 'Kill switch' : 'Kill switch: интернет заблокирован', 'ks');
  for (const [key, label] of [['apps', 'Приложения'], ['sites', 'Сайты']]) {
    const p = split?.[key];
    if (p && p.mode !== 'off' && p.list.length) badge(`${label}: ${p.mode === 'only' ? 'только' : 'кроме'} ${p.list.length}`);
  }

  const s = selected();
  $('chipName').textContent = s ? s.name : 'Сервер не выбран';
  $('chipMeta').textContent = s ? describe(s) : 'Нажмите, чтобы добавить';
  if (state.core !== 'connected') {
    $('downSpeed').textContent = fmtSpeed(0);
    $('upSpeed').textContent = fmtSpeed(0);
  }
}

setInterval(() => {
  if (state.core !== 'connected' || !state.connectedAt) {
    $('timer').textContent = '00:00:00';
    return;
  }
  const sec = Math.floor((Date.now() - state.connectedAt) / 1000);
  const p = (n) => String(n).padStart(2, '0');
  $('timer').textContent = `${p(Math.floor(sec / 3600))}:${p(Math.floor(sec / 60) % 60)}:${p(sec % 60)}`;
}, 1000);

$('powerBtn').addEventListener('click', async () => {
  showError($('homeError'), '');
  if (state.core === 'disconnecting') return;
  // Во время подключения кнопка тоже отменяет — раньше нажатие тут игнорировалось
  if (state.core === 'connected' || state.core === 'connecting') {
    return api.disconnect().catch((e) => showError($('homeError'), e.message));
  }
  if (!selected()) return go(state.store.servers.length ? 'servers' : 'add');
  try {
    await api.connect();
  } catch (e) {
    if (e.message === 'NEED_ADMIN') {
      $('adminBanner').classList.remove('hidden');
      showError($('homeError'), 'Для подключения перезапустите Leftik VPN от имени администратора.');
    } else {
      const ksHint = state.store.settings.killSwitch.enabled
        ? ' Kill switch включён: если подключиться не выходит, его можно выключить в Настройках.'
        : '';
      showError($('homeError'), e.message === 'CANCELLED' ? '' : e.message + ksHint);
    }
  }
});

$('serverChip').addEventListener('click', () => go(state.store.servers.length ? 'servers' : 'add'));
$('relaunchBtn').addEventListener('click', () => api.relaunchAdmin());

// ---------- Серверы ----------
function pingClass(ms) {
  if (ms == null) return 'bad';
  return ms < 120 ? 'good' : ms < 250 ? 'mid' : 'bad';
}

function renderServers() {
  const list = $('serverList');
  list.textContent = '';
  const { servers, selected: sel } = state.store;
  $('emptyServers').classList.toggle('hidden', servers.length > 0);

  for (const s of servers) {
    const wrap = document.createElement('div');
    wrap.className = 'server-wrap';
    wrap.classList.toggle('open', state.openMenu === s.id);
    wrap.classList.toggle('sel', s.id === sel);

    const row = document.createElement('div');
    row.className = 'server';
    row.classList.toggle('selected', s.id === sel);
    const ping = state.pings[s.id];
    const pingText = ping === undefined ? '…' : ping === null ? 'нет ответа' : `${Math.round(ping)} мс`;
    row.innerHTML = `
      <span class="radio"></span>
      <div class="server-info"><div class="server-name"></div><div class="server-meta"></div></div>
      <span class="ping ${ping === undefined ? '' : pingClass(ping)}">${pingText}</span>
      <button class="menu-btn" title="Действия">⋯</button>`;
    row.querySelector('.server-name').textContent = s.name;
    row.querySelector('.server-meta').textContent = describe(s);
    row.addEventListener('click', async (e) => {
      if (e.target.closest('.menu-btn')) {
        state.openMenu = state.openMenu === s.id ? null : s.id;
        return renderServers();
      }
      if (s.id === sel) return go('home');
      const wasOn = state.core === 'connected';
      state.store = await api.select(s.id);
      renderAll();
      if (wasOn) {
        await api.disconnect();
        api.connect().catch((err) => showError($('homeError'), err.message));
      }
      go('home');
    });
    wrap.appendChild(row);

    if (state.openMenu === s.id) {
      const actions = document.createElement('div');
      actions.className = 'actions';
      const mk = (label, fn, cls = '') => {
        const b = document.createElement('button');
        b.className = `btn small ghost ${cls}`;
        b.textContent = label;
        b.addEventListener('click', fn);
        actions.appendChild(b);
      };
      mk('Поделиться ключом', async () => {
        await api.share(s.id);
        toast('Ключ vless:// скопирован');
      });
      mk('Переименовать', async () => {
        const name = await promptName(s.name);
        if (name) {
          state.store = await api.rename(s.id, name);
          renderAll();
        }
      });
      mk('Удалить', async () => {
        if (!confirm(`Удалить «${s.name}» из списка?`)) return;
        state.store = await api.remove(s.id);
        state.openMenu = null;
        renderAll();
      }, 'danger');
      wrap.appendChild(actions);
    }
    list.appendChild(wrap);
  }
}

// prompt() в Electron отключён, поэтому простое поле прямо в строке действий
function promptName(current) {
  return new Promise((resolve) => {
    const actions = document.querySelector('.server-wrap.open .actions');
    actions.textContent = '';
    const input = document.createElement('input');
    input.value = current;
    input.style.flex = '1';
    const ok = document.createElement('button');
    ok.className = 'btn small';
    ok.textContent = 'OK';
    const done = (v) => resolve(v);
    ok.addEventListener('click', () => done(input.value));
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') done(input.value);
      if (e.key === 'Escape') { done(null); renderServers(); }
    });
    actions.append(input, ok);
    input.focus();
    input.select();
  });
}

async function pingAll() {
  await Promise.all(state.store.servers.map(async (s) => {
    state.pings[s.id] = await api.ping(s.id);
  }));
  renderServers();
}

$('addServerBtn').addEventListener('click', () => go('add'));

// ---------- Добавление ----------
document.querySelectorAll('#view-add .seg').forEach((b) => b.addEventListener('click', () => {
  document.querySelectorAll('#view-add .seg').forEach((x) => x.classList.toggle('active', x === b));
  $('ownForm').classList.toggle('hidden', b.dataset.tab !== 'own');
  $('keyForm').classList.toggle('hidden', b.dataset.tab !== 'key');
  showError($('addError'), '');
}));

$('ownForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const params = Object.fromEntries(new FormData(e.target));
  const btn = $('installBtn');
  const log = $('installLog');
  showError($('addError'), '');
  log.textContent = '';
  log.classList.remove('hidden');
  btn.disabled = true;
  btn.textContent = 'Проверяю сервер…';
  try {
    const r = await api.install({ ...params, force: e.target.force.checked });
    state.store = r.store;
    e.target.password.value = '';
    e.target.force.checked = false;
    renderAll();
    toast(r.reused ? 'VLESS на сервере уже был — ключ получен, ничего не переустанавливали' : 'Сервер установлен');
    go('home');
    api.connect().catch((err) => {
      showError($('homeError'), err.message === 'NEED_ADMIN'
        ? 'Сервер готов. Для подключения перезапустите приложение от администратора.'
        : err.message);
    });
  } catch (err) {
    showError($('addError'), err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Подключить сервер';
  }
});

$('keyForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  showError($('addError'), '');
  try {
    state.store = await api.importKey(e.target.link.value);
    e.target.reset();
    renderAll();
    toast('Сервер добавлен');
    go('home');
  } catch (err) {
    showError($('addError'), err.message);
  }
});

api.onInstallLog((line) => {
  const log = $('installLog');
  log.textContent += `${line}\n`;
  log.scrollTop = log.scrollHeight;
});

// ---------- Настройки ----------
$('dnsSelect').addEventListener('change', async (e) => {
  state.store = await api.setSettings({ dns: e.target.value });
  toast('DNS сохранён');
});

// Kill switch
async function setKillSwitch(patch, doneText) {
  const ks = { ...state.store.settings.killSwitch, ...patch };
  const controls = document.querySelectorAll('#ksToggle, #ksLan, .ks-ex input, .ks-ex button');
  controls.forEach((c) => { c.disabled = true; });
  try {
    const r = await api.setKillSwitch(ks);
    state.store = r.store;
    toast(r.unresolved.length
      ? `Не удалось найти IP для: ${r.unresolved.join(', ')}`
      : doneText || (ks.enabled ? 'Kill switch включён' : 'Kill switch выключен'));
  } catch (e) {
    toast(e.message === 'NEED_ADMIN' ? 'Нужны права администратора' : `Ошибка: ${e.message}`);
    if (e.message === 'NEED_ADMIN') $('adminBanner').classList.remove('hidden');
  } finally {
    controls.forEach((c) => { c.disabled = false; });
    renderSettings();
    renderHome();
  }
}
$('ksToggle').addEventListener('change', (e) => setKillSwitch({ enabled: e.target.checked }));
$('ksLan').addEventListener('change', (e) => setKillSwitch({ allowLan: e.target.checked }, 'Сохранено'));

// Исключения kill switch: программам нужен полный путь (брандмауэр сверяет именно его)
function cloneExceptions() {
  return JSON.parse(JSON.stringify(state.store.settings.killSwitch.exceptions));
}

document.querySelectorAll('.ks-ex').forEach((box) => {
  const kind = box.dataset.ex;
  const input = box.querySelector('.split-input');
  const add = (values) => {
    const ex = cloneExceptions();
    const bad = [];
    for (const raw of values) {
      const v = kind === 'apps' ? normalizeExePath(raw) : normalizeEntry('sites', raw);
      if (!v) bad.push(raw);
      else if (!ex[kind].some((x) => x.toLowerCase() === v.toLowerCase())) ex[kind].push(v);
    }
    if (bad.length) {
      return toast(kind === 'apps'
        ? 'Нужен полный путь к .exe — проще выбрать через «Обзор…»'
        : `Не похоже на сайт или IP: ${bad.join(', ')}`);
    }
    input.value = '';
    setKillSwitch({ exceptions: ex }, 'Исключения сохранены');
  };
  const values = () => (kind === 'apps' ? [input.value] : input.value.split(/[\s,;]+/)).filter((v) => v.trim());
  box.querySelector('.add').addEventListener('click', () => add(values()));
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') add(values());
  });
  box.querySelector('.browse')?.addEventListener('click', async () => {
    const paths = await api.browseApps();
    if (paths.length) add(paths);
  });
  if (kind === 'apps') {
    input.addEventListener('focus', () => fillRunning($('runningPaths'), (a) => a.path, (a) => a.name), { once: true });
  }
});

function normalizeExePath(raw) {
  const v = String(raw || '').trim().replace(/^"|"$/g, '');
  return /^[a-z]:\\[^:*?"<>|]+\.exe$/i.test(v) ? v : null;
}

async function fillRunning(datalist, value, label) {
  if (datalist.childElementCount) return;
  for (const a of await api.runningApps()) {
    const o = document.createElement('option');
    o.value = value(a);
    if (label) o.label = label(a);
    datalist.appendChild(o);
  }
}

function renderChips(container, list, onRemove, cls = '') {
  container.textContent = '';
  for (const v of list) {
    const c = document.createElement('span');
    c.className = `chip ${cls}`;
    const t = document.createElement('span');
    t.textContent = cls === 'path' ? v.split('\\').pop() : v;
    c.title = v;
    const x = document.createElement('button');
    x.textContent = '×';
    x.title = 'Убрать';
    x.addEventListener('click', () => onRemove(v));
    c.append(t, x);
    container.appendChild(c);
  }
}

// Раздельное туннелирование
const HINTS = {
  apps: {
    off: 'Все приложения идут через VPN.',
    only: 'Через VPN идут только приложения из списка, остальные — напрямую.',
    except: 'Через VPN идут все приложения, кроме перечисленных.',
  },
  sites: {
    off: 'Все сайты открываются через VPN.',
    only: 'Через VPN открываются только эти сайты (вместе с поддоменами).',
    except: 'Эти сайты открываются напрямую, остальные — через VPN.',
  },
};

function normalizeEntry(kind, raw) {
  let v = String(raw || '').trim().toLowerCase();
  if (!v) return null;
  if (kind === 'apps') {
    v = v.split(/[\\/]/).pop();
    if (!v.endsWith('.exe')) v += '.exe';
    return /^[^:*?"<>|]+\.exe$/.test(v) ? v : null;
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return `${v}/32`;
  if (/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(v)) return v;
  if (/^[0-9a-f:]+\/\d{1,3}$/.test(v) && v.includes(':')) return v;
  v = v.replace(/^[a-z]+:\/\//, '').split(/[/?#:]/)[0].replace(/^\*\./, '').replace(/^www\./, '');
  return /^([a-z0-9-]+\.)+[a-z0-9-]{2,}$/.test(v) ? v : null;
}

async function saveSplit(split) {
  const wasOn = state.core === 'connected';
  state.store = await api.setSettings({ split });
  renderSettings();
  renderHome();
  if (wasOn) toast('Переподключаюсь, чтобы применить');
}

function cloneSplit() {
  return JSON.parse(JSON.stringify(state.store.settings.split));
}

document.querySelectorAll('.split').forEach((card) => {
  const kind = card.dataset.split;
  const input = card.querySelector('.split-input');
  card.querySelectorAll('.seg').forEach((b) => b.addEventListener('click', () => {
    const split = cloneSplit();
    split[kind].mode = b.dataset.mode;
    saveSplit(split);
  }));
  const add = (values) => {
    const split = cloneSplit();
    const bad = [];
    for (const raw of values) {
      const v = normalizeEntry(kind, raw);
      if (!v) bad.push(raw);
      else if (!split[kind].list.includes(v)) split[kind].list.push(v);
    }
    if (bad.length) toast(`Не похоже на ${kind === 'apps' ? 'программу' : 'сайт или IP'}: ${bad.join(', ')}`);
    else if (split[kind].mode === 'off') toast('Список сохранён. Выберите режим «Только эти» или «Все, кроме этих»');
    input.value = '';
    saveSplit(split);
  };
  card.querySelector('.add').addEventListener('click', () => add(input.value.split(/[\s,;]+/).filter(Boolean)));
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') add(input.value.split(/[\s,;]+/).filter(Boolean));
  });
  card.querySelector('.browse')?.addEventListener('click', async () => {
    const names = await api.browseApps();
    if (names.length) add(names);
  });
  if (kind === 'apps') {
    input.addEventListener('focus', () => fillRunning($('runningApps'), (a) => a.name), { once: true });
  }
});

function renderSettings() {
  const { killSwitch: ks, split } = state.store.settings;
  $('ksToggle').checked = !!ks.enabled;
  $('ksLan').checked = ks.allowLan !== false;
  $('ksLan').closest('.setting').classList.toggle('disabled', !ks.enabled);
  document.querySelectorAll('.ks-ex').forEach((box) => {
    const kind = box.dataset.ex;
    renderChips(box.querySelector('.chips'), ks.exceptions[kind], (v) => {
      const ex = cloneExceptions();
      ex[kind] = ex[kind].filter((item) => item !== v);
      setKillSwitch({ exceptions: ex }, 'Исключения сохранены');
    }, kind === 'apps' ? 'path' : '');
  });
  document.querySelectorAll('.split').forEach((card) => {
    const kind = card.dataset.split;
    const p = split[kind];
    card.classList.toggle('off', p.mode === 'off');
    card.querySelectorAll('.seg').forEach((b) => b.classList.toggle('active', b.dataset.mode === p.mode));
    card.querySelector('.split-hint').textContent = HINTS[kind][p.mode];
    renderChips(card.querySelector('.chips'), p.list, (v) => {
      const s = cloneSplit();
      s[kind].list = s[kind].list.filter((item) => item !== v);
      saveSplit(s);
    });
  });
}

function appendLog(line) {
  const el = $('coreLog');
  const stick = el.scrollTop + el.clientHeight >= el.scrollHeight - 8;
  el.textContent += `${line}\n`;
  if (el.textContent.length > 60000) el.textContent = el.textContent.slice(-40000);
  if (stick) el.scrollTop = el.scrollHeight;
}

$('copyLogs').addEventListener('click', () => {
  navigator.clipboard.writeText($('coreLog').textContent);
  toast('Журнал скопирован');
});

// ---------- Общее ----------
document.querySelectorAll('[data-go]').forEach((b) => b.addEventListener('click', () => go(b.dataset.go)));

function renderAll() {
  renderHome();
  renderServers();
}

api.onState(({ state: s, error }) => {
  if (s === 'connected' && state.core !== 'connected') state.connectedAt = Date.now();
  state.core = s;
  if (error) showError($('homeError'), error);
  else if (s === 'connected') showError($('homeError'), '');
  renderHome();
});
api.onLog(appendLog);
api.onTraffic(({ up, down }) => {
  $('upSpeed').textContent = fmtSpeed(up);
  $('downSpeed').textContent = fmtSpeed(down);
});

(async () => {
  const init = await api.init();
  state.store = init.store;
  state.core = init.core.state;
  if (state.core === 'connected') state.connectedAt = Date.now();
  init.core.logs.forEach(appendLog);
  $('adminBanner').classList.toggle('hidden', init.admin);
  $('dnsSelect').value = init.store.settings.dns || '1.1.1.1';
  $('version').textContent = `v${init.version}`;
  renderAll();
  renderSettings();
})();
