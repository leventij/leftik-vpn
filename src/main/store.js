// Список серверов и настройки в userData/leftik.json (пароли SSH не сохраняются)
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class Store {
  constructor(dir) {
    this.file = path.join(dir, 'leftik.json');
    const defaults = {
      dns: '1.1.1.1',
      killSwitch: { enabled: false, allowLan: true, exceptions: { apps: [], sites: [] } },
      split: { apps: { mode: 'off', list: [] }, sites: { mode: 'off', list: [] } },
    };
    this.data = { servers: [], selected: null, settings: defaults };
    try {
      const saved = JSON.parse(fs.readFileSync(this.file, 'utf8'));
      const settings = { ...defaults, ...saved.settings };
      settings.killSwitch = { ...defaults.killSwitch, ...settings.killSwitch };
      Object.assign(this.data, saved, { settings });
    } catch { /* первый запуск */ }
  }

  save() {
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    fs.writeFileSync(this.file, JSON.stringify(this.data, null, 2));
  }

  addServer(server) {
    const existing = this.data.servers.find((s) => s.host === server.host && s.port === server.port && s.uuid === server.uuid);
    if (existing) {
      Object.assign(existing, server, { id: existing.id });
      this.data.selected = existing.id;
    } else {
      const item = { ...server, id: crypto.randomUUID(), addedAt: Date.now() };
      this.data.servers.push(item);
      this.data.selected = item.id;
    }
    this.save();
    return this.state();
  }

  removeServer(id) {
    this.data.servers = this.data.servers.filter((s) => s.id !== id);
    if (this.data.selected === id) this.data.selected = this.data.servers[0]?.id || null;
    this.save();
    return this.state();
  }

  renameServer(id, name) {
    const s = this.data.servers.find((x) => x.id === id);
    if (s && name.trim()) s.name = name.trim().slice(0, 60);
    this.save();
    return this.state();
  }

  select(id) {
    if (this.data.servers.some((s) => s.id === id)) this.data.selected = id;
    this.save();
    return this.state();
  }

  setSettings(patch) {
    Object.assign(this.data.settings, patch);
    this.save();
    return this.state();
  }

  selectedServer() {
    return this.data.servers.find((s) => s.id === this.data.selected) || null;
  }

  state() {
    return JSON.parse(JSON.stringify(this.data));
  }
}

module.exports = { Store };
