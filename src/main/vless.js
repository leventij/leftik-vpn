// Разбор и сборка ссылок vless://uuid@host:port?params#name

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function parseVless(link) {
  const text = String(link || '').trim();
  if (!text.toLowerCase().startsWith('vless://')) throw new Error('Ключ должен начинаться с vless://');
  let url;
  try {
    url = new URL(text);
  } catch {
    throw new Error('Не удалось разобрать ключ');
  }
  const uuid = decodeURIComponent(url.username);
  if (!UUID_RE.test(uuid)) throw new Error('В ключе неверный UUID');
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (!host) throw new Error('В ключе нет адреса сервера');
  const q = url.searchParams;
  const security = (q.get('security') || 'none').toLowerCase();
  const transport = (q.get('type') || 'tcp').toLowerCase();
  if (!['none', 'tls', 'reality'].includes(security)) throw new Error(`Неподдерживаемый security=${security}`);
  if (!['tcp', 'ws', 'grpc', 'httpupgrade'].includes(transport)) throw new Error(`Неподдерживаемый type=${transport}`);
  if (security === 'reality' && !q.get('pbk')) throw new Error('Для Reality в ключе нужен pbk (публичный ключ)');
  return {
    name: decodeURIComponent(url.hash.replace(/^#/, '')) || host,
    host,
    port: Number(url.port) || 443,
    uuid,
    security,
    transport,
    flow: q.get('flow') || '',
    sni: q.get('sni') || q.get('peer') || '',
    fp: q.get('fp') || 'chrome',
    pbk: q.get('pbk') || '',
    sid: q.get('sid') || '',
    path: q.get('path') || '',
    hostHeader: q.get('host') || '',
    serviceName: q.get('serviceName') || '',
    alpn: q.get('alpn') || '',
  };
}

function buildVless(s) {
  const q = new URLSearchParams();
  q.set('type', s.transport || 'tcp');
  q.set('security', s.security || 'none');
  if (s.flow) q.set('flow', s.flow);
  if (s.sni) q.set('sni', s.sni);
  if (s.fp && s.security !== 'none') q.set('fp', s.fp);
  if (s.pbk) q.set('pbk', s.pbk);
  if (s.sid) q.set('sid', s.sid);
  if (s.path) q.set('path', s.path);
  if (s.hostHeader) q.set('host', s.hostHeader);
  if (s.serviceName) q.set('serviceName', s.serviceName);
  if (s.alpn) q.set('alpn', s.alpn);
  const host = s.host.includes(':') ? `[${s.host}]` : s.host;
  return `vless://${s.uuid}@${host}:${s.port}?${q.toString()}#${encodeURIComponent(s.name || s.host)}`;
}

module.exports = { parseVless, buildVless };
