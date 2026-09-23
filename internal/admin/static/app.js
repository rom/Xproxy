/* xproxy admin: a small single page application over /api. No inline
   scripts, no external assets, no innerHTML with data (strict CSP). */
'use strict';

const $ = (sel, root) => (root || document).querySelector(sel);
const view = $('#view');
let me = null;
let timer = null;
let es = null;

// ---- DOM helpers ----
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  if (attrs) for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined) el.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }
function table(headers, rows) {
  return h('table', null,
    h('thead', null, h('tr', null, headers.map(x => h('th', { class: x.num ? 'num' : null }, x.label || x)))),
    h('tbody', null, rows.map(r => h('tr', null, r.map((c, i) => h('td', { class: headers[i] && headers[i].num ? 'num' : null }, c))))));
}
function fmtNum(v) {
  if (v === null || v === undefined) return '-';
  if (Math.abs(v) >= 1e9) return (v / 1e9).toFixed(1) + 'G';
  if (Math.abs(v) >= 1e6) return (v / 1e6).toFixed(1) + 'M';
  if (Math.abs(v) >= 1e4) return (v / 1e3).toFixed(1) + 'k';
  return Number.isInteger(v) ? String(v) : v.toFixed(2);
}
function fmtBytes(b) {
  const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB']; let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return (i ? b.toFixed(1) : b) + ' ' + u[i];
}
function fmtDur(s) {
  s = Math.floor(s); const d = Math.floor(s / 86400); s -= d * 86400;
  const hh = Math.floor(s / 3600); s -= hh * 3600; const mm = Math.floor(s / 60);
  return (d ? d + 'd ' : '') + hh + 'h ' + mm + 'm';
}
function fmtTime(t) { return t ? new Date(t).toLocaleString() : '-'; }
function flash(msg, kind) {
  const f = $('#flash'); clear(f); f.append(msg); f.className = kind || '';
  clearTimeout(flash.t); flash.t = setTimeout(() => f.classList.add('hidden'), 6000);
}

// ---- API ----
async function api(method, path, body) {
  const opts = { method, headers: { 'X-Xproxy-Admin': '1' }, credentials: 'same-origin' };
  if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  const r = await fetch(path, opts);
  if (r.status === 401 && path !== '/api/login') { showLogin(); throw new Error('not logged in'); }
  const ct = r.headers.get('content-type') || '';
  const data = ct.includes('json') ? await r.json() : await r.text();
  if (!r.ok) {
    const err = new Error((data && data.error) || ('HTTP ' + r.status)); err.data = data; err.status = r.status; throw err;
  }
  return data;
}
const get = p => api('GET', p);
const post = (p, b) => api('POST', p, b === undefined ? {} : b);

// ---- session ----
async function boot() {
  try { me = await get('/api/me'); showApp(); } catch (e) { showLogin(); }
}
function showLogin() {
  stopRefresh(); me = null;
  $('#app').classList.add('hidden'); $('#login').classList.remove('hidden');
  get('/api/auth').then(a => {
    $('#sso').classList.toggle('hidden', !a.oidc);
    if (a.oidc && a.oidc_issuer) $('#sso-link').textContent = 'Sign in with ' + a.oidc_issuer;
  }).catch(() => {});
  const err = new URLSearchParams(location.search).get('sso_error');
  if (err) {
    $('#login-error').textContent = 'single sign-on failed: ' + err.replace(/[^a-zA-Z0-9_:-]/g, '');
    history.replaceState(null, '', location.pathname + location.hash);
  }
}
function showApp() {
  $('#login').classList.add('hidden'); $('#app').classList.remove('hidden');
  $('#who').textContent = me.user + ' (' + me.role + (me.via === 'certificate' ? ', certificate' : me.via === 'oidc' ? ', single sign-on' : '') + ')';
  $('#footer-version').textContent = 'xproxy-admin ' + me.version;
  route();
}
$('#login-form').addEventListener('submit', async ev => {
  ev.preventDefault();
  const f = ev.target; $('#login-error').textContent = '';
  try {
    me = await post('/api/login', { user: f.user.value, password: f.password.value });
    f.password.value = ''; showApp();
  } catch (e) { $('#login-error').textContent = e.message; }
});
$('#logout').addEventListener('click', async () => { try { await post('/api/logout'); } catch (e) { /* ignore */ } showLogin(); });

// ---- routing and refresh ----
const views = {};
function route() {
  const name = (location.hash || '#overview').slice(1);
  for (const a of $('#nav').querySelectorAll('a')) a.classList.toggle('active', a.getAttribute('href') === '#' + name);
  stopRefresh(); clear(view);
  const v = views[name] || views.overview;
  const period = v.refresh || 0;
  const run = async () => {
    try { await v.render(); $('#refresh-state').textContent = period ? 'refreshed ' + new Date().toLocaleTimeString() : ''; }
    catch (e) { if (e.message !== 'not logged in') flash(e.message, 'bad'); }
  };
  run();
  if (period) timer = setInterval(run, period);
}
function stopRefresh() { if (timer) clearInterval(timer); timer = null; if (es) { es.close(); es = null; } }
window.addEventListener('hashchange', route);
const operator = () => me && me.role === 'operator';

// ---- views ----
views.overview = { refresh: 5000, async render() {
  const st = await get('/api/status'); const s = st.stats;
  const denied = s.denied_acl + s.denied_rate_limit + s.tarpitted + s.denied_concurrency + s.denied_body_size + s.denied_uri_length + s.denied_no_route + s.denied_websocket + s.denied_bad_host + s.denied_ban + s.denied_waf + s.denied_jwt + s.denied_icap;
  const stats = [
    ['Version', st.version], ['Uptime', fmtDur(s.uptime_seconds)], ['Generation', st.generation], ['Routes / upstreams', st.routes + ' / ' + st.upstreams],
    ['Requests', fmtNum(s.requests)], ['2xx', fmtNum(s.responses_2xx)], ['4xx', fmtNum(s.responses_4xx)], ['5xx', fmtNum(s.responses_5xx)],
    ['Open connections', s.open_connections], ['Bytes in', fmtBytes(s.bytes_in)], ['Bytes out', fmtBytes(s.bytes_out)], ['Denied', fmtNum(denied)],
    ['Bans active', s.bans_active], ['WAF blocked / detected', fmtNum(s.denied_waf) + ' / ' + fmtNum(s.waf_detected)], ['Rate limited / tarpitted', fmtNum(s.denied_rate_limit) + ' / ' + fmtNum(s.tarpitted)], ['Shed', fmtNum(s.shed)],
    ['Load level', s.load_level.toFixed(2) + (s.shedding_classes && s.shedding_classes.length ? ' shedding ' + s.shedding_classes.join(',') : '')], ['Upstream latency', s.upstream_latency_ms.toFixed(1) + ' ms'], ['Upstream errors / timeouts', fmtNum(s.upstream_errors) + ' / ' + fmtNum(s.upstream_timeouts)], ['Cluster', s.cluster_connected + ' / ' + s.cluster_peers + ' peers'],
    ['Sandbox', sandboxSummary(st.sandbox)],
    ['Challenges issued / passed', fmtNum(s.challenges_issued) + ' / ' + fmtNum(s.challenges_passed)], ['Reloads / failures', s.reloads + ' / ' + s.reload_failures], ['Log drops (syslog / journald)', s.log_syslog_dropped + ' / ' + s.log_journald_dropped], ['Redaction', s.log_redaction ? 'on' : 'off'],
  ];
  const denies = Object.entries(s).filter(([k, v]) => k.startsWith('denied_') && v > 0).sort((a, b) => b[1] - a[1]);
  clear(view);
  view.append(
    h('div', { class: 'grid' }, stats.map(([k, v]) => h('div', { class: 'stat' }, h('div', { class: 'k' }, k), h('div', { class: 'v' }, v)))),
    h('div', { class: 'card mt' }, h('h2', null, 'Listeners'),
      table(['Name', 'Address'], Object.entries(st.listeners).map(([k, v]) => [k, v]))),
    h('div', { class: 'card' }, h('h2', null, 'Denials by reason'),
      denies.length ? table(['Reason', { label: 'Count', num: true }], denies.map(([k, v]) => [k.replace('denied_', ''), fmtNum(v)])) : h('p', { class: 'muted' }, 'none')),
    operator() ? h('div', { class: 'card' }, h('h2', null, 'Actions'), h('div', { class: 'row' },
      actionButton('Reload configuration', '/api/reload'), actionButton('Reload certificates', '/api/reload-certs'), actionButton('Reopen logs', '/api/reopen-logs'),
      me.can_restart ? actionButton('Restart data plane', '/api/restart', 'danger', 'Restart the xproxy service? Open connections are drained by systemd.') : null)) : null);
}};

function actionButton(label, path, cls, confirmText) {
  const b = h('button', { class: cls || 'secondary' }, label);
  b.addEventListener('click', async () => {
    if (confirmText && !confirm(confirmText)) return;
    b.disabled = true;
    try { const r = await post(path); flash(label + ': done' + (r.output ? ' (' + r.output + ')' : ''), 'ok'); }
    catch (e) { flash(label + ': ' + e.message + (e.data && e.data.output ? ' ' + e.data.output : ''), 'bad'); }
    b.disabled = false;
  });
  return b;
}

views.upstreams = { refresh: 5000, async render() {
  const [ups, pools] = await Promise.all([get('/api/upstreams'), get('/api/pools').catch(() => ({}))]);
  clear(view);
  const names = Object.keys(ups).sort();
  if (!names.length) view.append(h('p', { class: 'muted' }, 'no upstreams'));
  for (const n of names) {
    const p = pools[n];
    const facts = [];
    if (p) {
      facts.push(['Balancer', p.balancer], ['Available', p.available + ' / ' + p.endpoints], ['Active', p.active]);
      if (p.circuit) facts.push(['Circuit', circuitState(p.circuit)], ['Circuit opens / rejected', fmtNum(p.circuit.opens) + ' / ' + fmtNum(p.circuit.rejected)]);
      if (p.queue) facts.push(['Concurrency', p.queue.in_flight + ' / ' + p.queue.max_concurrent + ' in flight, ' + p.queue.waiting + ' / ' + p.queue.queue_size + ' queued'], ['Queue timeouts / full', fmtNum(p.queue.timeouts) + ' / ' + fmtNum(p.queue.full)]);
      if (p.discovery) facts.push(['Discovery', p.discovery.type + ' ' + p.discovery.name + ' (' + p.discovery.endpoints + ' endpoints, ' + p.discovery.changes + ' changes' + (p.discovery.errors ? ', ' + p.discovery.errors + ' errors' : '') + ')'], ['Last resolved', p.discovery.last_error ? h('span', { class: 'bad' }, p.discovery.last_error) : fmtTime(p.discovery.last_resolved)]);
      if (p.slow_start) facts.push(['Slow start', p.slow_start]);
      if (p.canary) facts.push(['Canary', (p.canary.header ? 'header ' + p.canary.header + ' ' : '') + (p.canary.cookie ? 'cookie ' + p.canary.cookie + ' ' : '') + p.canary.percent + '% on ' + p.canary.endpoints + ' endpoint(s)'], ['Canary requests / fallbacks', fmtNum(p.canary.requests) + ' / ' + fmtNum(p.canary.fallbacks)]);
    }
    view.append(h('div', { class: 'card' }, h('h2', null, n),
      facts.length ? h('div', { class: 'grid' }, facts.map(([k, v]) => h('div', { class: 'stat' }, h('div', { class: 'k' }, k), h('div', { class: 'v' }, v)))) : null,
      table(['Address', { label: 'Weight', num: true }, 'Health', { label: 'Active', num: true }, { label: 'Requests', num: true }, { label: 'Errors', num: true }, { label: 'Ejections', num: true }],
        ups[n].map(e => [e.address + (e.discovered ? ' (dns)' : ''), e.weight, e.ejected ? h('span', { class: 'bad' }, 'ejected') : e.healthy ? h('span', { class: 'ok' }, e.ramp < 1 ? 'warming ' + Math.round(e.ramp * 100) + '%' : 'healthy') : h('span', { class: 'bad' }, 'unhealthy'), e.active, fmtNum(e.requests), fmtNum(e.errors), e.ejections]))));
  }
}};
function circuitState(c) {
  const cls = c.state === 'closed' ? 'ok' : c.state === 'half_open' ? 'warn' : 'bad';
  return h('span', { class: cls }, c.state + (c.failures ? ' (' + c.failures + ' failures)' : ''));
}
function sandboxSummary(sb) {
  if (!sb) return 'not reported';
  if (!sb.enabled) return h('span', { class: 'warn' }, 'disabled');
  const applied = (sb.mechanisms || []).filter(m => m.state === 'applied').map(m => m.name);
  const other = (sb.mechanisms || []).filter(m => m.state !== 'applied').map(m => m.name + '=' + m.state);
  return h('span', null, h('span', { class: 'ok' }, applied.join(', ') || '-'), other.length ? h('span', { class: 'warn' }, ' ' + other.join(' ')) : null);
}

// Renders arbitrary JSON: arrays of objects as tables, objects as grids,
// used for subsystems whose views are a plain status document.
function jsonView(data) {
  if (Array.isArray(data)) {
    if (!data.length) return h('p', { class: 'muted' }, 'none');
    if (typeof data[0] !== 'object' || data[0] === null) return h('p', null, data.map(String).join(', '));
    const keys = [...new Set(data.flatMap(o => Object.keys(o)))];
    return table(keys, data.map(o => keys.map(k => cell(o[k]))));
  }
  if (data && typeof data === 'object') {
    return h('div', { class: 'grid' }, Object.entries(data).map(([k, v]) => h('div', { class: 'stat' }, h('div', { class: 'k' }, k.replace(/_/g, ' ')), h('div', { class: 'v' }, cell(v)))));
  }
  return h('p', null, String(data));
}
function cell(v) {
  if (v === null || v === undefined) return '-';
  if (typeof v === 'number') return fmtNum(v);
  if (typeof v === 'boolean') return v ? 'yes' : 'no';
  if (typeof v === 'string') return /^\d{4}-\d\d-\d\dT/.test(v) ? fmtTime(v) : v;
  if (Array.isArray(v)) return v.length && typeof v[0] === 'object' ? jsonView(v) : v.map(x => typeof x === 'object' ? JSON.stringify(x) : String(x)).join(', ');
  return jsonView(v);
}

views.bans = { refresh: 10000, async render() {
  const bans = await get('/api/bans');
  clear(view);
  if (operator()) {
    const target = h('input', { placeholder: '203.0.113.7 or 203.0.113.0/24', size: 28 });
    const dur = h('input', { value: '1h', size: 6 });
    const reason = h('input', { placeholder: 'reason', size: 30 });
    const btn = h('button', null, 'Ban');
    btn.addEventListener('click', async () => {
      try { await post('/api/bans', { target: target.value.trim(), duration: dur.value.trim(), reason: reason.value }); flash('banned ' + target.value, 'ok'); target.value = ''; route(); }
      catch (e) { flash(e.message, 'bad'); }
    });
    view.append(h('div', { class: 'card' }, h('h2', null, 'Add a ban'), h('div', { class: 'row' }, target, dur, reason, btn)));
  }
  const rows = (bans || []).map(b => [b.target, fmtTime(b.until), b.reason, b.source, b.count,
    operator() ? unbanButton(b.target) : '']);
  view.append(h('div', { class: 'card' }, h('h2', null, 'Active bans (' + rows.length + ')'),
    rows.length ? table(['Target', 'Until', 'Reason', 'Source', { label: 'Count', num: true }, ''], rows) : h('p', { class: 'muted' }, 'none')));
}};
function unbanButton(target) {
  const b = h('button', { class: 'secondary' }, 'Unban');
  b.addEventListener('click', async () => {
    try { await api('DELETE', '/api/bans?target=' + encodeURIComponent(target)); flash('unbanned ' + target, 'ok'); route(); }
    catch (e) { flash(e.message, 'bad'); }
  });
  return b;
}

views.cluster = { refresh: 5000, async render() {
  let c;
  try { c = await get('/api/cluster'); } catch (e) { clear(view); view.append(h('p', { class: 'muted' }, 'cluster not configured (' + e.message + ')')); return; }
  clear(view);
  view.append(
    h('div', { class: 'grid' }, [['Node', c.node_id], ['Listen', c.listen], ['Rates sent / received', fmtNum(c.rates_sent) + ' / ' + fmtNum(c.rates_received)], ['Keys received', fmtNum(c.keys_received)],
      ['Bans sent / received', fmtNum(c.bans_sent) + ' / ' + fmtNum(c.bans_received)], ['Rejected connections', c.rejected_connections], ['Dropped updates', c.dropped_updates]]
      .map(([k, v]) => h('div', { class: 'stat' }, h('div', { class: 'k' }, k), h('div', { class: 'v' }, v)))),
    h('div', { class: 'card mt' }, h('h2', null, 'Peers'),
      table(['Address', 'Node', 'State', 'Since', { label: 'Messages', num: true }, { label: 'Reconnects', num: true }, 'Last error'],
        (c.peers || []).map(p => [p.address, p.node_id || '-', p.connected ? h('span', { class: 'ok' }, 'connected') : h('span', { class: 'bad' }, 'down'), p.connected ? fmtTime(p.connected_at) : '-', fmtNum(p.messages_out), p.reconnects, p.last_error || '']))),
    h('div', { class: 'card' }, h('h2', null, 'Inbound'),
      table(['Remote', 'Node', 'Certificate', 'Since', 'Last seen'], (c.inbound || []).map(i => [i.remote, i.node_id || '-', i.cert_name, fmtTime(i.since), fmtTime(i.last_seen)]))));
}};

views.certificates = { refresh: 30000, async render() {
  const [served, certs, tickets] = await Promise.all([get('/api/tls').catch(() => ({})), get('/api/acme').catch(() => null), get('/api/tls-tickets').catch(() => null)]);
  clear(view);
  if (tickets) view.append(h('div', { class: 'grid' }, [['Session ticket keys', 'epoch ' + tickets.epoch + ', ' + tickets.keys + ' keys from ' + tickets.master_keys + ' master key(s)'], ['Fingerprint', h('code', null, tickets.fingerprint)], ['Next rotation', fmtTime(tickets.next_rotation) + ' (every ' + tickets.rotate + ')'],
    ['Cluster peers', (tickets.mismatched_peers || []).length ? h('span', { class: 'bad' }, 'mismatch: ' + tickets.mismatched_peers.join(', ')) : (Object.keys(tickets.peers || {}).length ? h('span', { class: 'ok' }, 'all agree') : '-')]]
    .map(([k, v]) => h('div', { class: 'stat' }, h('div', { class: 'k' }, k), h('div', { class: 'v' }, v)))));
  const now = Date.now();
  const rows = [];
  for (const ln of Object.keys(served).sort()) for (const c of served[ln]) {
    const days = Math.floor((new Date(c.not_after) - now) / 86400000);
    const exp = days < 7 ? h('span', { class: 'bad' }, days + ' days left') : days < 30 ? h('span', { class: 'warn' }, days + ' days left') : h('span', { class: 'ok' }, days + ' days left');
    const os = c.ocsp ? c.ocsp.status : 'disabled';
    const ocsp = os === 'disabled' ? '-' : h('span', { class: os === 'good' ? 'ok' : os === 'revoked' ? 'bad' : 'warn' }, os + (c.ocsp.error ? ' (' + c.ocsp.error + ')' : ''));
    const ct = c.ct && c.ct.required ? h('span', { class: c.ct.ok ? 'ok' : 'warn' }, (c.ct.ok ? 'ok' : 'failed') + ' ' + c.ct.verified + '/' + c.ct.required + ' SCTs' + (c.ct.error ? ' (' + c.ct.error + ')' : '')) : (c.ct && c.ct.embedded ? c.ct.embedded + ' SCTs' : '-');
    rows.push([ln, (c.names || []).join(', '), c.issuer || '-', exp, c.managed ? 'ACME' : 'file', ocsp, ct]);
  }
  view.append(h('div', { class: 'card' }, h('h2', null, 'Served certificates'),
    rows.length ? table(['Listener', 'Names', 'Issuer', 'Expires', 'Source', 'OCSP', 'CT'], rows) : h('p', { class: 'muted' }, 'no TLS listeners')));
  if (!certs) { view.append(h('p', { class: 'muted' }, 'ACME not configured')); return; }
  view.append(h('div', { class: 'card' }, h('h2', null, 'Managed certificates'),
    table(['Name', 'Hosts', 'State', 'Expires', 'Issuer', { label: 'Issued', num: true }, 'Last error'],
      certs.map(c => {
        const days = c.present ? Math.floor((new Date(c.not_after) - now) / 86400000) : null;
        const state = c.renewing ? h('span', { class: 'warn' }, 'renewing') : !c.present ? h('span', { class: 'bad' }, 'missing') : days < 7 ? h('span', { class: 'bad' }, days + ' days left') : days < 30 ? h('span', { class: 'warn' }, days + ' days left') : h('span', { class: 'ok' }, days + ' days left');
        return [c.name, c.hosts.join(', '), state, c.present ? fmtTime(c.not_after) : '-', c.issuer || '-', c.issued, c.last_error || ''];
      })),
    operator() ? h('div', { class: 'row mt-s' }, actionButton('Renew all now', '/api/acme/renew', 'secondary', 'Force renewal of every managed certificate?')) : null));
}};

views.icap = { refresh: 10000, async render() {
  let svc;
  try { svc = await get('/api/icap'); } catch (e) { clear(view); view.append(h('p', { class: 'muted' }, 'ICAP not configured (' + e.message + ')')); return; }
  clear(view);
  view.append(h('div', { class: 'card' }, h('h2', null, 'ICAP services'),
    table(['Name', 'URL', 'State', 'ISTag', { label: 'Preview', num: true }, { label: 'Requests', num: true }, { label: 'Unmodified', num: true }, { label: 'Modified', num: true }, { label: 'Blocked', num: true }, { label: 'Errors', num: true }, { label: 'Bypassed', num: true }],
      svc.map(s => [s.name, s.url, s.reachable ? h('span', { class: 'ok' }, 'reachable') : h('span', { class: 'bad' }, 'unreachable'), s.istag || '-', s.preview, fmtNum(s.requests), fmtNum(s.unmodified), fmtNum(s.modified), fmtNum(s.replacements), fmtNum(s.errors), fmtNum(s.bypassed)]))));
}};

// ---- graphs ----
const chartDefs = [
  { title: 'Requests per second', series: ['requests', 'responses_2xx', 'responses_4xx', 'responses_5xx'] },
  { title: 'Denied and shed per second', series: ['denied', 'shed', 'upstream_errors'] },
  { title: 'Bytes per second', series: ['bytes_in', 'bytes_out'], bytes: true },
  { title: 'Connections and in-flight', series: ['open_connections', 'in_flight'] },
  { title: 'Load level', series: ['load_level'] },
  { title: 'Upstream latency (ms)', series: ['upstream_latency_ms'] },
  { title: 'Bans active', series: ['bans_active'] },
  { title: 'Cluster peers connected', series: ['cluster_connected'] },
];
const palette = ['#1f5fbf', '#1a7f37', '#b7791f', '#b42318', '#7c3aed'];
let graphSince = '30m';
views.graphs = { refresh: 10000, async render() {
  const data = await get('/api/series?since=' + encodeURIComponent(graphSince));
  if (!view.firstChild || !view.firstChild.classList || !view.firstChild.classList.contains('charts-wrap')) {
    clear(view);
    const sel = h('select', null, ['10m', '30m', '1h', '3h', '6h', '12h', '24h'].map(v => h('option', { value: v, selected: v === graphSince ? '' : null }, v)));
    sel.addEventListener('change', () => { graphSince = sel.value; clear(view); route(); });
    const wrap = h('div', { class: 'charts-wrap' }, h('div', { class: 'row' }, h('span', { class: 'muted' }, 'window'), sel, h('span', { class: 'muted', id: 'series-info' })), h('div', { class: 'charts' }));
    view.append(wrap);
    for (const d of chartDefs) {
      const c = h('canvas', { class: 'chart' }); c.chartDef = d;
      $('.charts', wrap).append(h('div', { class: 'card' }, h('h2', null, d.title), c, h('div', { class: 'legend' }, d.series.map((s, i) => h('span', null, h('span', { class: 'swatch c' + i }), s)))));
    }
  }
  $('#series-info').textContent = (data.points || []).length + ' samples, ' + data.interval_seconds + 's interval';
  for (const c of view.querySelectorAll('canvas.chart')) drawChart(c, data, c.chartDef);
}};
function drawChart(canvas, data, def) {
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth, hgt = canvas.clientHeight;
  canvas.width = w * dpr; canvas.height = hgt * dpr;
  const ctx = canvas.getContext('2d'); ctx.scale(dpr, dpr);
  const cs = getComputedStyle(document.documentElement);
  ctx.clearRect(0, 0, w, hgt);
  const pts = data.points || [];
  const idx = def.series.map(s => data.names.indexOf(s));
  const padL = 46, padR = 8, padT = 6, padB = 18;
  let max = 0;
  for (const p of pts) for (const i of idx) if (i >= 0 && p.v[i] > max) max = p.v[i];
  if (max === 0) max = 1;
  max *= 1.1;
  ctx.strokeStyle = cs.getPropertyValue('--line'); ctx.lineWidth = 1;
  ctx.fillStyle = cs.getPropertyValue('--muted'); ctx.font = '11px system-ui';
  for (let g = 0; g <= 4; g++) {
    const y = padT + (hgt - padT - padB) * g / 4;
    ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(w - padR, y); ctx.stroke();
    const val = max * (1 - g / 4);
    ctx.fillText(def.bytes ? fmtBytes(val) : fmtNum(val), 2, y + 4);
  }
  if (pts.length) {
    const t0 = new Date(pts[0].t).getTime(), t1 = new Date(pts[pts.length - 1].t).getTime() || t0 + 1;
    const xOf = t => padL + (w - padL - padR) * (t1 === t0 ? 1 : (t - t0) / (t1 - t0));
    ctx.fillText(new Date(t0).toLocaleTimeString(), padL, hgt - 4);
    const lbl = new Date(t1).toLocaleTimeString(); ctx.fillText(lbl, w - padR - ctx.measureText(lbl).width, hgt - 4);
    idx.forEach((si, k) => {
      if (si < 0) return;
      ctx.strokeStyle = palette[k]; ctx.lineWidth = 1.5; ctx.beginPath();
      pts.forEach((p, j) => {
        const x = xOf(new Date(p.t).getTime()), y = padT + (hgt - padT - padB) * (1 - p.v[si] / max);
        if (j === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      });
      ctx.stroke();
    });
  } else {
    ctx.fillText('no samples yet', padL + 8, hgt / 2);
  }
}

// ---- configuration ----
views.config = { async render() {
  clear(view);
  const active = h('button', { class: 'secondary' }, 'Show active configuration');
  const activePre = h('pre', { class: 'hidden' });
  active.addEventListener('click', async () => {
    try { activePre.textContent = await get('/api/active-config'); activePre.classList.toggle('hidden'); } catch (e) { flash(e.message, 'bad'); }
  });
  view.append(h('div', { class: 'card' }, h('h2', null, 'Active configuration (as loaded by the data plane)'), active, activePre));
  if (!me.can_edit_file) {
    view.append(h('p', { class: 'muted' }, operator() ? 'no configuration file configured for editing' : 'editing requires the operator role'));
    return;
  }
  const f = await get('/api/config/file');
  const ta = h('textarea', { class: 'code', spellcheck: 'false' }); ta.value = f.text;
  ta.addEventListener('keydown', ev => { if (ev.key === 'Tab') { ev.preventDefault(); const s = ta.selectionStart; ta.setRangeText('  ', s, ta.selectionEnd, 'end'); } });
  let etag = f.etag;
  const problems = h('ul', { class: 'problems' });
  const status = h('span', { class: 'muted' }, f.path + ' (mode ' + f.mode + ')');
  const show = v => { clear(problems); if (v.ok) { flash('valid: ' + v.routes + ' routes, ' + v.upstreams + ' upstreams', 'ok'); } else { for (const p of v.problems) problems.append(h('li', null, p)); flash(v.problems.length + ' problem(s)', 'bad'); } };
  const validateBtn = h('button', { class: 'secondary' }, 'Validate');
  validateBtn.addEventListener('click', async () => { try { show(await post('/api/config/validate', { text: ta.value })); } catch (e) { flash(e.message, 'bad'); } });
  const saveBtn = h('button', null, 'Validate and save');
  saveBtn.addEventListener('click', async () => {
    try { const r = await api('PUT', '/api/config/file', { text: ta.value, etag }); etag = r.etag; clear(problems); flash('saved ' + r.path + '; reload to apply', 'ok'); }
    catch (e) { if (e.data && e.data.problems) show(e.data); else flash(e.message, 'bad'); }
  });
  const reloadBtn = actionButton('Reload data plane', '/api/reload', 'secondary');
  const revert = h('button', { class: 'secondary' }, 'Revert');
  revert.addEventListener('click', () => route());
  view.append(h('div', { class: 'card' }, h('h2', null, 'Configuration file'), h('div', { class: 'row' }, validateBtn, saveBtn, reloadBtn, revert, status), problems, ta,
    h('p', { class: 'muted' }, 'Save writes the file atomically and keeps the previous version in ', h('code', null, f.path + '.bak'), '. Listener, cluster and ACME changes need a restart; everything else applies on reload.')));
}};

// ---- logs ----
let logStream = 'security';
views.logs = { async render() {
  clear(view);
  const sel = h('select', null, ['access', 'error', 'security', 'audit'].map(v => h('option', { value: v, selected: v === logStream ? '' : null }, v)));
  const filter = h('input', { placeholder: 'filter (substring)', size: 30 });
  const pause = h('button', { class: 'secondary' }, 'Pause');
  const box = h('div', { class: 'log' });
  let paused = false;
  pause.addEventListener('click', () => { paused = !paused; pause.textContent = paused ? 'Resume' : 'Pause'; });
  const add = line => {
    if (filter.value && !line.includes(filter.value)) return;
    box.append(h('div', null, compact(line)));
    while (box.childElementCount > 2000) box.removeChild(box.firstChild);
    if (!paused) box.scrollTop = box.scrollHeight;
  };
  const start = async () => {
    if (es) { es.close(); es = null; }
    clear(box);
    try {
      const t = await get('/api/logs/' + logStream + '?lines=200');
      for (const l of t.lines) add(l);
    } catch (e) { flash(e.message, 'bad'); return; }
    es = new EventSource('/api/logs/' + logStream + '/follow');
    es.onmessage = ev => { if (!paused) add(ev.data); };
    es.onerror = () => { $('#refresh-state').textContent = 'log stream disconnected'; };
  };
  sel.addEventListener('change', () => { logStream = sel.value; start(); });
  view.append(h('div', { class: 'row' }, h('span', { class: 'muted' }, 'stream'), sel, filter, pause), box);
  await start();
}};
function compact(line) {
  try {
    const o = JSON.parse(line);
    const keys = ['ts', 'level', 'msg', 'client_ip', 'method', 'host', 'path', 'status', 'reason', 'route', 'upstream', 'duration_ms', 'request_id', 'action', 'user', 'target', 'err'];
    const parts = [];
    for (const k of keys) if (o[k] !== undefined) parts.push(k === 'ts' || k === 'msg' ? String(o[k]) : k + '=' + JSON.stringify(o[k]));
    for (const [k, v] of Object.entries(o)) if (!keys.includes(k) && k !== 'stream') parts.push(k + '=' + JSON.stringify(v));
    return parts.join(' ');
  } catch (e) { return line; }
}

boot();


// ---- routes, WAF, subsystems, history ----
views.routes = { refresh: 10000, async render() {
  const q = await get('/api/quotas');
  clear(view);
  if ((q.tenants || []).length) view.append(h('div', { class: 'card' }, h('h2', null, 'Tenants'),
    table(['Tenant', { label: 'Routes', num: true }, { label: 'Requests', num: true }, { label: 'Denied', num: true }, { label: 'Rate limited', num: true }, { label: 'Bytes in', num: true }, { label: 'Bytes out', num: true }],
      q.tenants.map(t => [t.tenant, t.routes, fmtNum(t.requests), fmtNum(t.denied), fmtNum(t.rate_limited), fmtBytes(t.bytes_in), fmtBytes(t.bytes_out)]))));
  view.append(h('div', { class: 'card' }, h('h2', null, 'Routes (generation ' + q.generation + ')'),
    table(['Route', 'Tenant', 'Upstream', { label: 'Requests', num: true }, { label: '2xx', num: true }, { label: '3xx', num: true }, { label: '4xx', num: true }, { label: '5xx', num: true }, { label: 'Denied', num: true }, { label: 'Rate limited', num: true }, { label: 'Bytes out', num: true }, { label: 'p50 ms', num: true }, { label: 'p95 ms', num: true }, { label: 'p99 ms', num: true }],
      (q.routes || []).map(r => [r.route, r.tenant || '-', r.upstream || '-', fmtNum(r.requests), fmtNum(r.status_2xx), fmtNum(r.status_3xx), fmtNum(r.status_4xx), fmtNum(r.status_5xx), fmtNum(r.denied), fmtNum(r.rate_limited), fmtBytes(r.bytes_out), r.latency_p50_ms, r.latency_p95_ms, r.latency_p99_ms]))));
  if ((q.rate_limits || []).length) view.append(h('div', { class: 'card' }, h('h2', null, 'Rate limit policies'),
    table(['Policy', 'Key', { label: 'Rate', num: true }, { label: 'Burst', num: true }, { label: 'Keys', num: true }, { label: 'Allowed', num: true }, { label: 'Denied', num: true }, 'Top consumers'],
      q.rate_limits.map(p => [p.policy, p.key, p.rate, p.burst, p.keys, fmtNum(p.allowed), fmtNum(p.denied), (p.top || []).map(u => u.key + '=' + fmtNum(u.total)).join(', ') || '-']))));
  if ((q.upstreams || []).length) view.append(h('div', { class: 'card' }, h('h2', null, 'Upstream share'),
    table(['Upstream', { label: 'Requests', num: true }, { label: 'Errors', num: true }, { label: 'Active', num: true }], q.upstreams.map(u => [u.upstream, fmtNum(u.requests), fmtNum(u.errors), u.active]))));
}};

views.waf = { refresh: 10000, async render() {
  const w = await get('/api/waf');
  clear(view);
  const l = w.learning || {};
  view.append(h('div', { class: 'grid' }, [['Enabled', w.enabled ? 'yes' : 'no'], ['Since', fmtTime(w.since)], ['Requests', fmtNum(w.requests)], ['Blocked', fmtNum(w.blocked)], ['Detected', fmtNum(w.detected)], ['Rules seen', w.total_rules],
    ['Learning', (l.enabled ? 'on' : 'off') + ', min hits ' + (l.min_hits || '-') + ', ' + (l.entries || 0) + '/' + (l.max_entries || 0) + ' entries' + (l.dropped ? ', ' + l.dropped + ' dropped' : '')]]
    .map(([k, v]) => h('div', { class: 'stat' }, h('div', { class: 'k' }, k), h('div', { class: 'v' }, v)))));
  if ((w.profiles || []).length) view.append(h('div', { class: 'card mt' }, h('h2', null, 'Profiles'),
    table(['Profile', 'Modes', 'Rule set', 'CRS version', { label: 'Rule files', num: true }], w.profiles.map(p => [p.name, (p.modes || []).join(', '), p.crs || '-', p.version || '-', p.rule_files || 0]))));
  if ((w.routes || []).length) view.append(h('div', { class: 'card' }, h('h2', null, 'Routes'),
    table(['Route', 'Profile', 'Mode'], w.routes.map(r => [r.route, r.profile, h('span', { class: r.mode === 'block' ? 'ok' : 'warn' }, r.mode)]))));
  view.append(h('div', { class: 'card' }, h('h2', null, 'Most matched rules'),
    (w.rules || []).length ? table([{ label: 'Rule', num: true }, { label: 'Matches', num: true }, { label: 'Blocks', num: true }, { label: 'Detects', num: true }, 'Severity', 'Last seen', 'Message', 'Last URI'],
      w.rules.map(r => [r.id, fmtNum(r.matches), fmtNum(r.blocks), fmtNum(r.detects), r.severity || '-', fmtTime(r.last_seen), r.message || '', r.last_uri || ''])) : h('p', { class: 'muted' }, 'no matches recorded'),
    operator() ? h('div', { class: 'row mt-s' }, actionButton('Reset statistics', '/api/waf/reset', 'secondary', 'Clear the WAF rule statistics and the learning table?')) : null));
  const props = l.proposals || [];
  view.append(h('div', { class: 'card' }, h('h2', null, 'Exclusion proposals (' + props.length + ')'),
    props.length ? table([{ label: 'Rule', num: true }, 'Target', 'Route', { label: 'Hits', num: true }, { label: 'Clients', num: true }, 'Last seen', 'Message', 'Directive'],
      props.map(p => [p.rule, p.target, p.route || '-', fmtNum(p.hits), p.clients, fmtTime(p.last_seen), p.message || '', h('code', null, p.directive)])) : h('p', { class: 'muted' }, l.enabled ? 'none yet' : 'learning is off (waf.learning.enabled)'),
    props.length ? h('p', { class: 'muted mt-s' }, 'Review before use: ', h('a', { href: '/api/waf/exclusions', target: '_blank' }, 'download as SecLang')) : null));
}};

// One page for the subsystems that expose a status document each.
const subsystems = [
  ['Sandbox', '/api/sandbox', d => h('div', null, h('div', { class: 'grid' }, [['Platform', d.platform], ['Enabled', d.enabled ? 'yes' : 'no'], ['Strict', d.strict ? 'yes' : 'no'], ['Applied', fmtTime(d.applied_at)], ['Landlock ABI', d.landlock_abi || '-'], ['Syscalls refused', d.seccomp_denied || 0]].map(([k, v]) => h('div', { class: 'stat' }, h('div', { class: 'k' }, k), h('div', { class: 'v' }, v)))),
    table(['Mechanism', 'State', 'Detail'], (d.mechanisms || []).map(m => [m.name, h('span', { class: m.state === 'applied' ? 'ok' : m.state === 'disabled' ? 'muted' : 'warn' }, m.state), m.detail || ''])),
    d.landlocked ? h('p', { class: 'muted' }, 'read: ' + (d.read_paths || []).join(', ') + ' — write: ' + (d.write_paths || []).join(', ')) : null)],
  ['Telemetry', '/api/telemetry', d => h('div', null, ...[['Metrics', d.metrics], ['Traces', d.traces], ['Logs', d.logs]].map(([k, v]) => h('div', null, h('h3', null, k), v ? jsonView(v) : h('p', { class: 'muted' }, 'not configured'))))],
  ['DNS', '/api/dns', d => (d || []).length ? h('div', null, ...d.map(l => h('div', null, h('h3', null, l.listener + (l.encrypted ? ' (DoT/DoH)' : '')), jsonView(l)))) : h('p', { class: 'muted' }, 'no dns listeners')],
  ['ICAP', '/api/icap', jsonView],
  ['Cache', '/api/cache', jsonView],
  ['GeoIP', '/api/geoip', jsonView],
  ['Honeypots', '/api/honeypot', jsonView],
  ['Filters', '/api/filters', jsonView],
  ['Ingress', '/api/ingress', jsonView],
  ['OpenTelemetry metrics', '/api/otlp', jsonView],
];
views.subsystems = { refresh: 10000, async render() {
  const results = await Promise.all(subsystems.map(([, path]) => get(path).then(d => ({ d })).catch(e => ({ e }))));
  clear(view);
  subsystems.forEach(([title, , render], i) => {
    const r = results[i];
    view.append(h('div', { class: 'card' }, h('h2', null, title), r.e ? h('p', { class: 'muted' }, 'not configured (' + r.e.message + ')') : render(r.d)));
  });
}};

views.history = { async render() {
  const [entries, pending] = await Promise.all([get('/api/history').catch(e => ({ e })), api('POST', '/api/reload/dry-run').catch(e => ({ e }))]);
  clear(view);
  const pend = h('div', { class: 'card' }, h('h2', null, 'Pending changes (file versus active)'));
  if (pending.e) pend.append(h('p', { class: 'muted' }, pending.e.message));
  else if (pending.same || !(pending.changes || []).length) pend.append(h('p', { class: 'muted' }, 'the file matches the active configuration'));
  else pend.append(table(['Section', 'Item', 'Change'], pending.changes.map(it => [it.section, it.name || '-', it.kind])),
    (pending.summary || []).length ? h('ul', null, pending.summary.map(l => h('li', null, l))) : null,
    (pending.restart_needed || []).length ? h('p', { class: 'warn mt-s' }, 'needs a restart: ' + pending.restart_needed.join(', ')) : null,
    (pending.drains || []).length ? h('p', { class: 'muted mt-s' }, 'applied with a connection drain: ' + pending.drains.join(', ')) : null,
    pending.text ? h('pre', { class: 'diff' }, pending.text + (pending.truncated ? '\n... (truncated)' : '')) : null);
  view.append(pend);
  const hist = h('div', { class: 'card' }, h('h2', null, 'Recorded configurations'));
  if (entries.e) hist.append(h('p', { class: 'muted' }, entries.e.message + ' (set management.history_dir)'));
  else hist.append(table(['Id', { label: 'Generation', num: true }, 'Applied', 'Note', 'Source', { label: 'Size', num: true }, ''],
    (entries || []).map(e => [e.id, e.generation, fmtTime(e.applied), e.note, e.source, fmtBytes(e.size), operator() ? rollbackButton(e.id) : ''])));
  view.append(hist);
}};
function rollbackButton(id) {
  const b = h('button', { class: 'secondary' }, 'Roll back');
  b.addEventListener('click', async () => {
    if (!confirm('Apply the recorded configuration ' + id + '?')) return;
    try { await post('/api/rollback', { id }); flash('rolled back to ' + id, 'ok'); route(); }
    catch (e) { flash(e.message, 'bad'); }
  });
  return b;
}

// ---- second factors ----
// The enrolment file is the authority and every listener re-reads it,
// so what is done here takes effect on the next connection without a
// reload. An enrolment hands back a secret and recovery codes that
// exist nowhere else: they stay on the page until they are dismissed,
// which is also why this view does not refresh itself — a timer would
// wipe them while they were still being written down.
let mfaShown = null;

views.mfa = { async render() {
  const listeners = await get('/api/mfa');
  clear(view);
  view.append(h('div', { class: 'row' },
    h('button', { class: 'secondary', onclick: () => route() }, 'Refresh'),
    h('span', { class: 'muted' }, 'Enrolments are read from the file as connections arrive: a change here applies at once, without a reload.')));
  if (mfaShown) view.append(mfaSecretCard(mfaShown));
  if (!listeners.length) {
    view.append(h('p', { class: 'muted' }, 'No listener asks for a second factor. Set mfa.file on an ssh, sftp, ftp, telnet, vnc or rdp listener.'));
    return;
  }
  for (const l of listeners) {
    const users = l.users || [];
    const rows = users.map(u => [u.user, u.digits, u.period_seconds + 's', u.algo,
      (u.recovery - u.recovery_spent) + ' / ' + u.recovery, mfaState(u),
      operator() ? h('div', { class: 'row tight' },
        mfaAction('New codes', '/api/mfa/recovery', l.listener, u.user, null, 'Replace the recovery codes of ' + u.user + '? The old ones stop working.', true),
        u.locked || u.failures ? mfaAction('Unlock', '/api/mfa/unlock', l.listener, u.user) : null,
        mfaAction('Remove', '/api/mfa/remove', l.listener, u.user, 'danger', 'Take the second factor away from ' + u.user + '? They keep their password.')) : '']);
    view.append(h('div', { class: 'card' },
      h('h2', null, l.listener + ' (' + l.kind + ')'),
      h('p', { class: 'muted' }, 'file ' + l.file + ' — every listener reading this file shares these enrolments; a lockout is counted per listener.'),
      rows.length ? table(['User', { label: 'Digits', num: true }, { label: 'Period', num: true }, 'Algorithm', { label: 'Recovery left', num: true }, 'State', ''], rows)
        : h('p', { class: 'muted' }, 'nobody is enrolled'),
      operator() ? mfaEnrolForm(l.listener) : null));
  }
}};

function mfaState(u) {
  if (u.locked) return h('span', { class: 'bad' }, 'locked until ' + fmtTime(u.locked_until));
  if (u.failures) return h('span', { class: 'warn' }, u.failures + ' wrong code(s)');
  return h('span', { class: 'ok' }, 'ok');
}

// mfaAction runs one of the three per-person changes. What comes back
// from a recovery reset is shown once, like an enrolment.
function mfaAction(label, path, listener, user, cls, confirmText, show) {
  const b = h('button', { class: cls || 'secondary' }, label);
  b.addEventListener('click', async () => {
    if (confirmText && !confirm(confirmText)) return;
    b.disabled = true;
    try {
      const r = await post(path, { listener, user });
      mfaShown = show ? Object.assign({ listener, user }, r) : mfaShown;
      flash(label + ': ' + user + ' on ' + listener, 'ok');
      route();
    } catch (e) { flash(e.message, 'bad'); b.disabled = false; }
  });
  return b;
}

function mfaEnrolForm(listener) {
  const user = h('input', { placeholder: 'user name', size: 18 });
  const issuer = h('input', { placeholder: 'issuer (optional)', size: 14 });
  const digits = h('select', null, h('option', { value: '' }, '6 digits'), h('option', { value: '8' }, '8 digits'));
  const period = h('select', null, h('option', { value: '' }, '30 s'), h('option', { value: '60' }, '60 s'));
  const algo = h('select', null, h('option', { value: '' }, 'SHA1'), h('option', { value: 'SHA256' }, 'SHA256'), h('option', { value: 'SHA512' }, 'SHA512'));
  const b = h('button', null, 'Enrol');
  b.addEventListener('click', async () => {
    const name = user.value.trim();
    if (!name) { flash('a user name is required', 'bad'); return; }
    b.disabled = true;
    try {
      const req = { listener, user: name };
      if (issuer.value.trim()) req.issuer = issuer.value.trim();
      if (digits.value) req.digits = Number(digits.value);
      if (period.value) req.period_seconds = Number(period.value);
      if (algo.value) req.algo = algo.value;
      const r = await post('/api/mfa/enrol', req);
      mfaShown = Object.assign({ listener, user: name }, r);
      flash('enrolled ' + name + ' on ' + listener, 'ok');
      route();
    } catch (e) { flash(e.message, 'bad'); b.disabled = false; }
  });
  // Authenticators that only take the defaults are the common case, so
  // the parameters are the last thing on the row, not the first.
  return h('div', { class: 'row mt-s' }, h('span', { class: 'muted' }, 'Enrol'), user, issuer, digits, period, algo, b);
}

// mfaSecretCard shows what cannot be read again. It stays until it is
// dismissed by hand.
function mfaSecretCard(s) {
  const card = h('div', { class: 'card shown-once' },
    h('h2', null, 'Shown once: ' + s.user + ' on ' + s.listener),
    h('p', { class: 'warn' }, 'None of this can be read again. The file keeps only hashes; if it is lost, enrol the person again.'));
  if (s.secret) card.append(h('div', { class: 'row' }, h('span', { class: 'muted' }, 'Secret'), h('code', null, groupsOf(s.secret, 4)), copyButton(s.secret, 'Copy secret')));
  if (s.uri) card.append(h('div', { class: 'row' }, h('span', { class: 'muted' }, 'otpauth URI'), h('code', { class: 'wrap' }, s.uri), copyButton(s.uri, 'Copy URI')),
    h('p', { class: 'muted' }, 'Enter the secret in the authenticator by hand, or paste the URI into one that reads them.'));
  const codes = s.recovery || [];
  if (codes.length) card.append(h('p', { class: 'muted mt-s' }, 'Recovery codes, one use each:'),
    h('ul', { class: 'codes' }, codes.map(c => h('li', null, c))),
    copyButton(codes.join('\n'), 'Copy codes'));
  card.append(h('div', { class: 'row mt-s' }, h('button', { class: 'secondary', onclick: () => { mfaShown = null; route(); } }, 'Dismiss')));
  return card;
}

function groupsOf(s, n) {
  const out = [];
  for (let i = 0; i < s.length; i += n) out.push(s.slice(i, i + n));
  return out.join(' ');
}

function copyButton(text, label) {
  const b = h('button', { class: 'secondary' }, label || 'Copy');
  b.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(text); flash('copied', 'ok'); }
    catch (e) { flash('the browser refused the clipboard; select the text instead', 'bad'); }
  });
  return b;
}
