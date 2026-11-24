/* Maintenance: the router's services (restart, stop, start, reboot the host), their journal,
   network tests from Linux or from inside VPP, and a download of the configuration.
   vpp-system does the work. */
import { $, fetchJSON, postJSON, fillBody, bytes } from '../lib.js';

const API = 'api/system/maint';
const MAX_LINES = 5000;
const page = {
  shown: false, units: null, timer: 0, fastUntil: 0, busy: false, lost: false,
  cursor: '', followTimer: 0, logQuery: null, lines: 0, sources: null, testing: false,
};
const ACTIVE = { active: '运行中', inactive: '已停止', failed: '失败', activating: '启动中', deactivating: '停止中', reloading: '重新加载' };
const ENABLED = { enabled: '是', disabled: '否', static: '随依赖', indirect: '间接', masked: '已屏蔽', generated: '生成', 'enabled-runtime': '本次开机', alias: '别名' };
const ACTIONS = { restart: '重启', stop: '停止', start: '启动' };

function message(text, isError) {
  $('maint-message').textContent = text || '';
  $('maint-message').classList.toggle('error', !!isError);
}

function schedule() {
  clearTimeout(page.timer);
  if (!page.shown) return;
  page.timer = setTimeout(loadUnits, Date.now() < page.fastUntil ? 2000 : 5000);
}

async function loadUnits() {
  try {
    page.units = await fetchJSON(`${API}/units`);
    $('maint-content').hidden = false;
    $('maint-unavailable').hidden = true;
    if (page.lost) { page.lost = false; message('已重新连上。'); }
    renderUnits();
    if (!page.sources) loadSources();
    if (!page.logQuery) loadLogs();
  } catch (err) {
    if (page.units) {
      page.lost = true;
      message('连接中断，等待恢复…（重启 VPP 或面板时这是正常的）', true);
    } else {
      $('maint-content').hidden = true;
      $('maint-unavailable').hidden = false;
      $('maint-unavailable').textContent = '无法读取服务：' + err.message + '。维护页由 vpp-system 提供，确认它在运行。';
    }
  }
  schedule();
}

function since(unit) {
  if (!unit.since) return '—';
  const seconds = Math.max(0, Date.now() / 1000 - unit.since);
  if (seconds < 60) return Math.round(seconds) + ' 秒';
  if (seconds < 3600) return Math.round(seconds / 60) + ' 分钟';
  if (seconds < 86400) return Math.floor(seconds / 3600) + ' 小时 ' + Math.round(seconds % 3600 / 60) + ' 分';
  return Math.floor(seconds / 86400) + ' 天 ' + Math.floor(seconds % 86400 / 3600) + ' 小时';
}

function stateText(unit) {
  const text = ACTIVE[unit.active] || unit.active;
  const sub = unit.sub && unit.sub !== unit.active && !(unit.active === 'active' && unit.sub === 'running') && !(unit.active === 'inactive' && unit.sub === 'dead') ? `（${unit.sub}）` : '';
  const result = unit.active === 'failed' && unit.result && unit.result !== 'success' ? `：${unit.result}` : '';
  return text + sub + result;
}

function stateClass(unit) {
  if (unit.active === 'failed') return 'unit-failed';
  if (unit.active === 'active') return 'unit-active';
  if (unit.active === 'activating' || unit.active === 'deactivating' || unit.active === 'reloading') return 'unit-changing';
  return '';
}

function actionButton(text, onClick, disabled) {
  const b = document.createElement('button');
  b.className = 'close';
  b.textContent = text;
  b.onclick = onClick;
  b.disabled = !!disabled;
  return b;
}

function renderUnitRow(tr, unit) {
  while (tr.children.length < 7) tr.append(document.createElement('td'));
  const [nameCell, stateCell, enabledCell, sinceCell, memCell, restartsCell, actionsCell] = tr.children;
  const label = unit.name.replace(/\.service$/, '');
  const roles = { vpp: '（VPP）', panel: '（本面板）', self: '（执行维护操作）' };
  nameCell.replaceChildren(document.createTextNode(label + (roles[unit.role] || '')));
  if (unit.description && unit.description !== label) {
    const d = document.createElement('span');
    d.className = 'unit-desc';
    d.textContent = unit.description;
    nameCell.append(d);
  }
  stateCell.textContent = stateText(unit);
  stateCell.className = stateClass(unit);
  enabledCell.textContent = ENABLED[unit.enabled] || unit.enabled || '—';
  sinceCell.textContent = since(unit);
  memCell.textContent = unit.memory ? bytes(unit.memory) : '—';
  restartsCell.textContent = String(unit.restarts || 0);
  const busy = page.busy;
  const span = document.createElement('span');
  span.className = 'row-actions';
  span.append(actionButton('日志', () => showLogsOf(unit.name)));
  const blocked = unit.role === 'vpp' && page.units.pending;
  span.append(actionButton(ACTIONS.restart, () => act(unit, 'restart'), busy || blocked));
  if (!unit.role) {
    const running = unit.active === 'active' || unit.active === 'activating' || unit.active === 'reloading';
    span.append(running ? actionButton(ACTIONS.stop, () => act(unit, 'stop'), busy) : actionButton(ACTIONS.start, () => act(unit, 'start'), busy));
  }
  actionsCell.replaceChildren(span);
}

function renderUnits() {
  const v = page.units;
  const related = v.units.filter(u => u.related);
  const others = v.units.filter(u => !u.related);
  fillBody($('maint-units').tBodies[0], related.length, (tr, i) => renderUnitRow(tr, related[i]));
  fillBody($('maint-other-units').tBodies[0], others.length, (tr, i) => renderUnitRow(tr, others[i]));
  $('maint-other').hidden = others.length === 0;
  $('maint-other-summary').textContent = `其他服务（${others.length}）`;
  $('maint-pending').hidden = !v.pending;
  $('maint-pending').textContent = v.pending ? `${v.pending}：确认或恢复以前不能重启 VPP 或主机。` : '';
  const vpp = v.units.find(u => u.role === 'vpp');
  $('maint-restart-vpp').hidden = !vpp;
  $('maint-restart-vpp').disabled = page.busy || !!v.pending;
  $('maint-reboot').disabled = page.busy || !!v.pending;
  if (v.backup && v.backup.length) $('backup-paths').textContent = v.backup.join('、');
  renderLogSources();
}

function confirmText(unit, action) {
  const name = unit.name.replace(/\.service$/, '');
  if (unit.role === 'vpp') return `重启 VPP（${name}）？\n\n所有转发中断，通常十几秒；经局域网打开的面板也会断开，恢复后自动重新连上。`;
  if (unit.role === 'panel') return `重启面板（${name}）？\n\n页面会断开几秒，需要重新登录；内存里的历史曲线会清空。`;
  if (unit.role === 'self') return `重启 ${name}？\n\n系统页和维护页会有几秒不可用。`;
  if (action === 'stop') return `停止 ${name}？\n\n它提供的功能在启动前都不可用，VPP 或主机重启后按开机设置决定是否运行。`;
  return `${ACTIONS[action]} ${name}？`;
}

async function act(unit, action) {
  if (page.busy || !confirm(confirmText(unit, action))) return;
  await post({ unit: unit.name, action }, `已${ACTIONS[action]} ${unit.name.replace(/\.service$/, '')}。`);
}

async function post(body, done) {
  page.busy = true;
  renderUnits();
  message('正在执行…');
  try {
    page.units = await postJSON(`${API}/units`, body);
    message(done);
  } catch (err) {
    message(err.message, true);
  } finally {
    page.busy = false;
    page.fastUntil = Date.now() + 30000;
    if (page.units) renderUnits();
    schedule();
  }
}

$('maint-restart-vpp').onclick = () => {
  const vpp = page.units && page.units.units.find(u => u.role === 'vpp');
  if (vpp) act(vpp, 'restart');
};
$('maint-reboot').onclick = () => {
  if (page.busy) return;
  if (!confirm('重启主机？\n\n路由器的所有功能中断，通常要一两分钟才能恢复，期间面板无法访问。')) return;
  if (!confirm('再确认一次：现在重启主机。')) return;
  post({ action: 'reboot' }, '主机将在几秒后重启，恢复后刷新页面。');
};

/* Logs. */

function renderLogSources() {
  const select = $('log-unit');
  const v = page.units;
  const options = [['', 'syslog']];
  for (const u of v.units.filter(u => u.related)) options.push([u.name, u.name.replace(/\.service$/, '')]);
  options.push(['kernel', '内核']);
  if (v.vpp_unit) options.push(['vpp:logging', 'VPP 内部日志（show logging）']);
  for (const u of v.units.filter(u => !u.related)) options.push([u.name, u.name.replace(/\.service$/, '') + '（其他）']);
  const key = options.map(o => o[0]).join('\n');
  if (select.dataset.key === key) return;
  const value = select.value || (v.vpp_unit || '');
  select.replaceChildren(...options.map(([value, text]) => new Option(text, value)));
  select.value = options.some(o => o[0] === value) ? value : '';
  select.dataset.key = key;
  updateLogControls();
}

function logQuery() {
  const q = new URLSearchParams();
  const unit = $('log-unit').value;
  if (unit) q.set('unit', unit);
  const range = $('log-since').value;
  if (range === 'boot') q.set('boot', '1');
  else if (range) q.set('since', String(Math.floor(Date.now() / 1000) - Number(range)));
  q.set('lines', $('log-lines').value);
  if ($('log-priority').value) q.set('priority', $('log-priority').value);
  const grep = $('log-grep').value.trim();
  if (grep) q.set('grep', grep);
  return q;
}

function updateLogControls() {
  const vppLog = $('log-unit').value === 'vpp:logging';
  $('log-follow').disabled = vppLog;
  if (vppLog) { $('log-follow').checked = false; stopFollow(); }
  $('log-since').disabled = vppLog;
  $('log-priority').disabled = vppLog;
  const q = logQuery();
  q.set('lines', '50000');
  $('log-download').href = `${API}/logs.txt?${q}`;
}

const pad = n => String(n).padStart(2, '0');
function stamp(micros) {
  const d = new Date(micros / 1000);
  return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function appendEntries(entries, replace) {
  const view = $('log-view');
  const atBottom = view.scrollHeight - view.scrollTop - view.clientHeight < 40;
  if (replace) { view.textContent = ''; page.lines = 0; }
  const fragment = document.createDocumentFragment();
  for (const e of entries) {
    const line = document.createElement('div');
    if (e.priority <= 3) line.className = 'p3';
    else if (e.priority === 4) line.className = 'p4';
    const src = document.createElement('span');
    src.className = 'src';
    src.textContent = `${stamp(e.time)} ${e.source || ''}: `;
    line.append(src, document.createTextNode(e.message));
    fragment.append(line);
  }
  view.append(fragment);
  page.lines += entries.length;
  while (page.lines > MAX_LINES && view.firstChild) { view.firstChild.remove(); page.lines--; }
  if (replace || atBottom) view.scrollTop = view.scrollHeight;
}

async function loadLogs() {
  stopFollow();
  const q = logQuery();
  page.logQuery = q;
  $('log-status').textContent = '正在读取…';
  try {
    const result = await fetchJSONError(`${API}/logs?${q}`);
    if (result.text != null && $('log-unit').value === 'vpp:logging') {
      const view = $('log-view');
      view.textContent = result.text || '（没有内容）';
      page.lines = 0;
      view.scrollTop = view.scrollHeight;
    } else {
      appendEntries(result.entries, true);
      if (!result.entries.length) $('log-view').textContent = '（没有符合条件的日志）';
    }
    page.cursor = result.cursor || '';
    $('log-status').textContent = result.truncated ? `只显示最后 ${$('log-lines').value} 行，更早的用“下载”。` : '';
    if ($('log-follow').checked) startFollow();
  } catch (err) {
    $('log-status').textContent = '读取失败：' + err.message;
  }
}

/* fetchJSON, but with the service's error text. */
async function fetchJSONError(url) {
  const response = await fetch(url);
  if (response.status === 401) { location.href = '/login.html'; throw new Error('需要登录'); }
  const result = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(result.error || response.statusText);
  return result;
}

function startFollow() {
  stopFollow();
  if (!page.shown || !page.logQuery) return;
  page.followTimer = setTimeout(follow, 2000);
}

function stopFollow() {
  clearTimeout(page.followTimer);
  page.followTimer = 0;
}

async function follow() {
  const q = new URLSearchParams(page.logQuery);
  q.delete('since');
  q.delete('boot');
  q.set('lines', '2000');
  if (page.cursor) q.set('after', page.cursor);
  try {
    const result = await fetchJSONError(`${API}/logs?${q}`);
    if (result.entries.length) {
      if (!page.lines) $('log-view').textContent = '';
      appendEntries(result.entries, false);
    }
    page.cursor = result.cursor || page.cursor;
    $('log-status').textContent = '实时跟踪中，每 2 秒读取新日志。';
  } catch (err) {
    $('log-status').textContent = '跟踪中断：' + err.message + '，稍后重试。';
  }
  if ($('log-follow').checked) startFollow();
}

function showLogsOf(unit) {
  $('log-unit').value = unit;
  updateLogControls();
  loadLogs();
  $('maint-logs-card').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

$('log-load').onclick = loadLogs;
$('log-grep').onkeydown = event => { if (event.key === 'Enter') loadLogs(); };
for (const id of ['log-unit', 'log-since', 'log-lines', 'log-priority']) $(id).onchange = () => { updateLogControls(); loadLogs(); };
$('log-grep').oninput = updateLogControls;
$('log-follow').onchange = () => {
  if (!$('log-follow').checked) { stopFollow(); $('log-status').textContent = ''; return; }
  if (!page.logQuery) loadLogs(); else startFollow();
};

/* Network tests. */

async function loadSources() {
  try {
    page.sources = await fetchJSON(`${API}/sources`);
  } catch {
    page.sources = { linux: [], vpp: [], vpp_error: '读取失败', traceroute: '' };
  }
  updateTestForm();
}

function updateTestForm() {
  const kind = $('test-kind').value;
  const src = page.sources || { linux: [], vpp: [], traceroute: '' };
  if (kind !== 'ping') $('test-from').value = 'linux';
  const fromVPP = $('test-from').value === 'vpp';
  $('test-from-field').hidden = kind !== 'ping';
  $('test-count-field').hidden = kind !== 'ping';
  $('test-server-field').hidden = kind !== 'dns';
  $('test-type-field').hidden = kind !== 'dns';
  $('test-family').parentElement.hidden = kind === 'dns';
  $('test-target').placeholder = kind === 'http' ? 'https://example.com/' : kind === 'dns' ? '域名' : 'IP 地址或域名';
  const tracepath = kind === 'traceroute' && !src.trace_interface;
  const names = fromVPP ? src.vpp : src.linux;
  const select = $('test-interface');
  const key = (fromVPP ? 'vpp\n' : 'linux\n') + names.join('\n');
  if (select.dataset.key !== key) {
    const value = select.value;
    select.replaceChildren(new Option(fromVPP ? '自动（按 VPP 路由）' : '自动（按路由表）', ''), ...names.map(n => new Option(n, n)));
    select.value = names.includes(value) ? value : '';
    select.dataset.key = key;
  }
  select.parentElement.hidden = tracepath;
  const help = {
    ping: fromVPP
      ? 'VPP 自己发出的 ping，经 VPP 的路由表（FIB 0）。指定接口时用这个接口的地址做源地址。域名先用主机的 DNS 解析。' + (src.vpp_error ? `现在不可用：${src.vpp_error}。` : '')
      : '从 Linux 本机发出，经主机的路由表。指定接口时只从这个接口发出（-I）。',
    traceroute: !src.traceroute ? '主机上没有 traceroute 或 tracepath，装上其中一个才能用。'
      : src.traceroute === 'inetutils' ? '用主机上的 traceroute（GNU inetutils，只支持 IPv4，IPv6 改用 tracepath），最多 20 跳，每跳等 2 秒。它不能指定接口，要指定接口请装 Linux 的 traceroute。'
      : src.traceroute === 'tracepath' ? '用主机上的 tracepath，最多 20 跳。它不能指定接口，要指定接口请装 traceroute。'
      : '用主机上的 traceroute，最多 20 跳，每跳等 2 秒。指定接口时只从这个接口发出。',
    dns: '从 Linux 本机查询。留空用主机的 DNS（/etc/resolv.conf）；填 IP 或 IP:端口时直接问这个服务器，比如路由器的 Gate 或某个出口的 DNS，这时可以指定接口。',
    http: '从 Linux 本机访问，不跟随跳转，读取最多 1 MiB 后显示每一步的耗时、状态码和证书。指定接口时只从这个接口连接。',
  };
  $('test-help').textContent = help[kind];
  $('test-run').disabled = page.testing || (kind === 'traceroute' && !src.traceroute) || (fromVPP && !!src.vpp_error);
}

for (const id of ['test-kind', 'test-from']) $(id).onchange = updateTestForm;
$('test-target').onkeydown = event => { if (event.key === 'Enter') runTest(); };
$('test-run').onclick = runTest;

async function runTest() {
  if (page.testing) return;
  const target = $('test-target').value.trim();
  if (!target) { $('test-target').focus(); return; }
  const kind = $('test-kind').value;
  const body = {
    kind, target, from: $('test-from').value, interface: $('test-interface').parentElement.hidden ? '' : $('test-interface').value,
    family: kind === 'dns' ? 0 : Number($('test-family').value), count: Number($('test-count').value) || 4,
    server: kind === 'dns' ? $('test-server').value.trim() : '', type: $('test-type').value,
  };
  page.testing = true;
  updateTestForm();
  const view = $('test-view');
  view.hidden = false;
  view.textContent = '正在测试…（最长 40 秒）';
  view.classList.remove('error');
  try {
    const r = await postJSON(`${API}/test`, body);
    const tail = r.timed_out ? `超时，用时 ${r.seconds.toFixed(1)} 秒` : `${r.ok ? '成功' : '失败'}，用时 ${r.seconds.toFixed(1)} 秒`;
    view.textContent = `$ ${r.command}\n${r.output.replace(/\s+$/, '')}\n\n— ${tail}`;
    view.classList.toggle('error', !r.ok);
  } catch (err) {
    view.textContent = '无法测试：' + err.message;
    view.classList.add('error');
  } finally {
    page.testing = false;
    updateTestForm();
  }
}

export function start() {}

export function show() {
  page.shown = true;
  loadUnits();
  if (page.units && $('log-follow').checked) startFollow();
}

export function hide() {
  page.shown = false;
  clearTimeout(page.timer);
  stopFollow();
}
