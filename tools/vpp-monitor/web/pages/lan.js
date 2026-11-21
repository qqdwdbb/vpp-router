/* LAN: the dnsmasq's DHCP range, static hosts and the devices behind them. vpp-interfaces
   makes the changes. Per-device traffic comes from the LAN meter when it is on (ACL counters
   on the LAN gateway, read from the stats segment, with history), and otherwise from NAT
   sessions, read only while this page is open. */
import { $, FORMATS, fetchJSON, postJSON, fillBody, idleText, color, token } from '../lib.js';

const API = 'api/interfaces/dhcp';
const page = { state: null, nat: null, natError: '', meter: null, traffic: null, timer: 0, busy: false, device: '',
  range: 86400, plot: null, plotTimer: 0 };
const RANGES = [[3600, '1 小时'], [86400, '24 小时'], [604800, '7 天']];

const metering = () => !!(page.meter && page.meter.enabled);

function message(text, isError) {
  $('lan-message').textContent = text || '';
  $('lan-message').classList.toggle('error', !!isError);
}

async function load() {
  try {
    page.meter = await fetchJSON('api/interfaces/meter').catch(() => null);
    page.state = await fetchJSON(API);
    $('lan-content').hidden = false;
    $('lan-unavailable').hidden = true;
  } catch (err) {
    $('lan-content').hidden = true;
    $('lan-unavailable').hidden = false;
    $('lan-unavailable').textContent = '无法读取局域网的 DHCP：' + err.message;
    return;
  }
  render();
}

/* NAT sessions are read through VPP's API, which pauses the workers a moment, so only while
   this page is open; the panel itself reads them at most every 5 seconds. */
async function loadNAT() {
  try {
    const report = await fetchJSON('api/nat');
    page.nat = report.available ? report : null;
    page.natError = report.available ? '' : report.reason;
  } catch (err) {
    page.nat = null;
    page.natError = err.message;
  }
  render();
}

/* The meter's readings: the stats segment only, no VPP API. */
async function loadTraffic() {
  try {
    page.traffic = await fetchJSON('api/lan/traffic');
  } catch {
    page.traffic = null;
  }
  render();
}

function refreshTraffic() {
  if (metering()) loadTraffic();
  else loadNAT();
}

async function apply(path, body, description, after) {
  if (page.busy) return false;
  if (description && !confirm(description)) return false;
  page.busy = true;
  message('正在应用…');
  $('lan-device-error').textContent = '';
  try {
    page.state = await postJSON(`${API}/${path}`, body);
    message(after || '');
    return true;
  } catch (err) {
    message(err.message, true);
    $('lan-device-error').textContent = err.message;
    return false;
  } finally {
    page.busy = false;
    render();
  }
}

function button(text, onClick, disabled) {
  const element = document.createElement('button');
  element.className = 'close';
  element.textContent = text;
  element.onclick = onClick;
  element.disabled = !!disabled;
  return element;
}

/* Value cells, then one cell for the actions; text columns, as their headers say, align left. */
function row(tr, values, actions) {
  const count = values.length + 1;
  while (tr.children.length < count) tr.append(document.createElement('td'));
  while (tr.children.length > count) tr.lastChild.remove();
  const heads = tr.closest('table')?.tHead?.rows[0]?.cells;
  values.forEach((value, i) => {
    tr.children[i].className = heads?.[i]?.classList.contains('text') ? 'text' : '';
    if (value instanceof Node) tr.children[i].replaceChildren(value);
    else if (tr.children[i].textContent !== value) tr.children[i].textContent = value;
  });
  const cell = tr.lastChild;
  const span = document.createElement('span');
  span.className = 'row-actions';
  span.append(...(actions || []).filter(Boolean));
  cell.replaceChildren(span);
}

function ago(time) {
  if (!time) return '—';
  const seconds = (Date.now() - new Date(time).getTime()) / 1000;
  if (seconds >= 86400) return Math.floor(seconds / 86400) + ' 天前';
  return seconds < 60 ? '刚才' : idleText(seconds) + '前';
}

function clock(time) {
  const date = new Date(time);
  const pad = n => String(n).padStart(2, '0');
  const today = new Date().toDateString() === date.toDateString();
  return (today ? '' : `${date.getMonth() + 1}-${date.getDate()} `) + `${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

const byID = id => page.state.devices.find(d => d.id === id);
const labelOf = id => byID(id)?.label || id;

/* A device's traffic: from the meter by MAC, or from NAT by address. */
function traffic(device) {
  if (metering()) {
    if (!page.traffic || !page.traffic.enabled) return null;
    const macs = new Set(device.macs.map(m => m.mac));
    let up = 0, down = 0, v6 = 0, seen = false;
    for (const r of page.traffic.rates) {
      if (!macs.has(r.mac)) continue;
      seen = true;
      up += r.up_bps;
      down += r.down_bps;
      if (r.address.includes(':')) v6++;
    }
    return { up, down, v6, idle: !seen || up + down < 1000, meter: true };
  }
  if (!page.nat) return null;
  let bps = 0, pps = 0, sessions = 0, seen = false;
  for (const user of page.nat.users) {
    if (!device.ips.includes(user.address)) continue;
    seen = true;
    bps += user.bps || 0;
    pps += user.pps || 0;
    sessions += (user.dynamic || 0) + (user.static || 0);
  }
  return seen ? { bps, pps, sessions } : { bps: 0, pps: 0, sessions: 0, idle: true };
}

function status(device) {
  const t = traffic(device);
  if (t && !t.idle) return { text: t.meter ? '有流量' : '有连接', className: 'online', rank: 0 };
  if (device.macs.some(m => m.active)) return { text: '租约中', className: '', rank: 1 };
  return { text: '离线', className: 'offline', rank: 2 };
}

function deviceCell(device) {
  const box = document.createElement('div');
  const name = document.createElement('strong');
  name.textContent = device.label;
  box.append(name);
  const details = [];
  if (device.name && device.label === device.name) {
    const host = device.macs.find(m => m.hostname)?.hostname;
    if (host && host !== device.name) details.push(host);
  }
  details.push(device.macs.length > 1 ? `${device.macs.length} 个 MAC 地址` : device.macs[0]?.mac || '');
  if (device.macs.some(m => m.random)) details.push('随机地址');
  if (device.suggest.length) details.push('可能是 ' + device.suggest.map(labelOf).join('、'));
  const small = document.createElement('small');
  small.className = 'switch-help';
  small.textContent = details.filter(Boolean).join(' · ');
  box.append(small);
  return box;
}

function renderSummary() {
  const s = page.state;
  $('lan-summary').textContent = `网段 ${s.network}，网关 ${s.router}，发给设备的 DNS ${s.server || s.router}（局域网的 DNS 查询由 Gate 接管时，上游在路由页 default 行修改）。地址池 ${s.range.start} – ${s.range.end}，租期 ${s.range.lease}。`;
  const typing = document.activeElement?.closest?.('#page-lan .form-row');
  if (!typing) {
    $('lan-range-start').value = s.range.start;
    $('lan-range-end').value = s.range.end;
    $('lan-range-lease').value = s.range.lease;
    if (!$('lan-host-ip').placeholder) $('lan-host-ip').placeholder = `比如 ${s.network.replace(/\.\d+\/\d+$/, '.20')}`;
  }
}

function renderMeter() {
  const m = page.meter;
  const on = metering();
  $('lan-meter-toggle').textContent = on ? '关闭' : '开启';
  $('lan-meter-toggle').disabled = page.busy || !m;
  let state = !m ? '不可用' : on ? `已开启，在 ${m.interface || '局域网网关'} 上统计 ${m.rules.length} 个地址` : '未开启';
  if (m && m.error) state += `（${m.error}）`;
  $('lan-meter-state').textContent = state;
  $('lan-meter-state').className = m && m.error ? 'error' : '';
  $('lan-meter-help').textContent = on
    ? '速率来自局域网网关接口上的 ACL 计数：走代理、IPv6、隧道的流量都算在内，每 10 秒更新，“详情”里有流量曲线（监控进程重启后清空）。关闭后恢复用 NAT 会话估算。'
    : '开启后在局域网网关接口上挂两张 ACL，按设备地址计数所有流量（包括走代理、IPv6 和隧道的），读取不会让 VPP 暂停，并记录每台设备的流量历史。代价是经过网关的每个包多一次 ACL 查找：R6S 小核用 64 字节小包打满时，转发能力约降 5%，平时的流量下只是多占一点 CPU。未开启时，速率来自 NAT 会话，只在页面打开时读取，走代理和 IPv6 的流量统计不到。';
  $('lan-col-a').textContent = on ? '上传' : '速率';
  $('lan-col-b').textContent = on ? '下载' : '连接';
}

function renderDevices() {
  const devices = page.state.devices.map(device => ({ device, status: status(device), traffic: traffic(device) }));
  const volume = t => t ? (t.meter ? t.up + t.down : t.bps) : 0;
  devices.sort((a, b) => a.status.rank - b.status.rank || volume(b.traffic) - volume(a.traffic) ||
    a.device.label.localeCompare(b.device.label, 'zh-CN'));
  $('lan-devices-empty').hidden = devices.length > 0;
  fillBody($('lan-devices').tBodies[0], devices.length, (tr, i) => {
    const { device, status: st, traffic: t } = devices[i];
    const state = document.createElement('span');
    state.className = st.className;
    state.textContent = st.text;
    const actions = [button('详情', () => openDevice(device.id), page.busy)];
    if (device.suggest.length === 1) {
      actions.push(button('合并', () => apply('device/merge', { id: device.suggest[0], from: device.id },
        `把“${device.label}”并入“${labelOf(device.suggest[0])}”？`), page.busy));
    }
    const where = (device.ips.join('、') || '—') + (t && t.v6 ? ` +${t.v6} 个 IPv6` : '');
    const rates = t && t.meter ? [FORMATS.bps(t.up), FORMATS.bps(t.down)] : [t ? FORMATS.bps(t.bps) : '—', t ? String(t.sessions) : '—'];
    row(tr, [deviceCell(device), state, where, ...rates, ago(device.last_seen)], actions);
  });
  if (metering()) {
    const tr = page.traffic;
    $('lan-nat-note').textContent = !tr ? '正在读取计数…' : tr.error ? '读取计数失败：' + tr.error
      : !tr.ready ? '速率要再读一次计数才有，稍等 10 秒。' : '';
  } else {
    $('lan-nat-note').textContent = page.nat ? (page.nat.rates_ready ? '' : '速率要再读一次才有，稍等几秒。')
      : page.natError ? '读取 NAT 会话失败：' + page.natError : '正在读取 NAT 会话…';
  }
}

function renderHosts() {
  const s = page.state;
  const owner = mac => s.devices.find(d => d.macs.some(m => m.mac === mac));
  $('lan-hosts-empty').hidden = s.hosts.length > 0;
  fillBody($('lan-hosts').tBodies[0], s.hosts.length, (tr, i) => {
    const h = s.hosts[i];
    const device = owner(h.mac);
    row(tr, [h.mac, h.ip, h.name || '—', device ? device.label : '—'], [
      device ? button('设备', () => openDevice(device.id), page.busy) : null,
      button('删除', () => apply('host/delete', { mac: h.mac }, `删除 ${h.mac} → ${h.ip} 的静态分配？`), page.busy),
    ]);
  });
  $('lan-other-hosts').hidden = !s.other_hosts.length;
  $('lan-other-hosts').textContent = s.other_hosts.length
    ? `另有 ${s.other_hosts.length} 条其他写法的静态分配，这里只显示，不修改：${s.other_hosts.join('；')}` : '';
  for (const id of ['lan-range-apply', 'lan-host-add']) $(id).disabled = page.busy;
}

function render() {
  if (!page.state) return;
  renderMeter();
  renderSummary();
  renderDevices();
  renderHosts();
  if ($('lan-device-dialog').open) renderDevice();
}

/* ---------- one device ---------- */

/* A DHCP host name from a free-form one: letters, digits and hyphens. */
function hostName(text) {
  return (text || '').normalize('NFKD').replace(/[^A-Za-z0-9-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 63);
}

/* ---------- a device's traffic history (the meter's, kept by vpp-monitor per MAC) ---------- */

async function loadChart() {
  const device = byID(page.device);
  const box = $('lan-device-traffic-box');
  box.hidden = !device || !metering();
  if (box.hidden) return;
  const macs = device.macs.map(m => m.mac).slice(0, 32);
  const params = new URLSearchParams({ range: page.range });
  for (const mac of macs) params.append('key', 'lan/up/' + mac), params.append('key', 'lan/down/' + mac);
  let result;
  try {
    result = await fetchJSON('api/series?' + params);
  } catch (err) {
    $('lan-device-traffic-note').textContent = '读取历史失败：' + err.message;
    return;
  }
  const times = Array.from({ length: result.count }, (_, i) => result.start + i * result.step);
  const sum = dir => times.map((_, i) => {
    let total = null;
    for (const mac of macs) {
      const v = (result.values[`lan/${dir}/${mac}`] || [])[i];
      if (v != null) total = (total || 0) + v;
    }
    return total;
  });
  const up = sum('up'), down = sum('down');
  $('lan-device-traffic-note').textContent = up.some(v => v != null) || down.some(v => v != null)
    ? '每个点是这段时间的平均速率，短时的峰值会被抹平。历史只在监控进程的内存里，进程或主机重启后清空。'
    : '还没有记录：开启统计后，每 10 秒记录一次。';
  const host = $('lan-device-plot');
  if (!page.plot) {
    const axis = { stroke: token('--muted'), grid: { stroke: token('--grid'), width: 1 }, ticks: { stroke: token('--axis'), width: 1, size: 4 }, font: '11px system-ui, sans-serif' };
    const value = (u, v, s, idx) => FORMATS.bps(idx == null ? null : v);
    page.plot = new uPlot({
      width: host.clientWidth || 600, height: 200,
      cursor: { y: false, points: { size: 8 }, drag: { x: false, y: false } },
      scales: { y: { range: (u, min, max) => [0, max > 0 ? max * 1.1 : 1] } },
      axes: [axis, { ...axis, size: 76, values: (u, splits) => splits.map(FORMATS.bps) }],
      series: [
        { label: '时间', value: (u, v) => v == null ? '—' : new Date(v * 1000).toLocaleString('zh-CN', { hour12: false }) },
        { label: '下载', stroke: color(0), width: 2, points: { show: false }, value },
        { label: '上传', stroke: color(1), width: 2, points: { show: false }, value },
      ],
    }, [times, down, up], host);
  } else {
    page.plot.setData([times, down, up]);
  }
}

function renderRanges() {
  $('lan-device-ranges').replaceChildren(...RANGES.map(([seconds, label]) => {
    const b = document.createElement('button');
    b.textContent = label;
    b.setAttribute('aria-pressed', String(page.range === seconds));
    b.onclick = () => { page.range = seconds; renderRanges(); loadChart(); };
    return b;
  }));
}

function openDevice(id) {
  page.device = id;
  const device = byID(id);
  if (!device) return;
  $('lan-device-error').textContent = '';
  $('lan-device-name').value = device.name;
  const mac = device.macs.find(m => m.active) || device.macs[0];
  $('lan-device-static-ip').value = device.static[0]?.ip || mac?.ip || '';
  $('lan-device-static-name').value = device.static[0]?.name || hostName(device.name) || hostName(mac?.hostname);
  renderDevice();
  /* The MAC the address belongs to, not just the first one. */
  const chosen = device.static[0]?.mac || mac?.mac;
  if (chosen) $('lan-device-static-mac').value = chosen;
  $('lan-device-dialog').showModal();
  renderRanges();
  loadChart();
  clearInterval(page.plotTimer);
  page.plotTimer = setInterval(() => { if ($('lan-device-dialog').open && !document.hidden) loadChart(); }, 30000);
}

function renderDevice() {
  const device = byID(page.device);
  if (!device) { $('lan-device-dialog').close(); return; }
  $('lan-device-title').textContent = device.label;
  $('lan-device-name-apply').disabled = page.busy;
  fillBody($('lan-device-macs').tBodies[0], device.macs.length, (tr, i) => {
    const m = device.macs[i];
    const kind = [m.random ? '随机' : '固定', m.auto ? '自动归入' : ''].filter(Boolean).join('，');
    const where = m.ip ? m.ip + (m.active ? (m.expires ? `（租约到 ${clock(m.expires)}）` : '（永久租约）') : '（租约已过期）') : '—';
    row(tr, [m.mac, kind, m.hostname || '—', where, m.vendor || '—', ago(m.last_seen)], [
      device.macs.length > 1 ? button('拆出', () => apply('device/split', { mac: m.mac }, `把 ${m.mac} 拆成单独的设备？`), page.busy) : null,
    ]);
  });
  const suggest = device.suggest.filter(byID);
  $('lan-device-suggest-box').hidden = !suggest.length;
  $('lan-device-suggest-note').textContent = suggest.length
    ? '主机名和请求特征都一样，但有几台设备用这个主机名，所以没有自动合并。是同一台就合并，不是就忽略。' : '';
  $('lan-device-suggest').replaceChildren(...suggest.map(id => button(`并入“${labelOf(id)}”`, async () => {
    if (await apply('device/merge', { id, from: device.id }, `把“${device.label}”并入“${labelOf(id)}”？`)) {
      page.device = id;
      render();
    }
  }, page.busy)), button('不是同一台', () => apply('device/dismiss', { id: device.id }), page.busy));
  const macs = $('lan-device-static-mac');
  const keep = macs.value;
  macs.replaceChildren(...device.macs.map(m => new Option(m.mac + (m.random ? '（随机）' : ''), m.mac)));
  if (device.macs.some(m => m.mac === keep)) macs.value = keep;
  const randomOnly = device.macs.every(m => m.random) && device.macs.length > 1;
  $('lan-device-static-note').textContent = (device.static.length
    ? `已有：${device.static.map(h => `${h.mac} → ${h.ip}`).join('、')}。同一个 MAC 再设一次会替换。` : '静态分配按 MAC 地址生效。')
    + (randomOnly ? ' 这台设备换过随机 MAC，静态分配只对选中的那个 MAC 有效；要长期有效，在设备上把这个网络设为固定的私有地址。' : '');
  $('lan-device-static-apply').disabled = page.busy;
  const others = page.state.devices.filter(d => d.id !== device.id);
  const from = $('lan-device-merge-from');
  const keepFrom = from.value;
  from.replaceChildren(...others.map(d => new Option(d.label + (d.ips.length ? `（${d.ips.join('、')}）` : ''), d.id)));
  if (others.some(d => d.id === keepFrom)) from.value = keepFrom;
  $('lan-device-merge-apply').disabled = page.busy || !others.length;
  $('lan-device-forget').disabled = page.busy || device.static.length > 0 || device.macs.some(m => m.active);
}

export function start() {
  $('lan-device-dialog').addEventListener('close', () => {
    clearInterval(page.plotTimer);
    if (page.plot) { page.plot.destroy(); page.plot = null; }
  });
  $('lan-meter-toggle').onclick = async () => {
    const on = !metering();
    const text = on
      ? '开启按设备统计流量？\n\n在局域网网关接口上挂两张计数用的 ACL（放行所有，不拦截），每个包多一次 ACL 查找。'
      : '关闭按设备统计流量？\n\n计数 ACL 撤下，设备的流量历史不再记录。';
    if (page.busy || !confirm(text)) return;
    page.busy = true;
    message('正在应用…');
    try {
      page.meter = await postJSON('api/interfaces/meter', { enable: on });
      message('');
    } catch (err) {
      message(err.message, true);
      page.meter = await fetchJSON('api/interfaces/meter').catch(() => page.meter);
    } finally {
      page.busy = false;
      page.traffic = null;
      render();
      refreshTraffic();
    }
  };
  $('lan-range-apply').onclick = () => {
    const body = { start: $('lan-range-start').value.trim(), end: $('lan-range-end').value.trim(), lease: $('lan-range-lease').value.trim() };
    apply('range', body, `把地址池改成 ${body.start} – ${body.end}，租期 ${body.lease || page.state.range.lease}？\n\ndnsmasq 会重启，DHCP 和 DNS 中断约 1 秒。`);
  };
  $('lan-host-add').onclick = () => {
    const body = { mac: $('lan-host-mac').value.trim(), ip: $('lan-host-ip').value.trim(), name: $('lan-host-name').value.trim() };
    apply('host', body, `把 ${body.ip} 固定分配给 ${body.mac}？`).then(done => {
      if (done) for (const id of ['lan-host-mac', 'lan-host-ip', 'lan-host-name']) $(id).value = '';
    });
  };
  $('lan-device-name-apply').onclick = () => apply('device/name', { id: page.device, name: $('lan-device-name').value.trim() });
  $('lan-device-static-apply').onclick = () => {
    const body = { mac: $('lan-device-static-mac').value, ip: $('lan-device-static-ip').value.trim(), name: $('lan-device-static-name').value.trim() };
    apply('host', body, `把 ${body.ip} 固定分配给 ${body.mac}？`, '已保存。设备下次续租或重新连接时拿到这个地址。');
  };
  $('lan-device-merge-apply').onclick = () => {
    const from = $('lan-device-merge-from').value;
    apply('device/merge', { id: page.device, from }, `把“${labelOf(from)}”的 MAC 地址并入“${labelOf(page.device)}”？`);
  };
  $('lan-device-forget').onclick = async () => {
    if (await apply('device/forget', { id: page.device }, `删除设备“${labelOf(page.device)}”和它的记录？`)) $('lan-device-dialog').close();
  };
}

export function show() {
  load().then(refreshTraffic);
  clearInterval(page.timer);
  page.timer = setInterval(() => {
    if (document.hidden) return;
    refreshTraffic();
    /* Do not refresh the forms out from under the typing. */
    if (page.busy || document.activeElement?.closest?.('#page-lan .form-row')) return;
    load();
  }, 5000);
}

export function hide() {
  clearInterval(page.timer);
}
