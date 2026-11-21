/* The overview: current values, history charts and tables. */
import { $, si, bytes, FORMATS, duration, read, write, color, token, fetchJSON, setCells, fillBody, linkCell } from '../lib.js';
import { openNAT } from './exits.js';

const RANGES = [
  [300, '5 分钟', 2000], [900, '15 分钟', 2000], [3600, '1 小时', 10000],
  [10800, '3 小时', 10000], [86400, '24 小时', 30000], [604800, '7 天', 60000],
];

const view = {
  range: Number(read('vpp-monitor.range')) || 900,
  iface: read('vpp-monitor.iface'),
  error: null,
  status: null,
  charts: new Map(),
};

/* VPP names a TAP only by its id; the Linux name is what people recognise. */
const displayName = row => row.label || row.name;
const visibleInterfaces = status => (status.interfaces || []).filter(row => !row.hidden);

/* Each chart has one axis and one unit. A series keeps its slot for its whole life, so
   colour follows the thing measured rather than its position in a list. */
function definitions(status) {
  const defs = [];
  const iface = view.iface;
  if (iface) {
    const of = suffix => `if/${iface}/${suffix}`;
    const shown = (status.interfaces || []).find(r => r.name === iface);
    const label = shown ? displayName(shown) : iface;
    defs.push({ id: 'bps', title: `${label} 带宽`, unit: 'bps', group: 'fast',
      series: [{ key: of('rx_bps'), label: '接收', slot: 0 }, { key: of('tx_bps'), label: '发送', slot: 1 }] });
    defs.push({ id: 'pps', title: `${label} 包速率`, unit: 'pps', group: 'fast',
      series: [{ key: of('rx_pps'), label: '接收', slot: 0 }, { key: of('tx_pps'), label: '发送', slot: 1 }] });
    defs.push({ id: 'loss', title: `${label} 丢弃与错误`, unit: 'rate', group: 'fast', series: [
      { key: of('drops'), label: '丢弃', slot: 0 }, { key: of('rx_miss'), label: 'rx-miss', slot: 1 },
      { key: of('rx_no_buf'), label: 'rx-no-buf', slot: 2 }, { key: of('rx_error'), label: 'rx-error', slot: 3 },
      { key: of('tx_error'), label: 'tx-error', slot: 4 } ] });
  }
  const workers = (status.worker_rates || []).slice(0, 8);
  if (workers.length) defs.push({ id: 'workers', title: '各线程向量率', unit: 'count', group: 'slow',
    series: workers.map((_, i) => ({ key: `sys/worker/${i}/vector_rate`, label: i === 0 && workers.length > 1 ? '主线程' : `线程 ${i}`, slot: i })) });
  defs.push({ id: 'input', title: '输入速率', unit: 'pps', group: 'slow', series: [{ key: 'sys/input_rate', label: '输入', slot: 0 }] });
  if ((status.buffers || []).length) defs.push({ id: 'buffers', title: 'Buffer 使用量', unit: 'count', group: 'slow',
    series: status.buffers.slice(0, 8).map((b, i) => ({ key: `buf/${b.pool}/used`, label: b.pool, slot: i })) });
  if ((status.heaps || []).length) defs.push({ id: 'heaps', title: 'VPP 内存堆', unit: 'bytes', group: 'slow',
    series: status.heaps.slice(0, 8).map((h, i) => ({ key: `mem/${h.name}/used`, label: h.name, slot: i })) });
  if ((status.gauges || []).length) defs.push({ id: 'nat', title: 'NAT 用户与会话', unit: 'count', group: 'slow',
    series: status.gauges.slice(0, 8).map((g, i) => ({ key: g.key, label: g.name, slot: i })) });
  if (view.error) defs.push({ id: 'error', title: `计数器：${view.error.node} / ${view.error.reason}`, unit: 'rate', group: 'slow',
    series: [{ key: view.error.key, label: '速率', slot: 0 }] });

  const host = status.host || {};
  const cores = host.cores || [];
  if (cores.length) defs.push({ id: 'host-cpu', host: true, title: cores.length > 8 ? '各核心 CPU 使用率（前 8 个）' : '各核心 CPU 使用率', unit: 'percent', scale: 'percent', group: 'slow',
    series: cores.slice(0, 8).map((core, i) => ({ key: `host/cpu/${core.name}/busy`, label: core.name, slot: i })) });
  if (host.mem_total) defs.push({ id: 'host-mem', host: true, title: '内存使用', unit: 'bytes', group: 'slow',
    series: [{ key: 'host/mem/used', label: '内存', slot: 0 }, ...(host.swap_total ? [{ key: 'host/swap/used', label: 'Swap', slot: 1 }] : [])] });
  if ((host.temps || []).length) defs.push({ id: 'host-temp', host: true, title: '温度', unit: 'celsius', scale: 'fit', group: 'slow',
    series: host.temps.slice(0, 8).map((temp, i) => ({ key: temp.key, label: temp.name, slot: i })) });
  return defs;
}

const SCALES = {
  zero: (u, min, max) => [0, max > 0 ? max * 1.1 : 1],
  percent: () => [0, 100],
  fit: (u, min, max) => min == null ? [0, 100] : [Math.floor(min - 3), Math.ceil(max + 3)],
};

function card(def) {
  const box = document.createElement('div');
  box.className = 'card';
  const title = document.createElement('h2');
  const plot = document.createElement('div');
  plot.className = 'plot';
  box.append(title, plot);
  return { box, title, plot };
}

/* With no cursor on the chart, the legend shows the newest value. */
function latest(values) {
  for (let i = (values ? values.length : 0) - 1; i >= 0; i--) if (values[i] != null) return values[i];
  return null;
}

function makePlot(def, host, width) {
  const format = FORMATS[def.unit];
  const axis = {
    stroke: token('--muted'),
    grid: { stroke: token('--grid'), width: 1 },
    ticks: { stroke: token('--axis'), width: 1, size: 4 },
    font: '11px system-ui, sans-serif',
  };
  return new uPlot({
    width, height: 200,
    cursor: { y: false, points: { size: 8 }, drag: { x: false, y: false } },
    scales: { y: { range: SCALES[def.scale || 'zero'] } },
    axes: [axis, { ...axis, size: 76, values: (u, splits) => splits.map(format) }],
    series: [
      { value: (u, v, s, idx) => idx == null ? '最新' : new Date(v * 1000).toLocaleString('zh-CN', { hour12: false }), label: '时间' },
      ...def.series.map(s => ({ label: s.label, stroke: color(s.slot), width: 2, points: { show: false },
        value: (u, v, series, idx) => format(idx == null ? latest(u.data[series]) : v) })),
    ],
  }, [[], ...def.series.map(() => [])], host);
}

function syncCharts(defs) {
  const live = new Set();
  for (const def of defs) {
    const container = $(def.host ? 'host-charts' : 'charts');
    live.add(def.id);
    const signature = def.series.map(s => s.key + '|' + s.label).join(';');
    let chart = view.charts.get(def.id);
    if (chart && chart.signature !== signature) {
      chart.plot.destroy();
      chart.parts.plot.textContent = '';
      chart.plot = null;
      chart.signature = signature;
    }
    if (!chart) {
      const parts = card(def);
      container.append(parts.box);
      chart = { parts, signature, plot: null };
      view.charts.set(def.id, chart);
      new ResizeObserver(() => {
        if (chart.plot) chart.plot.setSize({ width: chart.parts.plot.clientWidth, height: 200 });
      }).observe(parts.plot);
    }
    chart.parts.title.textContent = def.title;
    if (!chart.plot) chart.plot = makePlot(def, chart.parts.plot, chart.parts.plot.clientWidth || 400);
    chart.def = def;
  }
  for (const [id, chart] of view.charts) {
    if (!live.has(id)) {
      chart.plot.destroy();
      chart.parts.box.remove();
      view.charts.delete(id);
    }
  }
}

async function loadGroup(defs, group) {
  const members = defs.filter(d => d.group === group);
  const keys = members.flatMap(d => d.series.map(s => s.key));
  if (!keys.length) return;
  const params = new URLSearchParams({ range: view.range });
  keys.forEach(k => params.append('key', k));
  const result = await fetchJSON('api/series?' + params);
  const times = Array.from({ length: result.count }, (_, i) => result.start + i * result.step);
  for (const def of members) {
    const chart = view.charts.get(def.id);
    if (!chart || !chart.plot) continue;
    chart.plot.setData([times, ...def.series.map(s => result.values[s.key] || times.map(() => null))]);
  }
}

function renderTiles(status) {
  const tiles = [];
  if (status.vpp_uptime_seconds) {
    const started = new Date((status.vpp_runs || [{}])[0].started * 1000);
    tiles.push(['VPP 运行时间', duration(status.vpp_uptime_seconds), `${status.vpp_restarts || 0} 次重启` + (isNaN(started) ? '' : ` · 自 ${dateTime(started)} 起`)]);
  }
  tiles.push(['向量率', si(status.vector_rate), '全局每次调度的向量数']);
  tiles.push(['输入速率', FORMATS.pps(status.input_rate), `${status.workers || 0} 个 worker`]);
  const drops = (status.interfaces || []).reduce((sum, row) => sum + row.drops, 0);
  tiles.push(['接口丢弃', FORMATS.rate(drops), '所有接口合计']);
  const buffers = status.buffers || [];
  if (buffers.length) {
    const used = buffers.reduce((sum, b) => sum + b.used, 0);
    const total = buffers.reduce((sum, b) => sum + b.used + b.available + b.cached, 0);
    tiles.push(['Buffer 使用', total ? (100 * used / total).toFixed(1) + '%' : '—', `${si(used)} / ${si(total)}`]);
  }
  const heap = (status.heaps || []).find(h => h.name === 'main heap');
  if (heap) tiles.push(['主堆', bytes(heap.used), `共 ${bytes(heap.total)}`]);
  const sessions = (status.gauges || []).find(g => g.key.endsWith('total-sessions'));
  if (sessions) {
    const canOpen = sessions.key.startsWith('nat-ei');
    tiles.push(['NAT 会话', si(sessions.value), canOpen ? '点击查看出口连接' : sessions.name, canOpen ? openNAT : null]);
  }
  setTiles($('tiles'), tiles);

  const info = status.host || {};
  const hostTiles = [];
  const cores = info.cores || [];
  if (cores.length) {
    const mhz = Math.max(...cores.map(core => core.mhz));
    hostTiles.push(['CPU 使用率', FORMATS.percent(info.cpu), `${cores.length} 核` + (mhz ? ` · ${Math.round(mhz)} MHz` : '')]);
  }
  if (info.mem_total) hostTiles.push(['内存', FORMATS.percent(100 * info.mem_used / info.mem_total), `${bytes(info.mem_used)} / ${bytes(info.mem_total)}`]);
  if ((info.temps || []).length) {
    const hottest = info.temps.reduce((a, b) => b.celsius > a.celsius ? b : a);
    hostTiles.push(['最高温度', FORMATS.celsius(hottest.celsius), hottest.name]);
  }
  if (info.disk_total) hostTiles.push(['根分区', FORMATS.percent(100 * info.disk_used / info.disk_total), `${bytes(info.disk_used)} / ${bytes(info.disk_total)}`]);
  if (info.uptime_seconds) hostTiles.push(['运行时间', duration(info.uptime_seconds), '主机开机至今']);
  setTiles($('host-tiles'), hostTiles);
}

function setTiles(host, tiles) {
  while (host.children.length < tiles.length) {
    const tile = document.createElement('div');
    tile.className = 'tile';
    tile.append(document.createElement('span'), document.createElement('strong'), document.createElement('small'));
    host.append(tile);
  }
  while (host.children.length > tiles.length) host.lastChild.remove();
  tiles.forEach((tile, i) => {
    const element = host.children[i];
    tile.slice(0, 3).forEach((text, j) => { element.children[j].textContent = text; });
    const open = tile[3] || null;
    element.classList.toggle('clickable', !!open);
    element.onclick = open;
    element.onkeydown = open && (event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); open(); } });
    if (open) { element.tabIndex = 0; element.setAttribute('role', 'button'); }
    else { element.removeAttribute('tabindex'); element.removeAttribute('role'); }
  });
}

function renderTables(status) {
  const interfaces = visibleInterfaces(status);
  fillBody($('ifaces').tBodies[0], interfaces.length, (row, i) => {
    const r = interfaces[i];
    row.className = r.name === view.iface ? 'selected' : '';
    linkCell(row, displayName(r), () => selectInterface(r.name));
    row.children[0].title = r.label ? r.name : '';
    const cells = [FORMATS.bps(r.rx_bps), FORMATS.bps(r.tx_bps), si(r.rx_pps), si(r.tx_pps), si(r.drops), si(r.rx_miss), si(r.rx_no_buf), si(r.rx_error + r.tx_error)];
    while (row.children.length < cells.length + 1) row.append(document.createElement('td'));
    cells.forEach((text, j) => { row.children[j + 1].textContent = text; });
  });

  const counters = status.errors || [];
  const attention = counters.filter(r => !r.normal);
  const normal = counters.filter(r => r.normal);
  $('errors-empty').hidden = attention.length > 0;
  $('errors').hidden = attention.length === 0;
  $('normal-box').hidden = normal.length === 0;
  $('normal-count').textContent = normal.length;
  renderCounters($('errors'), attention);
  renderCounters($('normal'), normal);

  const nodes = status.nodes || [];
  $('nodes-off').hidden = status.nodes_enabled;
  $('nodes').hidden = !status.nodes_enabled;
  fillBody($('nodes').tBodies[0], nodes.length, (row, i) => {
    const r = nodes[i];
    setCells(row, [r.name, si(r.vectors_per_sec), si(r.calls_per_sec), r.vectors_per_call.toFixed(1), si(r.clocks_per_vector)]);
  });
}

function dateTime(date) {
  return date.toLocaleString('zh-CN', { hour12: false, month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
}

function renderRuns(status) {
  const runs = status.vpp_runs || [];
  $('vpp-runs-empty').hidden = runs.length > 0;
  fillBody($('vpp-runs').tBodies[0], runs.length, (row, i) => {
    const run = runs[i];
    const isOldest = i === runs.length - 1;
    setCells(row, [
      i === 0 ? '当前' : String(runs.length - i),
      dateTime(new Date(run.started * 1000)),
      i === 0 && status.vpp_uptime_seconds ? duration(status.vpp_uptime_seconds) : i > 0 ? duration(runs[i - 1].previous_seconds) : '—',
      isOldest ? '首次记录' : '重启',
    ]);
  });
}

function renderCounters(table, rows) {
  fillBody(table.tBodies[0], rows.length, (row, i) => {
    const r = rows[i];
    row.className = view.error && view.error.key === r.key && r.key ? 'selected' : '';
    if (r.key) {
      linkCell(row, r.node, () => { view.error = r; refresh(); });
    } else {
      row.textContent = '';
      row.append(document.createElement('td'));
      row.firstChild.textContent = r.node;
    }
    while (row.children.length < 4) row.append(document.createElement('td'));
    row.children[1].className = 'text';
    row.children[1].textContent = r.reason;
    row.children[2].textContent = si(r.rate);
    row.children[3].textContent = si(r.total);
  });
}

function renderState(status) {
  const labels = { up: ['●', 'VPP 运行中'], stalled: ['▲', 'VPP 无响应'], down: ['✕', 'VPP 未连接'] };
  const [icon, text] = labels[status.state] || labels.down;
  const host = $('state');
  host.dataset.state = status.state;
  host.children[0].textContent = icon;
  host.children[1].textContent = text;
  host.children[2].textContent = status.state === 'up' ? '' : status.detail;
}

function renderInterfaces(status) {
  const interfaces = visibleInterfaces(status);
  const names = interfaces.map(r => r.name);
  if (!names.includes(view.iface) && names.length) {
    const busiest = [...interfaces].sort((a, b) => (b.rx_bps + b.tx_bps) - (a.rx_bps + a.tx_bps))[0];
    view.iface = busiest.name;
  }
  const select = $('iface');
  const shown = interfaces.map(displayName);
  if ([...select.options].map(o => o.value + '|' + o.textContent).join('\n') !== names.map((name, i) => name + '|' + shown[i]).join('\n')) {
    select.textContent = '';
    names.forEach((name, i) => {
      const option = document.createElement('option');
      option.value = name;
      option.textContent = shown[i];
      select.append(option);
    });
  }
  if (view.iface) select.value = view.iface;
}

function selectInterface(name) {
  view.iface = name;
  write('vpp-monitor.iface', name);
  refresh();
}

function renderFooter(status) {
  $('footer').textContent = `接口每 ${status.fast_seconds} 秒、其余指标每 ${status.slow_seconds} 秒采样。历史只保存在内存里，监控进程重启后清空，当前占用 ${bytes(status.history_bytes)}（${status.series_count} 条序列）。最近一次读取 ${(status.read_micros / 1000).toFixed(1)} ms。`;
}

let refreshing = false, again = false;
async function refresh() {
  if (refreshing) { again = true; return; }
  refreshing = true;
  try {
    const status = await fetchJSON('api/status');
    view.status = status;
    renderState(status);
    renderInterfaces(status);
    renderTiles(status);
    renderTables(status);
    renderRuns(status);
    renderFooter(status);
    $('open-flows').hidden = !(status.gauges || []).some(g => g.key.startsWith('nat-ei'));
    const defs = definitions(status);
    syncCharts(defs);
    await Promise.all([loadGroup(defs, 'fast'), loadGroup(defs, 'slow')]);
  } catch (err) {
    const host = $('state');
    host.dataset.state = 'down';
    host.children[0].textContent = '✕';
    host.children[1].textContent = '监控进程不可达';
    host.children[2].textContent = err.message;
  } finally {
    refreshing = false;
    $('charts').classList.remove('loading');
    if (again) { again = false; refresh(); }
  }
}

function renderRanges() {
  const host = $('ranges');
  host.textContent = '';
  for (const [seconds, label] of RANGES) {
    const button = document.createElement('button');
    button.textContent = label;
    button.setAttribute('aria-pressed', seconds === view.range);
    button.onclick = () => {
      view.range = seconds;
      write('vpp-monitor.range', seconds);
      renderRanges();
      $('charts').classList.add('loading');
      schedule();
      refresh();
    };
    host.append(button);
  }
}

let timer = 0;
function schedule() {
  clearInterval(timer);
  const entry = RANGES.find(r => r[0] === view.range) || RANGES[1];
  timer = setInterval(() => { if (!document.hidden) refresh(); }, entry[2]);
}

function rebuildCharts() {
  for (const chart of view.charts.values()) {
    chart.plot.destroy();
    chart.parts.box.remove();
  }
  view.charts.clear();
  refresh();
}

export function start() {
  if (!RANGES.some(r => r[0] === view.range)) view.range = 900;
  $('iface').onchange = event => selectInterface(event.target.value);
  $('open-flows').onclick = openNAT;
  document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
  matchMedia('(prefers-color-scheme: dark)').addEventListener('change', rebuildCharts);
  renderRanges();
  schedule();
  refresh();
}
