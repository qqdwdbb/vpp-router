/* System: how VPP receives and on which CPUs it runs, PCI cards added to VPP through DPDK, the
   CPUs' governors, and NAT44's mode, timeouts and table size. vpp-system makes the changes. RX
   settings, governors and timeouts take effect at once; the thread layout, a new card and the
   NAT table restart VPP and are undone unless confirmed in time. */
import { $, fetchJSON, postJSON, fillBody } from '../lib.js';

const API = 'api/system';
const page = { state: null, timer: 0, tick: 0, busy: false, deadline: 0, formsFilled: false };
const MODES = { polling: '轮询', interrupt: '中断', adaptive: '自适应' };
const OUTCOMES = { confirmed: '已保留', 'rolled-back': '已恢复', 'rollback-failed': '恢复失败' };
const POLICIES = { '': '默认（other）', other: 'other：普通分时', batch: 'batch：批处理', idle: 'idle：最低', fifo: 'fifo：实时，先进先出', rr: 'rr：实时，时间片轮转' };

function message(text, isError) {
  $('sys-message').textContent = text || '';
  $('sys-message').classList.toggle('error', !!isError);
}

async function load() {
  try {
    page.state = await fetchJSON(API);
    $('sys-content').hidden = false;
    $('sys-unavailable').hidden = true;
  } catch (err) {
    $('sys-content').hidden = true;
    $('sys-unavailable').hidden = false;
    $('sys-unavailable').textContent = '无法读取系统设置：' + err.message;
    return;
  }
  if (page.state.pending) page.deadline = Date.now() + page.state.seconds_remaining * 1000;
  render();
}

/* Applies one change. restart says it restarts VPP, which takes a while. */
async function apply(path, body, description, restart) {
  if (page.busy) return false;
  if (description) {
    const note = restart
      ? '\n\n要立即重启 VPP，期间所有流量中断（通常十几秒），面板会暂时断开。重启后 60 秒内不确认就恢复原来的设置并再次重启。'
      : '\n\n立即生效。';
    if (!confirm(description + note)) return false;
  }
  page.busy = true;
  for (const element of document.querySelectorAll('#page-system select[data-dirty], #page-system input[data-dirty]')) delete element.dataset.dirty;
  message(restart ? '正在重启 VPP，等它按新设置运行…' : '正在应用…');
  render();
  try {
    page.state = await postJSON(`${API}/${path}`, body);
    if (page.state.pending) page.deadline = Date.now() + page.state.seconds_remaining * 1000;
    message(restart ? 'VPP 已按新设置运行，确认后保留。' + (path === 'nics/add' ? '新网卡在接口页配置。' : '') : '');
    page.formsFilled = false;
    return true;
  } catch (err) {
    message(err.message, true);
    page.formsFilled = false;
    load();
    return false;
  } finally {
    page.busy = false;
    render();
  }
}

function button(text, onClick, disabled, strong) {
  const element = document.createElement('button');
  element.className = strong ? 'close strong' : 'close';
  element.textContent = text;
  element.onclick = onClick;
  element.disabled = !!disabled;
  return element;
}

/* A select that the refresh keeps once the user has changed it; a row's button reads it from
   the row, so it gets the kept one. */
function select(options, value) {
  const element = document.createElement('select');
  element.replaceChildren(...options.map(([v, text]) => new Option(text, v)));
  element.value = value;
  element.onchange = () => { element.dataset.dirty = '1'; };
  return element;
}

/* Value cells, then the given elements in the last cells. */
function row(tr, values, ...elements) {
  const count = values.length + elements.length;
  while (tr.children.length < count) tr.append(document.createElement('td'));
  while (tr.children.length > count) tr.lastChild.remove();
  values.forEach((value, i) => { if (tr.children[i].textContent !== value) tr.children[i].textContent = value; });
  elements.forEach((element, i) => {
    const cell = tr.children[values.length + i];
    /* Keep a select the user is changing or has changed. */
    const old = cell.firstChild;
    if (old === element) return;
    if (old && old.nodeName === 'SELECT' && element && element.nodeName === 'SELECT' && (old.dataset.dirty || cell.contains(document.activeElement))) return;
    cell.replaceChildren(...(element ? [element] : []));
  });
}

const threadName = index => index === 0 ? '主线程' : `worker ${index - 1}`;
const mhz = khz => khz ? (khz >= 1e6 ? (khz / 1e6).toFixed(2).replace(/\.?0+$/, '') + ' GHz' : Math.round(khz / 1000) + ' MHz') : '—';

function cpuLabel(cpu) {
  const s = page.state;
  const kinds = new Set(s.cpus.map(c => c.big));
  const kind = kinds.size > 1 ? (cpu.big ? '，大核' : '，小核') : '';
  return `CPU ${cpu.id}${kind}${cpu.max_khz ? '，' + mhz(cpu.max_khz) : ''}`;
}

function locked() {
  return page.busy || !!page.state.pending;
}

function renderPending() {
  const s = page.state;
  $('sys-pending').hidden = !s.pending;
  if (s.pending) {
    const seconds = Math.max(0, Math.ceil((page.deadline - Date.now()) / 1000));
    $('sys-pending-text').textContent = `${s.pending.description}。VPP 已按新设置重启，${seconds} 秒内未确认将恢复原来的设置并再次重启。`;
  }
  const last = s.last;
  $('sys-last').hidden = !last;
  if (last) {
    $('sys-last').textContent = `最近一次：${last.description}：${OUTCOMES[last.outcome] || last.outcome}${last.detail ? `（${last.detail}）` : ''}`;
    $('sys-last').classList.toggle('error', last.outcome === 'rollback-failed');
  }
}

function renderRx() {
  const s = page.state;
  const list = s.interfaces;
  $('sys-rx-empty').hidden = list.length > 0;
  fillBody($('sys-rx').tBodies[0], list.length, (tr, i) => {
    const iface = list[i];
    const modes = [...new Set(iface.queues.map(q => q.mode))];
    const current = modes.map(m => MODES[m] || m).join('、');
    const choice = select([['default', '缺省'], ...Object.entries(MODES)], iface.setting || 'default');
    const go = button('应用', () => {
      const mode = tr.querySelector('select').value;
      if (mode === (iface.setting || 'default')) return;
      apply('rx-mode', { interface: iface.name, mode }, mode === 'default'
        ? `${iface.name} 的收包方式改回缺省（安装器的设置）：现在的方式不变，下次 VPP 启动时生效`
        : `${iface.name} 改为${MODES[mode]}收包`);
    }, locked());
    row(tr, [iface.name, String(iface.queues.length), current], choice, go);
  });

  const threads = s.threads.live || [];
  const workers = threads.filter(t => t.index > 0 && t.type === 'workers');
  const queues = list.flatMap(iface => iface.queues.map(q => ({ name: iface.name, ...q })));
  $('sys-placement-help').textContent = workers.length
    ? '每个收包队列由一个线程处理。“VPP 分配”时 VPP 按队列依次分给 worker。修改立即生效，VPP 重启后自动恢复；worker 少了以后放不下的队列由 VPP 分配。'
    : 'VPP 只有主线程，所有队列都由它处理。在下面加 worker 后可以把队列分给不同的线程。';
  const options = [['-1', 'VPP 分配'], ...threads.filter(t => t.index === 0 || t.type === 'workers').map(t => [String(t.index), `${threadName(t.index)}${t.cpu >= 0 ? `（CPU ${t.cpu}）` : ''}`])];
  fillBody($('sys-placement').tBodies[0], queues.length, (tr, i) => {
    const q = queues[i];
    const setting = q.setting == null ? '-1' : String(q.setting);
    const choice = select(options, setting);
    const go = button('应用', () => {
      const value = tr.querySelector('select').value;
      if (value === setting) return;
      const thread = Number(value);
      apply('rx-placement', { interface: q.name, queue: q.queue, thread }, thread < 0
        ? `${q.name} 队列 ${q.queue} 交给 VPP 分配（现在的线程不变，下次 VPP 启动时生效）`
        : `${q.name} 队列 ${q.queue} 改由${threadName(thread)}处理`);
    }, locked() || workers.length === 0);
    row(tr, [q.name, String(q.queue), threadName(q.thread)], choice, go);
  });
}

function renderThreads() {
  const s = page.state;
  const t = s.threads;
  const live = t.live || [];
  fillBody($('sys-threads').tBodies[0], live.length, (tr, i) => {
    const th = live[i];
    const cpu = s.cpus.find(c => c.id === th.cpu);
    row(tr, [threadName(th.index), th.name + (th.type ? `（${th.type}）` : ''), th.cpu >= 0 ? (cpu ? cpuLabel(cpu) : `CPU ${th.cpu}`) : '未固定']);
  });
  const limit = t.max_workers;
  let help = `主线程处理控制面（CLI、API、DHCP 等），没有 worker 时也处理所有收包；worker 专门转发。轮询时每个线程占满它所在的 CPU。修改写入 VPP 的启动文件 ${s.start_conf}，要重启 VPP，60 秒内不确认就恢复。`;
  if (limit === 0) help += ' 这个平台只能单线程运行，不能加 worker。';
  else if (limit > 0) help += ` 这个平台最多 ${limit} 个 worker。`;
  if (t.error) help += ' 启动文件读取出错：' + t.error;
  $('sys-threads-help').textContent = help;

  $('thr-devices-wrap').hidden = !t.devices.length;
  fillBody($('thr-devices').tBodies[0], t.devices.length, (tr, i) => {
    const d = t.devices[i];
    let input = tr.querySelector('input');
    if (!input) {
      input = document.createElement('input');
      input.type = 'number';
      input.min = 1;
      input.dataset.address = d.address;
    }
    input.max = d.max_queues || 16;
    input.disabled = !d.editable || locked();
    if (!page.formsFilled) input.value = d.file_queues || d.default_queues || d.queues || 1;
    row(tr, [d.name || '—', d.address, d.queues ? String(d.queues) : '—', d.max_queues ? String(d.max_queues) : '—'], input);
  });

  if (!page.formsFilled && t.file) {
    const mainSelect = $('thr-main');
    mainSelect.replaceChildren(...s.cpus.map(c => new Option(cpuLabel(c), String(c.id))));
    const mainThread = live.find(th => th.index === 0);
    const main = t.file.main_core ?? (mainThread && mainThread.cpu >= 0 ? mainThread.cpu : s.cpus[0]?.id);
    mainSelect.value = String(main);
    const policy = $('thr-policy');
    policy.replaceChildren(...['', ...t.policies].map(p => new Option(POLICIES[p] || p, p)));
    policy.value = t.file.scheduler_policy || '';
    $('thr-priority').value = t.file.scheduler_priority ?? '';
    const current = t.file.workers?.length ? t.file.workers : live.filter(th => th.type === 'workers' && th.cpu >= 0).map(th => th.cpu);
    $('thr-workers').replaceChildren(document.createTextNode('worker 所在的 CPU：'), ...s.cpus.map(c => {
      const label = document.createElement('label');
      const box = document.createElement('input');
      box.type = 'checkbox';
      box.value = String(c.id);
      box.checked = current.includes(c.id);
      box.onchange = updateThreadForm;
      label.append(box, ' ' + cpuLabel(c));
      return label;
    }));
  }
  updateThreadForm();
}

function threadForm() {
  const main = Number($('thr-main').value);
  const workers = [...$('thr-workers').querySelectorAll('input:checked')].map(box => Number(box.value)).filter(c => c !== main);
  const policy = $('thr-policy').value;
  const priorityText = $('thr-priority').value.trim();
  const rx_queues = {};
  for (const input of $('thr-devices').querySelectorAll('input')) {
    if (!input.disabled) rx_queues[input.dataset.address] = Number(input.value);
  }
  const body = { main_core: main, workers, scheduler_policy: policy, rx_queues };
  if ((policy === 'fifo' || policy === 'rr') && priorityText) body.scheduler_priority = Number(priorityText);
  return body;
}

function updateThreadForm() {
  const s = page.state;
  if (!s) return;
  const main = Number($('thr-main').value);
  const limit = s.threads.max_workers;
  for (const box of $('thr-workers').querySelectorAll('input')) {
    const isMain = Number(box.value) === main;
    if (isMain) box.checked = false;
    box.disabled = isMain || locked() || limit === 0;
  }
  const realtime = ['fifo', 'rr'].includes($('thr-policy').value);
  $('thr-priority').disabled = !realtime || locked();
  for (const id of ['thr-main', 'thr-policy']) $(id).disabled = locked();
  const body = threadForm();
  const tooMany = limit >= 0 && body.workers.length > limit;
  $('thr-summary').textContent = `主线程 CPU ${body.main_core}，${body.workers.length ? `${body.workers.length} 个 worker` : '没有 worker'}` +
    (tooMany ? `，超过平台上限 ${limit}` : '') +
    (body.workers.length > 1 ? '。收包队列数一般等于 worker 数，流量才能分到每个 worker。' : '');
  $('thr-apply').disabled = locked() || !s.can_restart || !s.threads.file || tooMany;
  $('thr-apply').title = s.can_restart ? '' : 'vpp-system 没有设置 --vpp-unit，不能重启 VPP';
}

function applyThreads() {
  const body = threadForm();
  const parts = [`主线程放在 CPU ${body.main_core}`, body.workers.length ? `worker 放在 CPU ${body.workers.join('、')}` : '不用 worker'];
  if (body.scheduler_policy) parts.push(`调度策略 ${body.scheduler_policy}${body.scheduler_priority ? `，优先级 ${body.scheduler_priority}` : ''}`);
  for (const [address, n] of Object.entries(body.rx_queues)) {
    const d = page.state.threads.devices.find(x => x.address === address);
    if (d && n !== (d.file_queues || d.default_queues || d.queues || 1)) parts.push(`${d.name || address} ${n} 个收包队列`);
  }
  apply('threads', body, parts.join('，'), true);
}

function renderNICs() {
  const s = page.state;
  const n = s.nics;
  const all = n.reason ? [] : n.cards;
  /* Only cards that can be added go in the table; the rest, folded away, say why not. */
  const cards = all.filter(c => c.problems.length === 0);
  const blocked = all.filter(c => c.problems.length > 0);
  const active = n.reason ? [] : n.active;
  $('sys-nics-active-wrap').hidden = active.length === 0;
  $('sys-nics-active-empty').hidden = !!n.reason || active.length > 0;
  fillBody($('sys-nics-active').tBodies[0], active.length, (tr, i) => {
    const a = active[i];
    const multi = a.port > 0 || a.shares.length > 0;
    const blocked = a.problems.length > 0;
    const kind = a.kind === 'mlx' ? 'Mellanox，内核驱动' : `DPDK，${n.uio}`;
    const status = [a.role === 'wan' ? 'WAN' : '', a.running ? '' : 'VPP 里没有这个接口',
      a.shares.length ? `和 ${a.shares.join('、')} 同一块卡` : ''].filter(Boolean).join('，');
    const go = button('退出', () => {
      let note;
      if (a.shares.length) note = `\n\n同一块卡上的 ${a.shares.join('、')} 留在 VPP，这个口不再接入。`;
      else if (a.kind === 'mlx') note = '\n\nMellanox 网卡本来就由内核驱动管理，退出后只是 VPP 不再用它。';
      else note = `\n\n网卡交还 ${a.driver || '内核自动选择的驱动'}${a.interface ? `，Linux 网卡 ${a.interface} 重新出现（地址要由系统的网络配置设置）` : ''}。`;
      apply('nics/retire', { name: a.name }, `让 ${a.name}（${a.address}${multi ? ` 口 ${a.port}` : ''}）退出 VPP` + note, true);
    }, blocked || locked() || !s.can_restart);
    row(tr, [a.name, a.address + (multi ? ` 口 ${a.port}` : ''), a.interface || '—', kind,
      status + (blocked ? (status ? '。' : '') + a.problems.join('；') : '')], go);
    tr.children[4].classList.toggle('error', blocked);
  });
  $('nic-help').hidden = !n.reason;
  $('nic-help').textContent = n.reason ? '这里不能加入或退出网卡：' + n.reason + '。' : '';
  $('nic-add-help').textContent = `把还没接入的 PCI 网卡交给 VPP：网卡写进启动文件 ${s.start_conf} 的 dpdk 段和安装器的 router.env，VPP 启动前绑定到 ${n.uio}（Mellanox 网卡保留内核驱动，一个 PCI 设备上的几个口分别加入），${n.queues} 个收包队列（等于 worker 数，不超过网卡上限）。要重启 VPP，60 秒内不确认就恢复，网卡交还原来的驱动。接入后在接口页配置地址、桥和出口。`;
  $('sys-nics-wrap').hidden = cards.length === 0;
  $('sys-nics-empty').hidden = !!n.reason || cards.length > 0;
  $('sys-nics-blocked').hidden = blocked.length === 0;
  $('sys-nics-blocked-summary').textContent = `${blocked.length} 块网卡不能加入`;
  fillBody($('sys-nics-blocked-table').tBodies[0], blocked.length, (tr, i) => {
    const c = blocked[i];
    const multi = c.port > 0 || c.shares.length > 0;
    row(tr, [c.address + (multi ? ` 口 ${c.port}` : ''), c.interface || '—', `${c.id}${c.pmd ? `，${c.pmd}` : ''}`,
      c.driver === 'none' ? '无' : c.driver, c.problems.join('；')]);
  });
  $('sys-nics-parts').hidden = !!n.reason;
  fillBody($('sys-nics').tBodies[0], cards.length, (tr, i) => {
    const c = cards[i];
    const key = `${c.address}/${c.port}`;
    const multi = c.port > 0 || c.shares.length > 0;
    let input = tr.querySelector('input');
    if (!input || input.dataset.key !== key) {
      input = document.createElement('input');
      input.dataset.key = key;
      input.size = 10;
      input.maxLength = 32;
      input.value = n.suggested_name;
    }
    input.disabled = locked();
    const status = [c.link || (c.interface ? '' : '没有 Linux 网卡'), ...c.addresses,
      c.shares.length ? `和 ${c.shares.join('、')} 同一块卡` : ''].filter(Boolean).join('，');
    const go = button('加入', () => {
      const name = input.value.trim();
      if (!name) return;
      const warn = c.warnings.length ? '\n\n注意：' + c.warnings.join('\n') : '';
      apply('nics/add', { address: c.address, port: c.port, name, accept: true },
        `把 ${c.address}${multi ? ` 口 ${c.port}` : ''}${c.interface ? `（${c.interface}）` : ''} 接入 VPP，接口名 ${name}` + warn, true);
    }, locked() || !s.can_restart);
    row(tr, [c.address + (multi ? ` 口 ${c.port}` : ''), c.interface || '—', `${c.id}${c.pmd ? `，${c.pmd}` : ''}`, c.driver === 'none' ? '无' : c.driver,
      status + (c.warnings.length ? (status ? '。' : '') + c.warnings.join('；') : '')], input, go);
  });
}

function renderGovernors() {
  const s = page.state;
  const list = s.governors || [];
  const settings = s.governor_settings || {};
  $('sys-governors-empty').hidden = list.length > 0;
  fillBody($('sys-governors').tBodies[0], list.length, (tr, i) => {
    const p = list[i];
    const setting = settings[p.name] || '';
    const cpus = p.cpus.map(id => s.cpus.find(c => c.id === id)).filter(Boolean);
    const big = new Set(s.cpus.map(c => c.big)).size > 1 ? (cpus[0]?.big ? '（大核）' : '（小核）') : '';
    const choice = select([['', '缺省'], ...p.available.map(g => [g, g])], setting);
    const go = button('应用', () => {
      const value = tr.querySelector('select').value;
      if (value === setting) return;
      apply('governor', { policy: p.name, governor: value }, value
        ? `CPU ${p.cpus.join('、')} 的调速器改为 ${value}，开机时也这样设置`
        : `CPU ${p.cpus.join('、')} 的调速器改回缺省（系统的设置）：现在的 ${p.governor} 不变`);
    }, page.busy);
    const current = p.governor + (setting && setting !== p.governor ? `（设置的是 ${setting}）` : '');
    const floorSetting = s.frequency_floors?.[p.name] || 0;
    let floor = tr.querySelector(`[data-floor-policy="${p.name}"]`);
    let input = floor?.querySelector('input');
    if (!floor) {
      floor = document.createElement('div');
      floor.className = 'form-row';
      floor.dataset.floorPolicy = p.name;
      input = document.createElement('input');
      input.type = 'number';
      input.step = '1';
      input.dataset.policy = p.name;
      input.oninput = () => { input.dataset.dirty = '1'; };
      const choices = document.createElement('datalist');
      choices.id = `frequency-floor-${p.name}`;
      input.setAttribute('list', choices.id);
      floor.append(input, choices, document.createTextNode('MHz '), button('设置下限'), button('恢复下限'));
    }
    floor.querySelector('datalist').replaceChildren(...(p.frequencies || []).map(khz => new Option(String(khz / 1000), String(khz / 1000))));
    if (!input.dataset.dirty && input !== document.activeElement) input.value = (floorSetting || p.scaling_min_khz) / 1000;
    input.min = p.min_khz / 1000;
    input.max = p.scaling_max_khz / 1000;
    input.setAttribute('aria-label', `CPU ${p.cpus.join('、')} 最低频率（MHz）`);
    const canSetFloor = p.scaling_min_khz > 0 && p.scaling_max_khz > 0;
    input.disabled = page.busy || !canSetFloor;
    const [setFloor, restoreFloor] = floor.querySelectorAll('button');
    setFloor.disabled = page.busy || !canSetFloor;
    setFloor.onclick = () => {
      if (!input.reportValidity() || !input.value) return;
      const khz = Math.round(Number(input.value) * 1000);
      apply('frequency-floor', { policy: p.name, min_khz: khz },
        `CPU ${p.cpus.join('、')} 的最低频率设为 ${mhz(khz)}，开机时也保持；调速器保持 ${p.governor}`);
    };
    restoreFloor.disabled = page.busy || !floorSetting;
    restoreFloor.onclick = () => {
      apply('frequency-floor', { policy: p.name, min_khz: 0 },
        `恢复 CPU ${p.cpus.join('、')} 启用最低频率保护前的下限，并取消这项开机设置`);
    };
    row(tr, [`CPU ${p.cpus.join('、')}${big}`, mhz(p.cur_khz), `${mhz(p.scaling_min_khz)} – ${mhz(p.scaling_max_khz)}`, current], choice, go, floor);
  });
}

const natNames = { ei: 'NAT44-EI', ed: 'NAT44-ED' };
const natName = mode => natNames[mode] || 'NAT44';

function renderNAT() {
  const s = page.state;
  const n = s.nat;
  const mode = n.file_mode || n.mode;
  const ed = mode === 'ed';
  $('nat-cli-file').textContent = s.cli_file;
  $('nat-mode-files').textContent = s.cli_file;
  const running = n.running;
  let help;
  if (!n.enabled) help = `${s.cli_file} 里没有启用 NAT44（nat44 ei plugin enable 或 nat44 plugin enable），这里不能修改超时和会话表。在接口页把上行口设为出口后会启用。`;
  else if (!running) help = `VPP 没有 ${natName(mode)} 插件，下面是配置文件里的值。`;
  else {
    const t = running.timeouts, z = running.size;
    const size = running.mode === 'ed' ? `每线程 ${z.sessions} 个会话` : `每线程 ${z.sessions} 个会话、${z.users} 个用户，每个用户 ${z.user_sessions} 个会话`;
    help = `VPP 现在运行 ${natName(running.mode)}：TCP 已建立 ${t.tcp_established} 秒、握手和关闭 ${t.tcp_transitory} 秒、UDP ${t.udp} 秒、ICMP ${t.icmp} 秒；${size}。`;
    if (n.file_mode && running.mode !== n.file_mode) help += ` ${s.cli_file} 里却是 ${natName(n.file_mode)} 的命令，下次启动会失败，把模式改一致。`;
  }
  $('nat-help').textContent = help;
  $('nat-mode-now').textContent = n.mode ? `启动文件加载 ${natName(n.mode)}` : '启动文件没有加载 NAT 插件';
  const target = n.mode === 'ed' ? 'ei' : 'ed';
  $('nat-mode-switch').textContent = `改为 ${natName(target)}`;
  $('nat-mode-switch').disabled = !n.mode || !!n.switch_problem || locked() || !s.can_restart;
  $('nat-mode-problem').hidden = !n.switch_problem;
  $('nat-mode-problem').textContent = n.switch_problem ? '不能切换：' + n.switch_problem : '';
  $('nat-size-help').textContent = ed
    ? '会话数是每个线程的上限（主线程和每个 worker 各一份）。表满时新连接被丢弃。表越大占用 VPP 主堆内存越多，内存不够时插件启用失败，VPP 会自动恢复旧值。要重启 VPP，60 秒内不确认就恢复。'
    : '会话数和用户数是每个线程的上限（主线程和每个 worker 各一份），每个用户的会话数是一个局域网地址最多同时占用的会话。表满时新连接被丢弃。表越大占用 VPP 主堆内存越多，内存不够时插件启用失败，VPP 会自动恢复旧值。要重启 VPP，60 秒内不确认就恢复。';
  $('nat-size-users-label').hidden = ed;
  $('nat-user-sessions-label').hidden = ed;
  if (!page.formsFilled) {
    const t = n.file_timeouts, z = n.file_size;
    $('nat-tcp-est').value = t.tcp_established;
    $('nat-tcp-trans').value = t.tcp_transitory;
    $('nat-udp').value = t.udp;
    $('nat-icmp').value = t.icmp;
    $('nat-size-sessions').value = z.sessions || running?.size.sessions || '';
    $('nat-size-users').value = z.users || running?.size.users || '';
    $('nat-user-sessions').value = z.user_sessions || running?.size.user_sessions || '';
  }
  const off = !n.enabled || locked();
  for (const id of ['nat-tcp-est', 'nat-tcp-trans', 'nat-udp', 'nat-icmp', 'nat-timeouts-apply', 'nat-timeouts-default', 'nat-size-sessions', 'nat-size-users', 'nat-user-sessions']) $(id).disabled = off;
  $('nat-size-apply').disabled = off || !s.can_restart;
}

function render() {
  const s = page.state;
  if (!s) return;
  const problems = [];
  if (s.error) problems.push(s.error);
  if (s.apply_error) problems.push('VPP 重启后恢复收包设置出错：' + s.apply_error);
  for (const w of s.warnings || []) problems.push(w);
  if (s.other_pending) problems.push('接口页有改动等待确认，确认或恢复后才能在这里修改线程、网卡和 NAT。');
  $('sys-error').hidden = problems.length === 0;
  $('sys-error').textContent = problems.join(' ');
  renderPending();
  renderRx();
  renderThreads();
  renderNICs();
  renderGovernors();
  renderNAT();
  page.formsFilled = true;
}

function fileNATName() {
  const n = page.state.nat;
  return natName(n.file_mode || n.mode);
}

function applyTimeouts() {
  const body = {
    tcp_established: Number($('nat-tcp-est').value), tcp_transitory: Number($('nat-tcp-trans').value),
    udp: Number($('nat-udp').value), icmp: Number($('nat-icmp').value),
  };
  apply('nat/timeouts', body, `${fileNATName()} 超时改为：TCP 已建立 ${body.tcp_established} 秒、握手和关闭 ${body.tcp_transitory} 秒、UDP ${body.udp} 秒、ICMP ${body.icmp} 秒`);
}

function applySize() {
  const n = page.state.nat;
  if ((n.file_mode || n.mode) === 'ed') {
    const body = { sessions: Number($('nat-size-sessions').value) };
    apply('nat/size', body, `${fileNATName()} 会话表改为每线程 ${body.sessions} 个会话`, true);
    return;
  }
  const body = { sessions: Number($('nat-size-sessions').value), users: Number($('nat-size-users').value), user_sessions: Number($('nat-user-sessions').value) };
  apply('nat/size', body, `${fileNATName()} 会话表改为每线程 ${body.sessions} 个会话、${body.users} 个用户，每个用户 ${body.user_sessions} 个会话`, true);
}

function applyNATMode() {
  const n = page.state.nat;
  const target = n.mode === 'ed' ? 'ei' : 'ed';
  const what = target === 'ed'
    ? 'NAT 改为 NAT44-ED：外部端口按目的地复用，只放行回应已有连接的包。需要外部主机主动连进来的游戏或 P2P 应用可能要用端口转发。'
    : 'NAT 改为 NAT44-EI：每个内网端口对所有目的地用同一个外部端口，任何外部主机都能发进来。';
  apply('nat/mode', { mode: target }, what + `会改写启动文件和 ${page.state.cli_file} 里的 NAT 命令，所有 NAT 连接重建。`, true);
}

export function start() {
  $('sys-confirm').onclick = () => apply('confirm', {});
  $('sys-rollback').onclick = () => { if (confirm('立即恢复到修改前并重启 VPP？')) apply('rollback', {}, '', true); };
  $('thr-main').onchange = updateThreadForm;
  $('thr-policy').onchange = updateThreadForm;
  $('thr-apply').onclick = applyThreads;
  $('nat-timeouts-apply').onclick = applyTimeouts;
  $('nat-timeouts-default').onclick = () => {
    const d = page.state.nat.defaults;
    $('nat-tcp-est').value = d.tcp_established;
    $('nat-tcp-trans').value = d.tcp_transitory;
    $('nat-udp').value = d.udp;
    $('nat-icmp').value = d.icmp;
  };
  $('nat-size-apply').onclick = applySize;
  $('nat-mode-switch').onclick = applyNATMode;
}

export function show() {
  page.formsFilled = false;
  load();
  clearInterval(page.timer);
  clearInterval(page.tick);
  page.timer = setInterval(() => {
    if (document.hidden || page.busy) return;
    load();
  }, 5000);
  page.tick = setInterval(() => { if (page.state && page.state.pending) renderPending(); }, 1000);
}

export function hide() {
  clearInterval(page.timer);
  clearInterval(page.tick);
}
