/* Interfaces: addresses, VLAN sub-interfaces, bridge domains, state and MTU. Every change goes
   through vpp-interfaces, which edits VPP's startup CLI file and applies the change live, and
   undoes both unless it is confirmed in time. */
import { $, fetchJSON, postJSON, fillBody, setCells } from '../lib.js';

const API = 'api/interfaces';
const page = { state: null, labels: new Map(), timer: 0, tick: 0, deadline: 0, busy: false, editing: '', bridge: 0 };

const KIND = { physical: '物理口', sub: 'VLAN 子接口', loopback: '环回', tap: 'TAP', vxlan: 'VXLAN', gre: 'GRE', ipip: 'IPIP', other: '其他' };
const OUTCOMES = { confirmed: '已保留', 'rolled-back': '已恢复', 'rollback-failed': '恢复失败' };

function message(text, isError) {
  $('ifaces-message').textContent = text || '';
  $('ifaces-message').classList.toggle('error', !!isError);
}

const shown = name => {
  const label = page.labels.get(name);
  return label && label !== name ? `${name}（${label}）` : name;
};

async function loadLabels() {
  try {
    const status = await fetchJSON('api/status');
    page.labels = new Map((status.interfaces || []).filter(row => row.label).map(row => [row.name, row.label]));
  } catch {
    /* VPP's names still identify the interfaces. */
  }
}

async function load() {
  const labels = loadLabels();
  try {
    page.state = await fetchJSON(API);
    $('ifaces-content').hidden = false;
    $('ifaces-unavailable').hidden = true;
  } catch (err) {
    $('ifaces-content').hidden = true;
    $('ifaces-unavailable').hidden = false;
    $('ifaces-unavailable').textContent = '无法读取接口：' + err.message;
    return;
  }
  await labels;
  if (page.state.pending) page.deadline = Date.now() + page.state.seconds_remaining * 1000;
  render();
}

/* Applies one change. Each takes effect at once and is undone unless confirmed. */
async function apply(path, body, description, warning = '') {
  if (page.busy) return false;
  const restart = path === 'vlan';
  const text = `${description}\n\n${restart ? '会写入配置文件并重启 VPP，所有接口的转发中断约 10 秒。' : '会立即生效，并写入 VPP 的启动配置文件。'}应用后 60 秒内需要确认，否则自动恢复。${warning ? '\n\n' + warning : ''}`;
  if (!confirm(text)) return false;
  page.busy = true;
  message(restart ? '正在重启 VPP…' : '正在应用…');
  try {
    page.state = await postJSON(`${API}/${path}`, body);
    message('');
    if (page.state.pending) page.deadline = Date.now() + page.state.seconds_remaining * 1000;
    return true;
  } catch (err) {
    message(err.message, true);
    return false;
  } finally {
    page.busy = false;
    render();
  }
}

async function act(path, text) {
  if (page.busy) return;
  page.busy = true;
  message(text);
  try {
    page.state = await postJSON(`${API}/${path}`, {});
    message('');
  } catch (err) {
    message(err.message, true);
  } finally {
    page.busy = false;
    render();
  }
}

function button(text, onClick, disabled, title = '') {
  const element = document.createElement('button');
  element.className = 'close';
  element.textContent = text;
  element.onclick = onClick;
  element.disabled = !!disabled;
  element.title = title;
  return element;
}

function renderPending() {
  const state = page.state;
  $('ifaces-pending').hidden = !state.pending;
  if (state.pending) {
    const seconds = Math.max(0, Math.ceil((page.deadline - Date.now()) / 1000));
    $('ifaces-pending-text').textContent = `${state.pending.description}。已生效，${seconds} 秒内未确认将自动恢复。`;
  }
  const last = state.last;
  $('ifaces-last').hidden = !last;
  if (last) {
    $('ifaces-last').textContent = `最近一次：${last.description}：${OUTCOMES[last.outcome] || last.outcome}${last.detail ? `（${last.detail}）` : ''}`;
    $('ifaces-last').classList.toggle('error', last.outcome === 'rollback-failed');
  }
}

function stateText(iface) {
  if (!iface.up) return '○ down';
  return iface.link ? '● up' : '◐ up，无链路';
}

const MODE = { none: '不配置', static: '静态', dhcp: 'DHCP', slaac: 'SLAAC', dhcpv6: 'DHCPv6' };

/* The addresses it has, and where dynamic ones come from. */
function addressText(iface) {
  const ways = [];
  if (iface.ipv4 && ['dhcp'].includes(iface.ipv4.mode)) ways.push('IPv4 ' + MODE[iface.ipv4.mode]);
  if (iface.ipv6 && ['slaac', 'dhcpv6'].includes(iface.ipv6.mode)) ways.push('IPv6 ' + MODE[iface.ipv6.mode]);
  const text = iface.addresses.join(' ') || (ways.length ? '获取中' : '—');
  return ways.length ? `${text}（${ways.join('，')}）` : text;
}

function bridgeText(iface) {
  return iface.bridge ? `网桥 ${iface.bridge}` : '—';
}

/* An exit translates what leaves by it to its own address (NAT44-EI or NAT44-ED as an output feature),
   as the installer does for its WAN, so any uplink can be one without hand-written NAT. */
function natButton(iface, locked) {
  if (iface.nat) {
    return button('取消出口', () => apply('nat', { interface: iface.name, nat: false }, `取消 ${shown(iface.name)} 的出口（NAT）`,
      '从这个口出去的局域网流量不再做地址转换，路由或默认出口还指向它时会不通。'), locked);
  }
  const element = button('设为出口', () => apply('nat', { interface: iface.name, nat: true }, `把 ${shown(iface.name)} 设为出口：从它出去的流量转换成它自己的地址（NAT44），地址由 DHCP 变化时跟着变`,
    '只做地址转换，不改路由。要让流量走这个口，在路由页把它选为默认出口或规则的出口。'), locked || !!iface.nat_reason);
  if (iface.nat_reason) element.title = iface.nat_reason;
  return element;
}

/* Hairpinning lets LAN hosts reach a port forward by the exit's outside address. It costs every
   IPv4 packet the interface receives a little (about 8 % of NAT throughput at full load), so it is
   off until turned on, per LAN-side interface: normally a bridge's gateway. */
function hairpinText(iface) {
  if (!iface.hairpin) return iface.hairpin_live ? '关（VPP 里还开着）' : '关';
  return iface.hairpin_live ? '开' : '开（VPP 里没开）';
}

function hairpinButton(iface, locked) {
  if (iface.hairpin) {
    return button('关闭回流', () => apply('hairpin', { interface: iface.name, hairpin: false }, `关闭 ${shown(iface.name)} 的 NAT 回流`,
      '局域网里的设备用出口的外部地址访问端口转发时不再转回局域网，要改用内网地址。'), locked);
  }
  return button('开启回流', () => apply('hairpin', { interface: iface.name, hairpin: true }, `开启 ${shown(iface.name)} 的 NAT 回流：从这里进来、发往出口外部地址上端口转发的流量转回局域网`,
    '这个接口收到的每个 IPv4 包都要多做一次检查，满负荷时 NAT 吞吐约降低 8%。不用外部地址访问自己的端口转发时不需要开。'), locked || !!iface.hairpin_reason, iface.hairpin_reason);
}

/* Interfaces where hairpinning makes sense to offer: LAN-side layer-3 ones, not exits. */
const hairpinCandidate = iface => iface.hairpin || (!iface.nat && !iface.bridge && !iface.reason && iface.ipv4 && iface.ipv4.mode !== 'none');

function renderInterfaces() {
  const state = page.state;
  const locked = !!state.pending || page.busy;
  /* A bridge's gateway (its BVI) belongs to the bridge, and is shown and set there. */
  const rows = state.interfaces.filter(iface => !iface.bvi);
  fillBody($('ifaces-table').tBodies[0], rows.length, (row, i) => {
    const iface = rows[i];
    setCells(row, [shown(iface.name), KIND[iface.kind] || iface.kind, iface.vlan ? String(iface.vlan) : '—', stateText(iface), iface.mtu ? String(iface.mtu) : iface.kind === 'sub' ? '继承' : '—', addressText(iface), bridgeText(iface), iface.nat ? 'NAT' : iface.hairpin ? '回流' : '—', '']);
    row.children[3].className = iface.up && iface.link ? 'online' : 'offline';
    const cell = row.lastChild;
    cell.textContent = '';
    if (iface.reason) {
      cell.textContent = '其他程序管理';
      cell.className = 'offline';
      cell.title = iface.reason;
    } else {
      cell.className = '';
      cell.title = '';
      cell.append(button('编辑', () => openEditor(iface.name), locked), ' ', natButton(iface, locked));
      if (hairpinCandidate(iface)) cell.append(' ', hairpinButton(iface, locked));
    }
  });
  $('ifaces-summary').textContent = state.file;
  $('ifaces-error').textContent = state.error || '';
}

const byName = name => page.state.interfaces.find(iface => iface.name === name);
const gatewayOf = bridge => bridge.bvi ? byName(bridge.bvi) : null;

function renderBridges() {
  const state = page.state;
  const locked = !!state.pending || page.busy;
  fillBody($('ifaces-bridges').tBodies[0], state.bridges.length, (row, i) => {
    const bridge = state.bridges[i];
    const gateway = gatewayOf(bridge);
    const addresses = gateway ? gateway.addresses.join(' ') || '（没有地址）' : '没有网关（纯二层）';
    const status = gateway ? stateText(gateway) : '—';
    setCells(row, [`网桥 ${bridge.id}`, addresses, bridge.members.map(shown).join('、') || '—', status, gateway ? hairpinText(gateway) : '—', '']);
    row.children[3].className = gateway && gateway.up ? 'online' : 'offline';
    const cell = row.lastChild;
    cell.textContent = '';
    if (!bridge.in_file) {
      cell.textContent = '其他程序管理';
      cell.className = 'offline';
    } else {
      cell.className = '';
      cell.append(button('编辑', () => openBridge(bridge.id), locked));
      if (gateway && !gateway.reason) cell.append(' ', hairpinButton(gateway, locked));
    }
  });
  $('ifaces-bridges-empty').hidden = state.bridges.length > 0;
}

/* Keeps what was picked when the list refreshes. */
function setOptions(select, options) {
  const signature = options.map(option => option.value + '|' + option.label).join('\n');
  if (select.dataset.options === signature) return;
  const current = select.value;
  select.textContent = '';
  for (const { value, label } of options) {
    const option = document.createElement('option');
    option.value = value;
    option.textContent = label;
    select.append(option);
  }
  select.dataset.options = signature;
  if (options.some(option => option.value === current)) select.value = current;
}

function renderForms() {
  const state = page.state;
  const locked = !!state.pending || page.busy;
  const parents = state.interfaces.filter(iface => iface.kind === 'physical' && !iface.reason);
  setOptions($('subif-parent'), parents.map(iface => ({ value: iface.name, label: shown(iface.name) })));
  $('subif-add').disabled = locked || !parents.length;
  renderDevice();
  $('bd-add').disabled = locked;
}

function render() {
  if (!page.state) return;
  renderPending();
  renderInterfaces();
  renderBridges();
  renderForms();
  if ($('iface-dialog').open) renderEditor();
  if ($('bridge-dialog').open) renderBridge();
}

/* The bridge editor: its gateway's addresses and MTU, and its members. */

const currentBridge = () => page.state && page.state.bridges.find(bridge => bridge.id === page.bridge);

function openBridge(id) {
  page.bridge = id;
  const bridge = currentBridge();
  if (!bridge) return;
  const gateway = gatewayOf(bridge);
  $('bridge-title').textContent = `网桥 ${id}`;
  $('bridge-addresses').value = gateway ? (gateway.file_addresses.length ? gateway.file_addresses : gateway.addresses).join('\n') : '';
  $('bridge-mtu').value = gateway ? gateway.mtu || '' : '';
  $('bridge-error').textContent = '';
  renderBridge();
  $('bridge-dialog').showModal();
}

/* Interfaces that may join: managed, in no bridge, without addresses, and not a loopback. */
function joinable() {
  return page.state.interfaces.filter(iface => !iface.reason && !iface.bridge && !iface.addresses.length && !iface.file_addresses.length && ['physical', 'sub', 'tap', 'vxlan', 'gre'].includes(iface.kind));
}

function renderBridge() {
  const bridge = currentBridge();
  if (!bridge) { $('bridge-dialog').close(); return; }
  const locked = !!page.state.pending || page.busy;
  const gateway = gatewayOf(bridge);
  const reason = !gateway ? '这个网桥没有网关，是纯二层网桥。' : gateway.address_reason || gateway.reason;
  $('bridge-gateway-reason').textContent = reason || '';
  $('bridge-gateway-reason').hidden = !reason;
  $('bridge-gateway').hidden = !gateway;
  if (gateway) {
    $('bridge-addresses').disabled = !!reason;
    $('bridge-address-apply').disabled = locked || !!reason;
    $('bridge-mtu-apply').disabled = locked || !!gateway.reason;
    $('bridge-bvi-note').textContent = `网关在 VPP 里是 BVI 接口 ${gateway.name}。`;
  }
  fillBody($('bridge-members').tBodies[0], bridge.members.length, (row, i) => {
    const name = bridge.members[i];
    const member = byName(name);
    setCells(row, [shown(name), '']);
    const cell = row.lastChild;
    cell.textContent = '';
    if (member && !member.reason) {
      cell.append(button('移出', () => bridgeApply('bridge', { interface: name, bridge: 0, bvi: false }, `把 ${name} 移出网桥 ${bridge.id}`), locked));
    } else {
      cell.textContent = '其他程序管理';
      cell.className = 'offline';
    }
  });
  $('bridge-members-empty').hidden = bridge.members.length > 0;
  const candidates = joinable();
  setOptions($('bridge-join'), candidates.map(iface => ({ value: iface.name, label: shown(iface.name) })));
  $('bridge-join-apply').disabled = locked || !candidates.length;
}

async function bridgeApply(path, body, description, warning) {
  $('bridge-error').textContent = '';
  message('');
  const done = await apply(path, body, description, warning);
  if (done) $('bridge-dialog').close();
  else if ($('ifaces-message').classList.contains('error')) $('bridge-error').textContent = $('ifaces-message').textContent;
}

function startBridge() {
  $('bridge-address-apply').onclick = () => {
    const bridge = currentBridge();
    const addresses = $('bridge-addresses').value.split(/[\s,，]+/).filter(Boolean);
    bridgeApply('address', { interface: bridge.bvi, addresses },
      addresses.length ? `把网桥 ${bridge.id} 的网关地址改成 ${addresses.join('、')}` : `删除网桥 ${bridge.id} 的网关地址`, ADDRESS_WARNING);
  };
  $('bridge-mtu-apply').onclick = () => {
    const bridge = currentBridge();
    const mtu = Number($('bridge-mtu').value);
    bridgeApply('mtu', { interface: bridge.bvi, mtu }, `把网桥 ${bridge.id} 网关的 MTU 改成 ${mtu}`);
  };
  $('bridge-join-apply').onclick = () => {
    const bridge = currentBridge();
    const name = $('bridge-join').value;
    bridgeApply('bridge', { interface: name, bridge: bridge.id, bvi: false }, `把 ${name} 加入网桥 ${bridge.id}`,
      '加入后它成为二层口，经过它的流量进入这个网桥的网络。');
  };
}

/* The editor. Each part applies as its own change. */

const current = () => page.state && page.state.interfaces.find(iface => iface.name === page.editing);

function openEditor(name) {
  page.editing = name;
  const iface = current();
  if (!iface) return;
  $('iface-title').textContent = `编辑 ${shown(name)}`;
  for (const v of ['4', '6']) {
    const family = iface['ipv' + v];
    $(`ip${v}-mode`).value = family.mode;
    $(`ip${v}-addresses`).value = family.addresses.join('\n');
    $(`ip${v}-gateway`).value = family.gateway || '';
  }
  $('ip4-hostname').value = iface.ipv4.hostname || '';
  $('iface-bridge').dataset.options = '';
  $('iface-state').value = iface.up ? 'up' : 'down';
  $('iface-mtu').value = iface.mtu || '';
  $('iface-mtu').placeholder = iface.kind === 'sub' ? '继承父接口' : '';
  $('iface-vlan').value = iface.vlan || '';
  $('iface-error').textContent = '';
  renderEditor();
  const bridge = $('iface-bridge');
  bridge.value = String(iface.bridge || 0);
  $('iface-dialog').showModal();
}

function renderEditor() {
  const iface = current();
  if (!iface) { $('iface-dialog').close(); return; }
  const locked = !!page.state.pending || page.busy;
  const reason = (id, text) => { $(id).textContent = text || ''; $(id).hidden = !text; };

  for (const v of ['4', '6']) renderFamily(iface, v, locked, reason);

  reason('iface-bridge-reason', iface.bridge_reason);
  setOptions($('iface-bridge'), [{ value: '0', label: '不在网桥里' }, ...page.state.bridges.filter(bridge => bridge.in_file).map(bridge => ({ value: String(bridge.id), label: `网桥 ${bridge.id}` }))]);
  $('iface-bridge-apply').disabled = locked || !!iface.bridge_reason;

  $('iface-state-apply').disabled = locked;
  $('iface-mtu-apply').disabled = locked;

  const sub = iface.kind === 'sub';
  $('iface-vlan-part').hidden = !sub;
  if (sub) {
    reason('iface-vlan-reason', iface.vlan_reason);
    $('iface-vlan').disabled = !!iface.vlan_reason;
    $('iface-vlan-apply').disabled = locked || !!iface.vlan_reason;
  }
  /* Only what the file created can go; for a physical port that is never so, so say nothing. */
  $('iface-delete-part').hidden = iface.kind === 'physical' && !!iface.delete_reason;
  reason('iface-delete-reason', iface.delete_reason);
  $('iface-delete').disabled = locked || !!iface.delete_reason;
}

const FAMILY_HELP = {
  none: '不配置这个地址族的地址。',
  static: '地址和网关写进配置文件。',
  dhcp: '由 DHCP 服务器分配地址和默认路由。',
  slaac: '按路由器通告（RA）自动生成地址并设置默认路由。',
  dhcpv6: '由 DHCPv6 服务器分配地址，默认路由来自路由器通告（RA）；通告里允许自动配置的前缀也会生成地址。',
};

function renderFamily(iface, v, locked, reason) {
  const mode = $(`ip${v}-mode`).value;
  const loopback = iface.kind === 'loopback';
  const why = iface.address_reason || (loopback && ['dhcp', 'slaac', 'dhcpv6'].includes(mode) ? 'loopback 没有链路，只能用静态地址。' : '');
  reason(`ip${v}-reason`, why);
  $(`ip${v}-mode`).disabled = !!iface.address_reason;
  $(`ip${v}-static-part`).hidden = mode !== 'static';
  if (v === '4') $('ip4-dhcp-part').hidden = mode !== 'dhcp';
  $(`ip${v}-apply`).disabled = locked || !!why;
  $(`ip${v}-help`).textContent = FAMILY_HELP[mode] || '';
  const ipv6 = v === '6';
  const now = iface.addresses.filter(address => address.includes(':') === ipv6);
  const configured = iface['ipv' + v];
  $(`ip${v}-current`).textContent = `现在：${MODE[configured.mode]}${now.length ? '，' + now.join(' ') : ''}`;
}

async function editorApply(path, body, description, warning) {
  $('iface-error').textContent = '';
  message('');
  const done = await apply(path, body, description, warning);
  if (done) $('iface-dialog').close();
  else if ($('ifaces-message').classList.contains('error')) $('iface-error').textContent = $('ifaces-message').textContent;
}

const ADDRESS_WARNING = '局域网网关在原网段内换地址时，DHCP 发的网关和 Linux 管理口的默认路由跟着改（已经连着的设备续租或重新连接后才换网关），没确认时一起恢复。'
  + '换到别的网段时，依赖这个地址的其他配置（dnsmasq 的地址池、Gate、Linux 管理口的地址等）不会跟着修改。';

function startEditor() {
  for (const v of ['4', '6']) {
    $(`ip${v}-mode`).onchange = () => renderEditor();
    $(`ip${v}-apply`).onclick = () => {
      const name = page.editing;
      const mode = $(`ip${v}-mode`).value;
      const body = { interface: name, mode };
      let text = MODE[mode];
      if (mode === 'static') {
        body.addresses = $(`ip${v}-addresses`).value.split(/[\s,，]+/).filter(Boolean);
        body.gateway = $(`ip${v}-gateway`).value.trim();
        text += ' ' + body.addresses.join('、') + (body.gateway ? '，网关 ' + body.gateway : '');
      }
      if (mode === 'dhcp') body.hostname = $('ip4-hostname').value.trim();
      const warning = (mode === 'static' || mode === 'none' ? ADDRESS_WARNING + '\n\n' : '') +
        '经过这个接口连到面板时，改错可能断开连接，60 秒内不确认会自动恢复。';
      editorApply('ipv' + v, body, `把 ${name} 的 IPv${v} 改成 ${text}`, warning);
    };
  }
  $('iface-bridge-apply').onclick = () => {
    const name = page.editing;
    const bridge = Number($('iface-bridge').value);
    editorApply('bridge', { interface: name, bridge, bvi: false }, bridge ? `把 ${name} 加入网桥 ${bridge}` : `把 ${name} 移出网桥`);
  };
  $('iface-state-apply').onclick = () => {
    const name = page.editing;
    const up = $('iface-state').value === 'up';
    editorApply('state', { interface: name, up }, `把 ${name} 设为 ${up ? 'up' : 'down'}`, up ? '' : '接口 down 后经过它的流量全部中断。');
  };
  $('iface-mtu-apply').onclick = () => {
    const name = page.editing;
    const mtu = Number($('iface-mtu').value);
    editorApply('mtu', { interface: name, mtu }, `把 ${name} 的 MTU 改成 ${mtu}`);
  };
  $('iface-vlan-apply').onclick = () => {
    const name = page.editing;
    const vlan = Number($('iface-vlan').value);
    editorApply('vlan', { interface: name, vlan }, `把 ${name} 的 VLAN ID 改成 ${vlan}，接口名不变`);
  };
  $('iface-delete').onclick = () => {
    const name = page.editing;
    if (current().kind === 'sub') editorApply('subif/delete', { interface: name }, `删除子接口 ${name}，它的地址和桥接一起删除`);
    else editorApply('delete', { interface: name }, `删除接口 ${name}，配置文件里它的各行一起删除`);
  };
}

/* Other interfaces. The fields shown are the kind's; VPP names it by an instance it is given. */
const DEVICE_HELP = {
  tap: 'VPP 一侧是 tapN，Linux 一侧是填写的接口名，可以顺便给 Linux 一侧设地址（IPv4 和 IPv6 各一个，用空格隔开）。建好后在“编辑”里设置 VPP 一侧的地址，或加入网桥。',
  vxlan: '二层隧道，名字是 vxlan_tunnelN。本端地址要是 VPP 某个接口上的地址。通常加入网桥，把两地的二层网络连起来。',
  gre: '名字是 greN。不勾二层时是三层隧道，在“编辑”里给它设地址；勾了二层（TEB）时承载以太网帧，可以加入网桥。',
  ipip: '三层隧道（IP-in-IP），名字是 ipipN，在“编辑”里给它设地址。',
  loopback: '名字是 loopN，没有链路，只能设静态地址，常用作路由器自己的地址。',
  af_packet: '把一块 Linux 网卡接进 VPP，名字是 host-网卡名。Linux 不要再用这块网卡（不设地址、不让 NetworkManager 管理），开机时网卡要已经存在。经过它连到面板时，接错了会断开，60 秒内不确认会自动恢复。',
};

function renderDevice() {
  const kind = $('dev-kind').value;
  for (const label of document.querySelectorAll('[data-dev]')) label.hidden = !label.dataset.dev.split(' ').includes(kind);
  $('dev-host-label').textContent = kind === 'tap' ? 'Linux 接口名' : 'Linux 网卡';
  $('dev-host').placeholder = kind === 'tap' ? '比如 vpp-lab，最多 15 个字符' : '比如 enp3s0';
  $('dev-local').placeholder = 'VPP 上的地址';
  $('dev-help').textContent = DEVICE_HELP[kind] || '';
  $('dev-add').disabled = !page.state || !!page.state.pending || page.busy;
}

function addDevice() {
  const kind = $('dev-kind').value;
  const body = { kind };
  const label = $('dev-kind').selectedOptions[0].textContent;
  let text = `新建 ${label} 接口`;
  if (kind === 'tap' || kind === 'af_packet') body.host = $('dev-host').value.trim();
  if (kind === 'tap') body.host_addresses = $('dev-host-addresses').value.split(/[\s,，]+/).filter(Boolean);
  if (['vxlan', 'gre', 'ipip'].includes(kind)) {
    body.local = $('dev-local').value.trim();
    body.peer = $('dev-peer').value.trim();
    text += `，${body.local} → ${body.peer}`;
  }
  if (kind === 'vxlan') { body.vni = Number($('dev-vni').value); text += `，VNI ${body.vni}`; }
  if (kind === 'gre') { body.l2 = $('dev-l2').checked; if (body.l2) text += '，二层'; }
  if (body.host) text += kind === 'tap' ? `，Linux 一侧 ${body.host}` : `：${body.host}`;
  apply('create', body, text, kind === 'af_packet' ? DEVICE_HELP.af_packet : '').then(done => {
    if (done) for (const id of ['dev-host', 'dev-host-addresses', 'dev-local', 'dev-peer', 'dev-vni']) $(id).value = '';
  });
}

export function start() {
  $('dev-kind').onchange = renderDevice;
  $('dev-add').onclick = addDevice;
  $('ifaces-confirm').onclick = () => act('confirm', '正在确认…');
  $('ifaces-rollback').onclick = () => { if (confirm('立即恢复到修改前？')) act('rollback', '正在恢复…'); };
  $('subif-add').onclick = () => {
    const parent = $('subif-parent').value;
    const vlan = Number($('subif-vlan').value);
    const subID = Number($('subif-id').value || 0);
    apply('subif', { parent, vlan, sub_id: subID }, `在 ${parent} 上新建 VLAN ${vlan} 子接口 ${parent}.${subID || vlan}`).then(done => {
      if (done) { $('subif-vlan').value = ''; $('subif-id').value = ''; }
    });
  };
  $('bd-add').onclick = () => {
    const bridge = Number($('bd-id').value);
    const addresses = $('bd-address').value.split(/[\s,，]+/).filter(Boolean);
    const bvi = addresses.length > 0;
    apply('bridge-domain', { bridge, bvi, addresses }, `新建网桥 ${bridge}${bvi ? '，网关地址 ' + addresses.join('、') : '（纯二层，没有网关）'}`).then(done => {
      if (done) { $('bd-id').value = ''; $('bd-address').value = ''; }
    });
  };
  startEditor();
  startBridge();
}

export function show() {
  load();
  clearInterval(page.timer);
  clearInterval(page.tick);
  page.timer = setInterval(() => {
    /* Do not refresh the forms out from under the typing. */
    if (document.hidden || page.busy || $('iface-dialog').open || $('bridge-dialog').open) return;
    load();
  }, 5000);
  page.tick = setInterval(() => { if (page.state && page.state.pending) renderPending(); }, 1000);
}

export function hide() {
  clearInterval(page.timer);
  clearInterval(page.tick);
}
