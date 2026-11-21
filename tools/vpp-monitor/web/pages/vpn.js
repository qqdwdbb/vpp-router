/* VPN clients, read only while this page is open. WireGuard peers are added and removed
   through vpp-wireguard; without it the page only shows them. */
import { $, bytes, fetchJSON, postJSON, fillBody, setCells, duration } from '../lib.js';

const API = 'api/wireguard';
const vpn = { timer: 0, managed: new Set(), manageable: false, busy: false, report: null, state: null, importedName: '' };

function shortKey(key) {
  return key.length > 12 ? key.slice(0, 8) + '…' : key;
}

function handshake(seconds) {
  if (seconds < 0) return '从未';
  return (seconds < 60 ? `${seconds} 秒` : duration(seconds)) + '前';
}

/* setCells was given the labels joined, so a cell whose buttons still match is left alone. */
function actionCell(cell, actions) {
  if (cell.firstChild?.nodeName !== 'BUTTON') {
    cell.textContent = '';
    for (const action of actions) {
      const button = document.createElement('button');
      button.className = 'close';
      button.textContent = action.label;
      cell.append(button);
    }
  }
  actions.forEach((action, i) => { cell.children[i].onclick = action.run; });
}
const labels = actions => actions.map(action => action.label).join('');

/* One key can be a peer of several interfaces. */
const peerID = peer => `${peer.interface}|${peer.public_key}`;
const peerActions = peer => vpn.managed.has(peerID(peer)) ? [{ label: '删除', run: () => removePeer(peer) }] : [];

function configStatus(config) {
  if (config.running) return '● 运行中';
  if (config.error) return '✕ 恢复失败';
  return config.enabled ? '○ 等待恢复' : '○ 已停止';
}

function configActions(config) {
  return [
    config.enabled
      ? { label: '停止', run: () => configAction('stop', config, `停止配置 ${config.name}？\n\n接口 ${config.interface} 会被删除，经过它的连接马上断开，配置仍然保留。`) }
      : { label: '启动', run: () => configAction('start', config) },
    ...(!config.enabled ? [
      { label: '编辑', run: () => editConfig(config) },
    ] : []),
    { label: '删除', run: () => configAction('delete', config, `删除配置 ${config.name}？\n\n私钥和节点都会一起删除，不能恢复。`) },
  ];
}

/* Tunnels from startup files are listed for completeness and have no controls. */
function renderConfigs() {
  const state = vpn.state;
  if (!state) return;
  $('vpn-configs-card').hidden = false;
  const stored = new Set(state.configs.map(config => config.interface));
  const addresses = new Map(state.interfaces.map(iface => [iface.name, iface.addresses]));
  const names = new Set([...state.interfaces.map(iface => iface.name), ...((vpn.report && vpn.report.wireguard) || []).map(peer => peer.interface)]);
  const system = [...names].filter(name => !stored.has(name)).sort();
  const rows = [...state.configs, ...system.map(name => ({ system: true, interface: name }))];
  $('vpn-configs-summary').textContent = state.vpp_error || `${state.configs.length} 份配置，${state.configs.filter(config => config.running).length} 份运行中。`;
  $('vpn-configs-summary').classList.toggle('error', !!state.vpp_error);
  fillBody($('vpn-configs').tBodies[0], rows.length, (row, i) => {
    const config = rows[i];
    if (config.system) {
      setCells(row, ['系统', '—', config.interface, (addresses.get(config.interface) || ['—']).join(' '), '—', '—', '—', '—', '—', '']);
      row.children[0].className = 'offline';
      row.children[0].title = '';
      return;
    }
    const actions = configActions(config);
    const gate = state.dns_gate || {};
    const dns = config.dns ? [config.dns.ipv4 || gate.ipv4, config.dns.ipv6 || gate.ipv6].filter(Boolean).join(' ') : '未启用';
    setCells(row, [configStatus(config), config.name, config.interface, config.addresses.join(' '), config.source, String(config.listen_port), shortKey(config.public_key), String(config.peers), dns, labels(actions)]);
    actionCell(row.lastChild, actions);
    row.children[0].className = config.running ? 'online' : 'offline';
    row.children[0].title = config.error || (config.dns ? 'DNS 转发已配置' : 'DNS 转发未配置');
    row.children[6].title = config.public_key;
  });
}

// What DNS forwarding would use, as the service will discover it when the tunnel starts.
function gateNote(dns) {
  const gate = vpn.state?.dns_gate || {};
  const endpoints = [dns?.ipv4 || gate.ipv4, dns?.ipv6 || gate.ipv6].filter(Boolean).join('、');
  return endpoints
    ? `自动使用 DNS Gate：${endpoints}（Linux 接口 ${dns?.host_interface || gate.host_interface || '未发现'}）。客户端 DNS 填隧道接口自己的地址。`
    : '未发现可用的 DNS Gate 监听地址，请先配置并启动 Gate。';
}

function editConfig(config) {
  if (vpn.busy) return;
  $('vpn-source-interface').value = config.interface;
  $('vpn-source-address').value = config.source;
  $('vpn-source-dns-enabled').checked = !!config.dns;
  $('vpn-source-gate').textContent = gateNote(config.dns);
  $('vpn-source-error').textContent = '';
  $('vpn-source-dialog').showModal();
}

async function saveConfig(event) {
  event.preventDefault();
  if (vpn.busy) return;
  vpn.busy = true;
  $('vpn-source-submit').disabled = true;
  $('vpn-source-error').textContent = '';
  try {
    applyManaged(await postJSON(API + '/config/edit', {
      interface: $('vpn-source-interface').value,
      source: $('vpn-source-address').value,
      dns: $('vpn-source-dns-enabled').checked ? {} : null,
    }));
    $('vpn-source-dialog').close();
    await load();
  } catch (err) {
    $('vpn-source-error').textContent = err.message;
  } finally {
    vpn.busy = false;
    $('vpn-source-submit').disabled = false;
  }
}

async function configAction(action, config, question) {
  if (vpn.busy || (question && !confirm(question))) return;
  vpn.busy = true;
  $('vpn-configs-message').textContent = '';
  try {
    applyManaged(await postJSON(API + '/config/' + action, { interface: config.interface }));
    await load();
  } catch (err) {
    $('vpn-configs-message').textContent = err.message;
  } finally {
    vpn.busy = false;
  }
}

async function addConfig(event) {
  event.preventDefault();
  if (vpn.busy) return;
  vpn.busy = true;
  $('vpn-config-submit').disabled = true;
  $('vpn-config-error').textContent = '';
  try {
    applyManaged(await postJSON(API + '/config', {
      name: $('vpn-config-name').value,
      source: $('vpn-config-source').value,
      text: $('vpn-config-text').value,
      exit_via: $('vpn-config-exit-via').value,
      after_up: $('vpn-config-after-up').value,
      before_down: $('vpn-config-before-down').value,
      dns: $('vpn-config-dns-enabled').checked ? {} : null,
    }));
    $('vpn-config-form').reset();
    $('vpn-config-dialog').close();
    await load();
  } catch (err) {
    $('vpn-config-error').textContent = err.message;
  } finally {
    vpn.busy = false;
    $('vpn-config-submit').disabled = false;
  }
}

/* A standard .conf file fills the form; the name comes from the file unless one was typed.
   The parsing stays in vpp-wireguard, which says which line is wrong. */
const configFileLimit = 64 << 10;

async function importConfigFile(file) {
  $('vpn-config-error').textContent = '';
  if (!file) return;
  if (/\.zip$/i.test(file.name)) {
    $('vpn-config-error').textContent = '这是压缩包，请先解压，再一次导入一个 .conf 文件。';
    return;
  }
  if (file.size > configFileLimit) {
    $('vpn-config-error').textContent = `${file.name} 太大了，WireGuard 配置文件一般只有几百字节。`;
    return;
  }
  const text = (await file.text()).replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n');
  if (!/^\s*\[interface\]\s*$/im.test(text)) {
    $('vpn-config-error').textContent = `${file.name} 里没有 [Interface]，不是 WireGuard 配置文件。`;
    return;
  }
  $('vpn-config-text').value = text.trim() + '\n';
  const name = $('vpn-config-name');
  if (!name.value.trim() || name.value === vpn.importedName) {
    name.value = vpn.importedName = file.name.replace(/\.(conf|txt)$/i, '').slice(0, 64);
  }
}

function openConfigDialog() {
  $('vpn-config-error').textContent = '';
  if (vpn.state && !$('vpn-config-source').value) $('vpn-config-source').value = vpn.state.default_source || '';
  $('vpn-config-gate').textContent = gateNote();
  if (!$('vpn-config-dialog').open) $('vpn-config-dialog').showModal();
}

function render(report) {
  vpn.report = report;
  const peers = report.wireguard || [];
  const clients_ = peers.filter(peer => !peer.upstream);
  const online = clients_.filter(peer => peer.online).length;
  const limited = peers.some(peer => peer.limited);
  $('vpn-wg-summary').textContent = report.wireguard_error || (limited ? `${clients_.length} 个客户端。这个 VPP 没有 wg show，不显示在线状态、握手和流量。` : `${clients_.length} 个客户端，${online} 个在线`);
  $('vpn-wg-summary').classList.toggle('error', !!report.wireguard_error);
  $('vpn-wg').hidden = !!report.wireguard_error;
  fillBody($('vpn-wg').tBodies[0], peers.length, (row, i) => {
    const peer = peers[i];
    setCells(row, [
      peer.upstream ? '上游隧道' : peer.limited ? '—' : peer.online ? '● 在线' : '○ 离线',
      peer.name || shortKey(peer.public_key),
      peer.interface,
      peer.allowed_ips.join(' '),
      peer.endpoint && !peer.endpoint.startsWith('0.0.0.0') ? peer.endpoint : '—',
      peer.limited ? '—' : handshake(peer.handshake_seconds),
      peer.limited ? '—' : bytes(peer.rx_bytes),
      peer.limited ? '—' : bytes(peer.tx_bytes),
      ...(vpn.manageable ? [labels(peerActions(peer))] : []),
    ]);
    if (vpn.manageable) actionCell(row.lastChild, peerActions(peer));
    row.children[0].className = peer.upstream ? 'offline' : peer.online ? 'online' : 'offline';
    row.children[1].title = peer.public_key;
  });

  renderConfigs();

  const clients = report.ipsec || [];
  $('vpn-ipsec-summary').textContent = report.ipsec_error || `${clients.length} 个客户端在线`;
  $('vpn-ipsec-summary').classList.toggle('error', !!report.ipsec_error);
  $('vpn-ipsec').hidden = !!report.ipsec_error || clients.length === 0;
  fillBody($('vpn-ipsec').tBodies[0], clients.length, (row, i) => {
    const client = clients[i];
    setCells(row, [
      client.eap_identity || client.identity,
      client.connection,
      client.virtual_ips.join(' '),
      client.remote,
      client.established_seconds < 0 ? '—' : duration(client.established_seconds),
      client.has_counters ? bytes(client.bytes_in) : '—',
      client.has_counters ? bytes(client.bytes_out) : '—',
    ]);
  });
}

function applyManaged(state) {
  vpn.state = state.configs ? state : null;
  $('vpn-configs-card').hidden = !vpn.state;
  renderConfigs();
  vpn.managed = new Set(state.peers.map(peerID));
  vpn.manageable = state.interfaces.length > 0;
  $('vpn-wg-add').hidden = !vpn.manageable;
  $('vpn-wg-actions').hidden = !vpn.manageable;
  $('vpn-wg-interface').replaceChildren(...state.interfaces.map(iface => {
    const option = document.createElement('option');
    option.value = iface.name;
    option.textContent = `${iface.name} (${iface.addresses.join(' ')})`;
    return option;
  }));
}

/* Peers stay visible when the admin service is absent; only the controls go. */
async function loadManaged() {
  try {
    applyManaged(await fetchJSON(API));
  } catch {
    applyManaged({ peers: [], interfaces: [] });
    $('vpn-config-source').value = '';
  }
  if (vpn.report) render(vpn.report);
}

async function removePeer(peer) {
  if (vpn.busy) return;
  const label = `${peer.name || peer.public_key}（${peer.interface}）`;
  if (!confirm(`删除 WireGuard 节点 ${label}？\n\n它会马上断开，如果你正通过它连接，面板也会断开。`)) return;
  vpn.busy = true;
  $('vpn-wg-message').textContent = '';
  try {
    applyManaged(await postJSON(API + '/peer/delete', { interface: peer.interface, public_key: peer.public_key }));
    await load();
  } catch (err) {
    $('vpn-wg-message').textContent = err.message;
  } finally {
    vpn.busy = false;
  }
}

async function addPeer(event) {
  event.preventDefault();
  if (vpn.busy) return;
  vpn.busy = true;
  $('vpn-wg-submit').disabled = true;
  $('vpn-wg-error').textContent = '';
  try {
    applyManaged(await postJSON(API + '/peer', {
      interface: $('vpn-wg-interface').value,
      public_key: $('vpn-wg-key').value.trim(),
      name: $('vpn-wg-name').value,
      allowed_ips: $('vpn-wg-addresses').value.split(/[\s,，]+/).filter(Boolean),
    }));
    $('vpn-wg-form').reset();
    $('vpn-wg-dialog').close();
    await load();
  } catch (err) {
    $('vpn-wg-error').textContent = err.message;
  } finally {
    vpn.busy = false;
    $('vpn-wg-submit').disabled = false;
  }
}

async function load() {
  try {
    render(await fetchJSON('api/vpn'));
  } catch (err) {
    $('vpn-wg-summary').textContent = err.message;
    $('vpn-wg-summary').classList.add('error');
  }
}

export function show() {
  $('vpn-wg-add').onclick = () => { $('vpn-wg-error').textContent = ''; $('vpn-wg-dialog').showModal(); };
  $('vpn-wg-form').onsubmit = addPeer;
  $('vpn-config-add').onclick = openConfigDialog;
  /* The picker opens in the same click, so the browser still counts it as the user's. */
  $('vpn-config-import').onclick = () => { openConfigDialog(); $('vpn-config-file').click(); };
  $('vpn-config-pick').onclick = () => $('vpn-config-file').click();
  $('vpn-config-file').onchange = event => {
    importConfigFile(event.target.files[0]).catch(err => { $('vpn-config-error').textContent = err.message; });
    event.target.value = '';
  };
  const area = $('vpn-config-text');
  area.ondragover = event => {
    if (!event.dataTransfer.types.includes('Files')) return;
    event.preventDefault();
    area.classList.add('dropping');
  };
  area.ondragleave = () => area.classList.remove('dropping');
  area.ondrop = event => {
    area.classList.remove('dropping');
    if (!event.dataTransfer.files.length) return;
    event.preventDefault();
    importConfigFile(event.dataTransfer.files[0]).catch(err => { $('vpn-config-error').textContent = err.message; });
  };
  $('vpn-config-form').onsubmit = addConfig;
  $('vpn-source-form').onsubmit = saveConfig;
  loadManaged();
  load();
  clearInterval(vpn.timer);
  vpn.timer = setInterval(() => { if (!document.hidden) load(); }, 10000);
}

export function hide() {
  clearInterval(vpn.timer);
}
