/* Firewall: what VPP lets in from its WAN. IPv4 port forwards and ports open to VPP itself are
   NAT44-EI mappings; ping and the IPv6 inbound firewall are an ACL on the WAN. vpp-firewall
   applies each change at once and puts it all back after VPP restarts. */
import { $, fetchJSON, postJSON, fillBody } from '../lib.js';

const API = 'api/firewall';
const page = { state: null, timer: 0, busy: false };
const PROTO = { tcp: 'TCP', udp: 'UDP', both: 'TCP+UDP', any: '全部' };

function message(text, isError) {
  $('fw-message').textContent = text || '';
  $('fw-message').classList.toggle('error', !!isError);
}

async function load() {
  try {
    page.state = await fetchJSON(API);
    $('fw-content').hidden = false;
    $('fw-unavailable').hidden = true;
  } catch (err) {
    $('fw-content').hidden = true;
    $('fw-unavailable').hidden = false;
    $('fw-unavailable').textContent = '无法读取防火墙：' + err.message;
    return;
  }
  render();
}

async function apply(path, body, description) {
  if (page.busy) return false;
  if (description && !confirm(`${description}\n\n立即生效，VPP 重启后自动恢复。`)) return false;
  page.busy = true;
  message('正在应用…');
  try {
    page.state = await postJSON(`${API}/${path}`, body);
    message('');
    return true;
  } catch (err) {
    message(err.message, true);
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

/* Value cells, then one cell for the action. */
function row(tr, values, action) {
  const count = values.length + 1;
  while (tr.children.length < count) tr.append(document.createElement('td'));
  while (tr.children.length > count) tr.lastChild.remove();
  values.forEach((value, i) => { if (tr.children[i].textContent !== value) tr.children[i].textContent = value; });
  tr.lastChild.replaceChildren(...(action ? [action] : []));
}

const ports = (first, last) => last ? `${first}-${last}` : String(first);

/* "8080" or "8000-8010". */
function parsePorts(text) {
  const match = text.trim().match(/^(\d+)(?:\s*[-~～]\s*(\d+))?$/);
  if (!match) return null;
  return { port: Number(match[1]), last: match[2] ? Number(match[2]) : 0 };
}

function removeButton(item, what) {
  if (item.other) return null;
  return button('删除', () => apply('delete', { id: item.id }, `删除${what}`), page.busy);
}

function renderSwitches() {
  const s = page.state;
  const rows = [
    {
      name: 'WAN 上的 ping', state: s.allow_ping ? '响应' : '不响应', action: s.allow_ping ? '不响应' : '响应',
      help: '关闭后不回应从 WAN 来的 ping（IPv4 和 IPv6，包括局域网主机的 IPv6 地址）。',
      toggle: () => apply('ping', { allow: !s.allow_ping }, s.allow_ping ? '不再响应 WAN 上的 ping' : '恢复响应 WAN 上的 ping'),
    },
    {
      name: 'IPv6 入站防火墙', state: s.ipv6_firewall ? (s.acl_applied ? '开启' : '开启（未生效）') : '关闭', action: s.ipv6_firewall ? '关闭' : '开启',
      help: '开启后从 WAN 进来的 IPv6 只放行：局域网主动发起连接的回程、必需的 ICMPv6、DHCPv6、路由器本机端口和下面的放行规则。WAN 上的 IPv4 包也要多查一次 ACL（N1 上每包约 0.36 微秒）。',
      toggle: () => apply('ipv6', { enable: !s.ipv6_firewall }, s.ipv6_firewall
        ? '关闭 IPv6 入站防火墙：WAN 上的任何主机都能直接连到局域网主机的 IPv6 地址'
        : '开启 IPv6 入站防火墙：WAN 上不请自来的 IPv6 连接都被丢弃'),
    },
  ];
  fillBody($('fw-switches').tBodies[0], rows.length, (tr, i) => {
    const item = rows[i];
    row(tr, ['', item.state], button(item.action, item.toggle, page.busy || !s.acl || !s.wan.length));
    const name = document.createElement('strong');
    name.textContent = item.name;
    const help = document.createElement('small');
    help.className = 'switch-help';
    help.textContent = item.help;
    tr.firstChild.replaceChildren(name, help);
  });
}

function renderTables() {
  const s = page.state;
  const forwards = s.forwards;
  $('fw-forwards-empty').hidden = forwards.length > 0;
  fillBody($('fw-forwards').tBodies[0], forwards.length, (tr, i) => {
    const f = forwards[i];
    const inside = f.last_port ? `${f.internal_ip}:${ports(f.internal_port, f.internal_port + f.last_port - f.external_port)}` : `${f.internal_ip}:${f.internal_port}`;
    row(tr, [(f.name || '—') + (f.other ? '（其他程序）' : ''), PROTO[f.protocol] || f.protocol, f.interface, ports(f.external_port, f.last_port), inside + (f.problem ? `（${f.problem}）` : '')],
      removeButton(f, `端口转发 ${PROTO[f.protocol]} ${ports(f.external_port, f.last_port)} → ${inside}`));
  });
  const list = s.ports;
  $('fw-ports-empty').hidden = list.length > 0;
  fillBody($('fw-ports').tBodies[0], list.length, (tr, i) => {
    const p = list[i];
    row(tr, [p.name || '—', PROTO[p.protocol] || p.protocol, p.interface, ports(p.port, p.last_port), (p.other ? '其他程序' : '防火墙') + (p.problem ? `（${p.problem}）` : '')],
      removeButton(p, `本机端口 ${PROTO[p.protocol]} ${ports(p.port, p.last_port)}`));
  });
  const rules = s.ipv6_rules;
  $('fw-ipv6-empty').hidden = rules.length > 0;
  fillBody($('fw-ipv6').tBodies[0], rules.length, (tr, i) => {
    const r = rules[i];
    row(tr, [r.name || '—', PROTO[r.protocol] || r.protocol, r.address, r.protocol === 'any' ? '全部' : ports(r.port, r.last_port)],
      removeButton(r, `IPv6 放行 ${r.address} ${r.protocol === 'any' ? '' : ports(r.port, r.last_port)}`));
  });
  $('fw-ipv6-help').textContent = s.ipv6_firewall
    ? '允许 WAN 上的主机连到局域网主机的这些 IPv6 地址和端口。地址写主机的完整地址或一个前缀；运营商换了委派前缀后，写死的地址要跟着改。'
    : 'IPv6 入站防火墙没有开启，现在所有 IPv6 入站连接都能进来；这些规则在开启后才起作用。';
}

function fillSelect(select, names) {
  const keep = select.value;
  select.replaceChildren(...names.map(name => new Option(name, name)));
  if (names.includes(keep)) select.value = keep;
}

function render() {
  const s = page.state;
  if (!s) return;
  const problems = [];
  if (s.vpp_error) problems.push('读取 VPP 失败：' + s.vpp_error);
  if (s.apply_error) problems.push('应用规则出错：' + s.apply_error);
  if (s.wan_missing && s.wan_missing.length) problems.push('配置的 WAN 接口不在：' + s.wan_missing.join('、'));
  if (!s.vpp_error && !s.wan.length) problems.push('没有 WAN 接口：在接口页把上行口设为出口（NAT）后才能使用。');
  if (!s.vpp_error && !s.acl) problems.push('VPP 没有加载 acl 插件，ping 和 IPv6 防火墙不能用。');
  $('fw-error').hidden = problems.length === 0;
  $('fw-error').textContent = problems.join(' ');
  $('fw-wan').textContent = s.wan.length ? s.wan.map(w => `${w.name}（${w.addresses.join('、') || '没有地址'}）`).join('，') + (s.wan_fixed ? '，在配置文件里指定' : '，即 NAT 出口') : '无';
  renderSwitches();
  renderTables();
  const names = s.wan.map(w => w.name);
  fillSelect($('fwd-iface'), names);
  fillSelect($('port-iface'), names);
  if (s.networks.length && !$('fwd-ip').placeholder) $('fwd-ip').placeholder = `比如 ${s.networks[0].prefix.replace(/\.\d+\/\d+$/, '.10')}`;
  for (const id of ['fwd-add', 'port-add', 'v6-add']) $(id).disabled = page.busy || !!s.vpp_error;
  $('fwd-add').disabled ||= !s.nat || !names.length;
  $('port-add').disabled ||= !s.nat || !names.length;
}

function addForward() {
  const range = parsePorts($('fwd-port').value);
  if (!range) { message('外部端口写一个端口或端口段，比如 8080 或 8000-8010', true); return; }
  const body = {
    name: $('fwd-name').value.trim(), protocol: $('fwd-proto').value, interface: $('fwd-iface').value,
    external_port: range.port, last_port: range.last, internal_ip: $('fwd-ip').value.trim(), internal_port: Number($('fwd-local-port').value || 0),
  };
  const inside = `${body.internal_ip}:${body.internal_port || range.port}`;
  apply('forward', body, `把 ${body.interface} 的 ${PROTO[body.protocol]} ${ports(range.port, range.last)} 转发到 ${inside}${range.last ? ' 起' : ''}`).then(done => {
    if (done) for (const id of ['fwd-name', 'fwd-port', 'fwd-ip', 'fwd-local-port']) $(id).value = '';
  });
}

function addPort() {
  const range = parsePorts($('port-port').value);
  if (!range) { message('端口写一个端口或端口段，比如 51820 或 5000-5010', true); return; }
  const body = { name: $('port-name').value.trim(), protocol: $('port-proto').value, interface: $('port-iface').value, port: range.port, last_port: range.last };
  apply('port', body, `在 ${body.interface} 上给路由器本机开放 ${PROTO[body.protocol]} ${ports(range.port, range.last)}`).then(done => {
    if (done) for (const id of ['port-name', 'port-port']) $(id).value = '';
  });
}

function addIPv6() {
  const protocol = $('v6-proto').value;
  const body = { name: $('v6-name').value.trim(), protocol, address: $('v6-address').value.trim() };
  if (protocol !== 'any') {
    const range = parsePorts($('v6-port').value);
    if (!range) { message('端口写一个端口或端口段，比如 443 或 8000-8100', true); return; }
    body.port = range.port;
    body.last_port = range.last;
  }
  apply('ipv6/rule', body, `允许从 WAN 连到 ${body.address} 的 ${PROTO[protocol]}${protocol === 'any' ? '' : ' ' + ports(body.port, body.last_port)}`).then(done => {
    if (done) for (const id of ['v6-name', 'v6-address', 'v6-port']) $(id).value = '';
  });
}

export function start() {
  $('fwd-add').onclick = addForward;
  $('port-add').onclick = addPort;
  $('v6-add').onclick = addIPv6;
  $('v6-proto').onchange = () => { $('v6-port').disabled = $('v6-proto').value === 'any'; };
}

export function show() {
  load();
  clearInterval(page.timer);
  page.timer = setInterval(() => {
    /* Do not refresh the forms out from under the typing. */
    if (document.hidden || page.busy || document.activeElement?.closest?.('#page-firewall .form-row')) return;
    load();
  }, 5000);
}

export function hide() {
  clearInterval(page.timer);
}
