/* The sing-box proxy entry: its state, its upstream set up with a wizard, and nodes imported from
   sing-box configurations, share links and subscriptions. Changes go through vpp-proxy, which
   checks the configuration, restarts sing-box and puts the old upstream back if it fails. */
import { $, fetchJSON, postJSON, fillBody, setCells } from '../lib.js';

const API = 'api/proxy';
const page = { state: null, timer: 0, busy: false, imported: [], editing: null, subURL: '' };

/* The fields each protocol has, besides server and port. */
const FIELDS = {
  socks: ['username', 'password'], http: ['username', 'password'], shadowsocks: ['method', 'password'],
  vmess: ['uuid', 'security', 'alter_id'], vless: ['uuid', 'flow'], trojan: ['password'],
  hysteria2: ['password', 'obfs', 'up_mbps', 'down_mbps'], tuic: ['uuid', 'password', 'congestion'], anytls: ['password'],
  wireguard: ['address', 'private_key', 'peer_public_key', 'pre_shared_key', 'allowed_ips', 'mtu'],
};
const SECRETS = ['password', 'uuid', 'private_key', 'pre_shared_key', 'obfs'];
const NUMBERS = ['alter_id', 'up_mbps', 'down_mbps', 'mtu'];
const LISTS = ['address', 'allowed_ips'];
const INBOUNDS = {
  'lan-socks': '局域网 SOCKS5，设备手动设置代理时用',
  tproxy: 'Gate 代理规则的透明代理（TPROXY），真实地址和 Fake-IP 地址都从这里进',
  'fake-dns': 'Gate 代理规则的 Fake-IP DNS',
};

function message(text, isError) {
  $('proxy-message').textContent = text || '';
  $('proxy-message').classList.toggle('error', !!isError);
}

const protocolName = type => (page.state && page.state.options.protocols[type]) || type;
const serverText = node => node.type === 'wireguard' || !node.server ? node.server || '—' : `${node.server}:${node.port}`;

async function load() {
  try {
    page.state = await fetchJSON(API);
    $('proxy-content').hidden = false;
    $('proxy-unavailable').hidden = true;
  } catch (err) {
    $('proxy-content').hidden = true;
    $('proxy-unavailable').hidden = false;
    $('proxy-unavailable').textContent = '无法读取代理状态：' + err.message;
    return;
  }
  render();
}

async function act(path, body, text, question) {
  if (page.busy) return null;
  if (question && !confirm(question)) return null;
  page.busy = true;
  message(text);
  try {
    const result = await postJSON(`${API}/${path}`, body || {});
    message('');
    return result;
  } catch (err) {
    message(err.message, true);
    return null;
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

function span(className, text) {
  const element = document.createElement('span');
  element.className = className;
  element.textContent = text;
  return element;
}

/* The upstream in use, set apart: its name first, then how it is reached. */
function renderUpstream(state) {
  const host = $('proxy-upstream');
  let parts;
  if (state.upstream === 'wizard' && state.profile) {
    const p = state.profile;
    const server = serverText(p);
    parts = [span('caption', '当前上游'), span('name', p.name || server), boxOf(span('tag', protocolName(p.type)), span('', server))];
  } else if (state.upstream === 'custom') {
    parts = [span('caption', '当前上游'), span('name', '自定义（手写的 upstream.json）'), boxOf(span('', state.custom.join('；'))),
      span('caption', '用“编辑上游”应用后会替换它，原文件另存为 upstream.json.bak。')];
  } else {
    parts = [span('caption', '当前上游'), span('name', '还没有配置上游，发到代理入口的流量都会被拒绝。')];
  }
  const signature = JSON.stringify([state.upstream, state.profile, state.custom]);
  host.classList.toggle('none', state.upstream !== 'wizard' && state.upstream !== 'custom');
  if (host.dataset.signature === signature) return;
  host.dataset.signature = signature;
  host.replaceChildren(...parts);
}

function boxOf(...children) {
  const box = document.createElement('span');
  box.className = 'detail';
  box.append(...children);
  return box;
}

function render() {
  const state = page.state;
  if (!state) return;
  if (!state.installed) {
    $('proxy-status').textContent = '没有安装 sing-box。用安装脚本安装时选择“安装 sing-box”。';
    for (const id of ['proxy-start', 'proxy-stop', 'proxy-restart', 'proxy-edit', 'proxy-clear', 'proxy-test-current']) $(id).disabled = true;
    return;
  }
  $('proxy-status').textContent = `${state.running ? '● 运行中' : '○ 已停止'}，sing-box ${state.version || ''}`;
  $('proxy-status').className = 'note section-help ' + (state.running ? 'online' : 'offline');
  $('proxy-start').disabled = page.busy || state.running;
  $('proxy-stop').disabled = page.busy || !state.running;
  $('proxy-restart').disabled = page.busy || !state.running;
  fillBody($('proxy-inbounds').tBodies[0], state.inbounds.length, (row, i) => {
    const inbound = state.inbounds[i];
    const host = inbound.listen.includes(':') ? `[${inbound.listen}]` : inbound.listen;
    setCells(row, [inbound.tag, `${inbound.type} ${host}:${inbound.port}`, INBOUNDS[inbound.tag] || '']);
  });
  renderUpstream(state);
  $('proxy-test-current').disabled = page.busy || state.upstream === 'none';
  const hasUpstream = state.upstream === 'wizard' || state.upstream === 'custom';
  $('proxy-edit').disabled = page.busy;
  $('proxy-edit').textContent = hasUpstream ? '编辑上游' : '设置上游';
  $('proxy-clear').disabled = page.busy || !hasUpstream;
  $('proxy-import-clear').disabled = page.busy || (!page.imported.length && !$('proxy-import-text').value);
  renderNodes($('proxy-import-nodes'), page.imported, (node, i) => [
    button('测试', () => testProfile(node), page.busy),
    button('填入向导', () => openWizard(node), page.busy),
    button('移除', () => { page.imported.splice(i, 1); render(); }, page.busy),
  ]);
  const sub = state.subscription;
  $('proxy-sub-update').disabled = page.busy || !sub;
  $('proxy-sub-delete').disabled = page.busy || !sub;
  /* The saved address goes in the box when it changes, not every time the page refreshes, so
     the box can be edited or emptied. */
  const subURL = sub ? sub.url : '';
  if (subURL !== page.subURL) {
    page.subURL = subURL;
    $('proxy-sub-url').value = subURL;
  }
  $('proxy-sub-info').textContent = '';
  if (sub) {
    $('proxy-sub-info').textContent = `${sub.nodes.length} 个节点，${new Date(sub.fetched).toLocaleString()} 获取${sub.using ? `，正在用 ${sub.using}` : ''}。节点的密码保存在路由器上，“使用”直接应用；要修改就先用再“编辑上游”。`;
  }
  renderNodes($('proxy-sub-nodes'), sub ? sub.nodes : [], (node, i) => [
    button('测试', () => testSubscription(i), page.busy),
    button(sub && sub.using === node.name ? '正在用' : '使用', () => act('subscription/use', { index: i }, `正在应用 ${node.name || serverText(node)}…`).then(r => { if (r) page.state = r; }), page.busy),
  ]);
}

function renderNodes(table, nodes, actions) {
  table.hidden = !nodes.length;
  fillBody(table.tBodies[0], nodes.length, (row, i) => {
    const node = nodes[i];
    setCells(row, [node.name || '—', protocolName(node.type), serverText(node), node.ignored ? '会忽略：' + node.ignored.join('、') : '', '']);
    if (!row.dataset.result) row.children[3].className = '';
    const cell = row.lastChild;
    cell.textContent = '';
    const box = document.createElement('span');
    box.className = 'row-actions';
    box.append(...actions(node, i));
    cell.append(box);
  });
}

function showResult(element, result) {
  element.textContent = (result.ok ? '✓ 通：' : '✕ 不通：') + result.message;
  element.className = 'note ' + (result.ok ? 'ok' : 'error');
}

async function testProfile(node) {
  const result = await act('test', { profile: node }, `正在测试 ${node.name || serverText(node)}…`);
  if (result) {
    message(`${node.name || serverText(node)}：${result.ok ? '通，' : '不通，'}${result.message}`, !result.ok);
  }
}

async function testSubscription(index) {
  const node = page.state.subscription.nodes[index];
  const result = await act('subscription/test', { index }, `正在测试 ${node.name}…`);
  if (result) message(`${node.name}：${result.ok ? '通，' : '不通，'}${result.message}`, !result.ok);
}

/* The wizard. */

function setOptions(select, values, labels = values) {
  if (select.dataset.filled) return;
  select.textContent = '';
  values.forEach((value, i) => {
    const option = document.createElement('option');
    option.value = value;
    option.textContent = labels[i];
    select.append(option);
  });
  select.dataset.filled = '1';
}

function fillChoices() {
  const options = page.state.options;
  const types = Object.keys(options.protocols);
  setOptions($('pf-type'), types, types.map(type => options.protocols[type]));
  setOptions($('pf-method'), options.methods);
  setOptions($('pf-fingerprint'), ['', ...options.fingerprints], ['无', ...options.fingerprints]);
}

function openWizard(profile) {
  fillChoices();
  const p = profile || { type: 'socks', tls: {}, transport: {} };
  page.editing = p;
  const current = page.state.profile;
  const sameAsSaved = current && current.type === p.type && current.server === p.server && current.port === p.port;
  $('pf-type').value = p.type || 'socks';
  $('pf-name').value = p.name || '';
  $('pf-server').value = p.server || '';
  $('pf-port').value = p.port || '';
  for (const fields of Object.values(FIELDS)) {
    for (const field of fields) {
      const value = p[field];
      $('pf-' + field).value = LISTS.includes(field) ? (value || []).join(', ') : value ?? (NUMBERS.includes(field) ? '' : '');
    }
  }
  const tls = p.tls || {}, transport = p.transport || {};
  $('pf-tls').checked = !!tls.enabled;
  $('pf-sni').value = tls.server_name || '';
  $('pf-insecure').checked = !!tls.insecure;
  $('pf-alpn').value = (tls.alpn || []).join(', ');
  $('pf-fingerprint').value = tls.fingerprint || '';
  $('pf-reality').checked = !!tls.reality;
  $('pf-public_key').value = tls.public_key || '';
  $('pf-short_id').value = tls.short_id || '';
  $('pf-transport').value = transport.type || '';
  $('pf-path').value = transport.path || '';
  $('pf-host').value = transport.host || '';
  $('pf-service_name').value = transport.service_name || '';
  /* Lists start on their defaults where the node does not say. */
  if (!p.security) $('pf-security').value = 'auto';
  if (!p.congestion) $('pf-congestion').value = 'bbr';
  if (!p.method) $('pf-method').selectedIndex = 0;
  $('pf-secret-note').hidden = !(profile === current && sameAsSaved && page.state.secrets_set.length);
  $('pf-ignored').hidden = !(p.ignored && p.ignored.length);
  $('pf-ignored').textContent = p.ignored ? '向导表达不了这些设置，应用时会忽略：' + p.ignored.join('、') : '';
  $('pf-error').textContent = '';
  $('pf-test-result').textContent = '';
  renderWizard();
  $('proxy-dialog').showModal();
}

function renderWizard() {
  const options = page.state.options;
  const type = $('pf-type').value;
  const fields = FIELDS[type] || [];
  for (const label of document.querySelectorAll('#proxy-dialog [data-field]')) label.hidden = !fields.includes(label.dataset.field);
  $('pf-server-label').firstChild.textContent = type === 'wireguard' ? '对端地址 ' : '服务器 ';
  const tlsUse = options.tls[type];
  $('pf-tls-part').hidden = tlsUse === 'off';
  $('pf-tls-toggle').hidden = tlsUse !== 'optional';
  const tlsOn = tlsUse === 'on' || $('pf-tls').checked;
  $('pf-tls-fields').hidden = !tlsOn;
  $('pf-reality-part').hidden = type !== 'vless';
  for (const label of document.querySelectorAll('#proxy-dialog [data-reality]')) label.hidden = !$('pf-reality').checked;
  $('pf-transport-part').hidden = !options.transport[type];
  const transport = $('pf-transport').value;
  for (const label of document.querySelectorAll('#proxy-dialog [data-transport]')) label.hidden = !label.dataset.transport.split(' ').includes(transport);
}

function readWizard() {
  const type = $('pf-type').value;
  const words = text => text.split(/[\s,，]+/).filter(Boolean);
  const p = { type, name: $('pf-name').value.trim(), server: $('pf-server').value.trim(), port: Number($('pf-port').value) || 0, tls: {}, transport: {} };
  for (const field of FIELDS[type] || []) {
    const value = $('pf-' + field).value.trim();
    if (LISTS.includes(field)) p[field] = words(value);
    else if (NUMBERS.includes(field)) p[field] = Number(value) || 0;
    else p[field] = value;
  }
  const tlsUse = page.state.options.tls[type];
  if (tlsUse !== 'off' && (tlsUse === 'on' || $('pf-tls').checked)) {
    p.tls = { enabled: true, server_name: $('pf-sni').value.trim(), insecure: $('pf-insecure').checked, alpn: words($('pf-alpn').value), fingerprint: $('pf-fingerprint').value };
    if (type === 'vless' && $('pf-reality').checked) Object.assign(p.tls, { reality: true, public_key: $('pf-public_key').value.trim(), short_id: $('pf-short_id').value.trim() });
  }
  if (page.state.options.transport[type] && $('pf-transport').value) {
    p.transport = { type: $('pf-transport').value, path: $('pf-path').value.trim(), host: $('pf-host').value.trim(), service_name: $('pf-service_name').value.trim() };
  }
  return p;
}

async function wizardTest() {
  $('pf-error').textContent = '';
  $('pf-test-result').textContent = '正在测试…';
  $('pf-test-result').className = 'note';
  try {
    showResult($('pf-test-result'), await postJSON(`${API}/test`, { profile: readWizard() }));
  } catch (err) {
    $('pf-test-result').textContent = '';
    $('pf-error').textContent = err.message;
  }
}

async function wizardApply() {
  const p = readWizard();
  if (!confirm(`把上游设为 ${protocolName(p.type)} ${serverText(p)}？\n\nsing-box 会重启，正在经过代理的连接会断开；新上游启动不起来时自动恢复原来的。`)) return;
  $('pf-error').textContent = '';
  const result = await act('apply', { profile: p }, '正在应用，sing-box 重启中…');
  if (result) {
    page.state = result;
    $('proxy-dialog').close();
    message(`上游已设为 ${protocolName(p.type)} ${serverText(p)}`);
    render();
  } else {
    $('pf-error').textContent = $('proxy-message').textContent;
  }
}

async function parseImport() {
  const picked = $('proxy-import-file').files[0];
  const text = picked ? await picked.text() : $('proxy-import-text').value;
  const kind = picked && /\.json$/i.test(picked.name) ? 'json' : $('proxy-import-kind').value;
  if (!text.trim()) { message('先粘贴内容或选择文件', true); return; }
  const result = await act('parse', { kind, text }, '正在解析…');
  if (result) {
    page.imported = result.nodes;
    $('proxy-import-file').value = '';
    $('proxy-import-text').value = '';
    message(`解析出 ${result.nodes.length} 个节点`);
    render();
  }
}

export function start() {
  $('proxy-start').onclick = () => act('start', {}, '正在启动…').then(r => { if (r) page.state = r; render(); });
  $('proxy-restart').onclick = () => act('restart', {}, '正在重启…').then(r => { if (r) page.state = r; render(); });
  $('proxy-stop').onclick = () => act('stop', {}, '正在停止…', '停止 sing-box？\n\nGate 代理规则的流量、局域网 SOCKS5 和透明代理都会中断，直到再次启动。').then(r => { if (r) page.state = r; render(); });
  $('proxy-test-current').onclick = async () => {
    $('proxy-test-result').textContent = '正在测试…';
    $('proxy-test-result').className = 'note';
    const result = await act('test', {}, '');
    if (result) showResult($('proxy-test-result'), result);
    else $('proxy-test-result').textContent = '';
  };
  $('proxy-edit').onclick = () => openWizard(page.state.profile);
  $('proxy-clear').onclick = () => act('clear', {}, '正在删除上游，sing-box 重启中…',
    '删除当前上游？\n\nupstream.json 换回占位配置（原文件另存为 upstream.json.bak），发到代理入口的流量都会被拒绝，直到再设置上游。sing-box 会重启。')
    .then(r => { if (r) { page.state = r; message('上游已删除'); $('proxy-test-result').textContent = ''; render(); } });
  $('proxy-import-clear').onclick = () => {
    page.imported = [];
    $('proxy-import-text').value = '';
    $('proxy-import-file').value = '';
    render();
  };
  $('proxy-import-text').oninput = () => render();
  $('proxy-sub-delete').onclick = () => act('subscription/delete', {}, '正在删除订阅…', '删除订阅和它的节点？\n\n正在用的上游不变。')
    .then(r => { if (r) { page.state = r; message('订阅已删除'); render(); } });
  for (const id of ['pf-type', 'pf-tls', 'pf-reality', 'pf-transport']) $(id).onchange = renderWizard;
  $('pf-test').onclick = wizardTest;
  $('pf-apply').onclick = wizardApply;
  $('proxy-import-parse').onclick = parseImport;
  $('proxy-sub-fetch').onclick = () => act('subscription', { url: $('proxy-sub-url').value.trim() }, '正在下载订阅…').then(r => { if (r) { page.state = r; message(`订阅里有 ${r.subscription.nodes.length} 个节点`); render(); } });
  $('proxy-sub-update').onclick = () => act('subscription/update', {}, '正在更新订阅…', '重新下载订阅，并按名字重新应用正在用的节点？').then(r => { if (r) page.state = r; render(); });
}

export function show() {
  load();
  clearInterval(page.timer);
  page.timer = setInterval(() => { if (!document.hidden && !page.busy && !$('proxy-dialog').open) load(); }, 5000);
}

export function hide() {
  clearInterval(page.timer);
}
