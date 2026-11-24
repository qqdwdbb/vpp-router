/* Rules, exits, priority and the domain and address list files. Every change goes through Gate's admin
   service: it restarts Gate, and is undone unless confirmed in time. */
import { $, si, fetchJSON, postJSON, fillBody, setCells } from '../lib.js';

const API = 'api/gate/';
const routes = { state: null, labels: new Map(), interfaces: [], leases: new Map(), routers6: new Map(), viaTyped: false, via6Typed: false, via6Exit: '', order: null, timer: 0, tick: 0, deadline: 0, busy: false, edit: null, addDnsTyped: false, addFiles: new Set(), addRanges: new Set(), file: null, add: new Set(), remove: new Set() };

function message(text, isError) {
  const host = $('routes-message');
  host.textContent = text || '';
  host.classList.toggle('error', !!isError);
  if ($('routes-edit-dialog').open) {
    $('routes-edit-message').textContent = text || '';
    $('routes-edit-message').classList.toggle('error', !!isError);
  }
}

const FAMILY = { 4: 'IPv4', 6: 'IPv6' };
const KIND = { domains: '域名表', ranges: '网段表' };
const FILE_TEXT = {
  domains: { existing: '现有域名', add: '添加域名', hint: '每行一个，会匹配该域名及其子域名' },
  ranges: { existing: '现有网段', add: '添加网段', hint: '每行一个地址、CIDR 或 起始IP-结束IP' },
};

/* Rules name exits as VPP does; requests keep that name, and only what is shown changes. */
const exitName = name => ({ tproxy: '代理（TPROXY）' }[name] || routes.labels.get(name) || name);
const exitNames = text => text.split('、').map(exitName).join('、');
const describeChange = text => text.replace(/出口 ([^\s，、]+)/g, (_, name) => '出口 ' + exitName(name));

async function loadLabels() {
  try {
    const status = await fetchJSON('api/status');
    routes.labels = new Map((status.interfaces || []).filter(row => row.label).map(row => [row.name, row.label]));
    routes.interfaces = (status.interfaces || []).filter(row => !row.hidden && row.name !== 'local0').map(row => row.name);
  } catch {
    /* VPP's names, or the last labels read, still identify the exits. */
  }
}

const RESTART_NOTE = '应用时会重启 Gate，局域网 DNS 会短暂中断。应用后 60 秒内需要确认，否则自动恢复。';

async function apply(path, body, description, note = RESTART_NOTE) {
  if (routes.busy) return false;
  if (note && !confirm(`${description}\n\n${note}`)) return false;
  routes.busy = true;
  message(note ? '正在应用，等待 Gate 重新启动…' : '正在保存…');
  try {
    routes.state = await postJSON(API + path, body);
    if (!note && routes.state.pending?.reload) {
      await postJSON(API + 'confirm', {});
      routes.state = await fetchJSON(API);
    }
    routes.order = null;
    message('');
    return true;
  } catch (err) {
    message(err.message, true);
    return false;
  } finally {
    routes.busy = false;
    render();
    load();
  }
}

async function act(path, text, body = {}) {
  if (routes.busy) return false;
  routes.busy = true;
  message(text);
  try {
    await postJSON(API + path, body);
    message('');
    return true;
  } catch (err) {
    message(err.message, true);
    return false;
  } finally {
    routes.busy = false;
    load();
  }
}

/* DHCP routers, to suggest as next hops; the interfaces service may well not be there. */
async function loadLeases() {
  try {
    const state = await fetchJSON('api/interfaces');
    routes.leases = new Map((state.interfaces || []).filter(row => row.dhcp_gateway).map(row => [row.name, row.dhcp_gateway]));
    routes.routers6 = new Map((state.interfaces || []).filter(row => row.ipv6_gateway).map(row => [row.name, row.ipv6_gateway]));
  } catch {
    routes.leases = new Map();
    routes.routers6 = new Map();
  }
}

async function load() {
  const labels = Promise.all([loadLabels(), loadLeases()]);
  try {
    routes.state = await fetchJSON(API + 'state');
    $('routes-content').hidden = false;
    $('routes-unavailable').hidden = true;
  } catch (err) {
    $('routes-content').hidden = true;
    $('routes-unavailable').hidden = false;
    $('routes-unavailable').textContent = '无法读取路由规则：' + err.message;
    return;
  }
  await labels;
  if (routes.state.pending) routes.deadline = Date.now() + routes.state.seconds_remaining * 1000;
  render();
}

function currentOrder() {
  const groups = routes.state.groups;
  if (!routes.order) return groups;
  const byId = new Map(groups.map(group => [group.id, group]));
  const ordered = routes.order.map(id => byId.get(id)).filter(Boolean);
  return ordered.length === groups.length ? ordered : groups;
}

function move(index, delta) {
  const ids = currentOrder().map(group => group.id);
  const target = index + delta;
  if (target < 0 || target >= ids.length) return;
  [ids[index], ids[target]] = [ids[target], ids[index]];
  routes.order = ids;
  render();
}

function orderChanged() {
  return !!routes.order && routes.order.join('\n') !== routes.state.groups.map(group => group.id).join('\n');
}

function button(text, onClick, disabled) {
  const element = document.createElement('button');
  element.className = 'close';
  element.textContent = text;
  element.onclick = onClick;
  element.disabled = !!disabled;
  return element;
}

function replaceCell(row, index, ...children) {
  const cell = row.children[index];
  cell.textContent = '';
  cell.append(...children);
}

function boxOf(...children) {
  const box = document.createElement('span');
  box.className = 'row-actions';
  box.append(...children);
  return box;
}

/* Everything no rule matches. Its exit is the system's routes unless one is chosen; then Gate
   sends it there while the exit is up, and back to the system's routes while it is not. */
const SYSTEM = '系统路由表';

function defaultExitText(fallback) {
  const { exit, status } = routes.state.default;
  if (!exit) return SYSTEM;
  const name = exitName(exit);
  if (!status) return name;
  const active = status.active || [];
  const families = status.families || [];
  if (families.length && active.length === families.length) return name;
  const lost = families.filter(f => !active.includes(f)).map(f => FAMILY[f] || f).join(' / ');
  const detail = status.problem ? `：${status.problem}` : '';
  return fallback ? `${name}（${lost} 未生效，回落到${SYSTEM}${detail}）` : name;
}

function renderDefaultRow(row, locked) {
  setCells(row, ['—', 'default', 'IPv4 / IPv6', defaultExitText(true), routes.state.default.dns, '其余全部', '']);
  row.children[3].title = '没有匹配规则的流量走这里。选了出口时，出口断开（接口不在或已停止）期间自动回落到系统路由表';
  replaceCell(row, 6, boxOf(button('编辑', () => openDefaultEdit(), locked)));
}

function renderGroups() {
  const state = routes.state;
  const locked = !!state.pending || routes.busy;
  const groups = currentOrder();
  fillBody($('routes-groups').tBodies[0], groups.length + 1, (row, i) => {
    /* The page refreshes every few seconds; do not pull a field out from under the typing. */
    if (row.contains(document.activeElement) && document.activeElement.matches('input, select')) return;
    if (i === groups.length) { renderDefaultRow(row, locked); return; }
    const group = groups[i];
    setCells(row, [String(i + 1), group.id, (group.families || []).map(f => FAMILY[f] || f).join(' / ') || '—', exitNames(group.exit), group.dns || '默认 DNS', `${si(group.domains)} / ${si(group.keywords)} / ${si(group.ranges)}`, '']);
    replaceCell(row, 6, boxOf(
      button('编辑', () => openEdit(group), locked),
      button('↑', () => move(i, -1), locked || i === 0),
      button('↓', () => move(i, 1), locked || i === groups.length - 1),
      button('删除', () => apply('rule/delete', { group: group.id }, `删除规则 ${group.id}（包含 ${group.rules.join('、')}）。域名表和网段表文件会保留。`), locked),
    ));
  });
  const changed = orderChanged();
  $('routes-save-order').hidden = !changed;
  $('routes-reset-order').hidden = !changed;
  $('routes-flush').disabled = locked;
  $('routes-save-order').disabled = locked;
}

function renderStats() {
  const { groups, routes: installed } = routes.state;
  const count = groups.reduce((sum, group) => sum + group.rules.length, 0);
  const summary = `规则 ${count} 条（${groups.length} 组）`;
  if (!installed) {
    $('routes-stats').textContent = `${summary}。路由数暂时读不到，Gate 可能正在重启。`;
    return;
  }
  const exits = installed.exits.map(exit => `${exitName(exit.name)} ${exit.routes}`).join('，');
  $('routes-stats').textContent = `${summary}。Gate 在 VPP 中安装的路由 ${installed.total} 条，其中静态网段和地址池 ${installed.static} 条，按域名学到 ${installed.learned} 条${exits ? `。按出口：${exits}` : ''}。`;
}

function renderFiles() {
  const files = routes.state.files;
  $('routes-files-empty').hidden = files.length > 0;
  fillBody($('routes-files').tBodies[0], files.length, (row, i) => {
    const file = files[i];
    const inUse = file.used_by.length > 0;
    setCells(row, [file.name, KIND[file.kind], file.problem ? '读取失败' : si(file.domains), inUse ? file.used_by.join('、') : '未使用', '']);
    const actions = document.createElement('span');
    actions.className = 'row-actions';
    const remove = button('删除', () => deleteFile(file), inUse || !!routes.state.pending || routes.busy);
    if (inUse) remove.title = '先删除或修改使用它的规则';
    const rename = button('改名', () => renameFile(file), !!file.problem || !!routes.state.pending || routes.busy);
    actions.append(button('编辑', () => openFile(file), !!file.problem), rename, remove);
    replaceCell(row, 4, actions);
  });
}

function renderPending() {
  const state = routes.state;
  const banner = $('routes-pending');
  banner.hidden = !state.pending;
  if (state.pending) {
    const seconds = Math.max(0, Math.ceil((routes.deadline - Date.now()) / 1000));
    $('routes-pending-text').textContent = `${describeChange(state.pending.description)}。已生效，${seconds} 秒内未确认将自动恢复。`;
  }
  const last = state.last;
  const OUTCOMES = { applied: '已保存', pending: '等待确认', confirmed: '已保留', 'rolled-back': '已恢复', refused: '被拒绝', 'rollback-failed': '恢复失败', flushed: '已完成', 'flush-failed': '失败' };
  $('routes-last').hidden = !last;
  if (last) {
    const outage = last.outage_ms ? `，DNS 中断 ${(last.outage_ms / 1000).toFixed(1)} 秒` : '';
    const detail = last.detail ? `（${last.detail}）` : '';
    $('routes-last').textContent = `最近一次：${describeChange(last.description)}：${OUTCOMES[last.outcome] || last.outcome}${outage}${detail}`;
    $('routes-last').classList.toggle('error', last.outcome === 'rollback-failed' || last.outcome === 'flush-failed');
  }
}

/* Exits, and their next hops. Only a VPP interface's can be set; Gate makes the others. An
   interface may carry several exits, told apart by name, each with next hops of its own. */
const exitInterface = exit => exit.interface || exit.name;
function renderExits() {
  const state = routes.state;
  const locked = !!state.pending || routes.busy;
  const exits = state.exits || [];
  fillBody($('routes-exits').tBodies[0], exits.length, (row, i) => {
    const exit = exits[i];
    const via4 = exit.dhcp ? 'DHCP 网关' : exit.via4 || (exit.editable ? '—' : exit.families.includes(4) ? '自动' : '—');
    const via6 = exit.via6 || (exit.editable ? '—' : exit.families.includes(6) ? '自动' : '—');
    /* One listener takes real addresses and Fake-IP ones; a rule's DNS decides which it sends. */
    const use = exit.tproxy_port ? `TPROXY :${exit.tproxy_port}（${exit.dns ? `Fake-IP DNS ${exit.dns}，` : ''}仅规则）` : exit.rules ? '规则、默认出口' : '只能做默认出口';
    const shared = exitInterface(exit) !== exit.name ? `（接口 ${exitName(exitInterface(exit))}）` : '';
    setCells(row, [exitName(exit.name) + shared + (exit.custom ? '（手动）' : ''), via4, via6, use, '']);
    const actions = [];
    if (exit.editable) actions.push(button('编辑', () => editExit(exit), locked));
    if (exit.custom) actions.push(button('删除', () => apply('exit/delete', { name: exit.name, interface: exitInterface(exit) }, `删除手动设置的出口 ${exitName(exit.name)}。`, '在用它的规则保留现在的下一跳，不重启 Gate。'), locked));
    replaceCell(row, 4, boxOf(...actions));
  });
  const known = new Set(exits.filter(exit => !exit.editable).map(exit => exit.name));
  setOptions($('exit-interface'), routes.interfaces.filter(name => !known.has(name)).map(name => ({ value: name, label: exitName(name) })));
  $('exit-via4').disabled = $('exit-dhcp').checked;
  $('exit-save').disabled = locked || !routes.interfaces.length;
}

function editExit(exit) {
  $('exit-interface').value = exitInterface(exit);
  $('exit-name').value = exitInterface(exit) !== exit.name ? exit.name : '';
  $('exit-via4').value = exit.via4 || '';
  $('exit-via6').value = exit.via6 || '';
  $('exit-dhcp').checked = !!exit.dhcp;
  renderExits();
  $('exit-via4').focus();
}

async function saveExit() {
  const iface = $('exit-interface').value;
  const name = $('exit-name').value.trim();
  const dhcp = $('exit-dhcp').checked;
  const via4 = dhcp ? '' : $('exit-via4').value.trim();
  const via6 = $('exit-via6').value.trim();
  const hops = [dhcp ? 'IPv4 用 DHCP 网关' : via4 && 'IPv4 ' + via4, via6 && 'IPv6 ' + via6].filter(Boolean).join('，');
  const title = name && name !== iface ? `出口 ${name}（接口 ${exitName(iface)}）` : `出口 ${exitName(iface)}`;
  if (await apply('exit', { name, interface: iface, via4, via6, dhcp }, `${title}：${hops || '没有下一跳'}。`,
    '有规则在用这个出口时，规则一起改，并重启 Gate（局域网 DNS 短暂中断），60 秒内需要确认；没有时直接保存。')) {
    $('exit-name').value = ''; $('exit-via4').value = ''; $('exit-via6').value = ''; $('exit-dhcp').checked = false;
  }
}

function render() {
  const hijack = routes.state.vpp_dns_hijack;
  $('routes-dns-hijack').checked = !!hijack?.enabled;
  $('routes-dns-hijack').disabled = !hijack?.available || !!routes.state.pending || routes.busy;
  $('routes-dns-hijack-status').textContent = hijack?.available
    ? (hijack.enabled ? '已开启' : '已关闭')
    : '尚未配置 VPP DNS 劫持的接口、来源网段或 Linux DNS 重定向。';
  if (!routes.state) return;
  $('routes-edit-save').disabled = routes.busy || !!routes.state.pending;
  renderPending();
  renderStats();
  renderGroups();
  renderExits();
  renderFiles();
  renderAddRule();
  if ($('routes-file-dialog').open) renderFileChanges();
}

/* Keeps what the person has picked when the list refreshes underneath the form. */
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

const RULE_FILE_PICKERS = {
  domains: { picker: 'rule-file-picker', summary: 'rule-file-summary', options: 'rule-file-options', selected: 'addFiles' },
  ranges: { picker: 'rule-ranges-picker', summary: 'rule-ranges-summary', options: 'rule-ranges-options', selected: 'addRanges' },
};

function selectedRuleFiles(kind) {
  return [...routes[RULE_FILE_PICKERS[kind].selected]];
}

function renderRuleFilePicker(kind) {
  const config = RULE_FILE_PICKERS[kind];
  const selected = routes[config.selected];
  const files = routes.state.files.filter(file => !file.problem && file.kind === kind);
  const available = new Set(files.map(file => file.path));
  for (const path of selected) if (!available.has(path)) selected.delete(path);
  const signature = files.map(file => `${file.path}|${file.name}|${file.domains}`).join('\n');
  const options = $(config.options);
  if (options.dataset.options !== signature) {
    options.textContent = '';
    if (!files.length) {
      const empty = document.createElement('span');
      empty.className = 'list-picker-empty';
      empty.textContent = `没有可用的${KIND[kind]}`;
      options.append(empty);
    }
    for (const file of files) {
      const label = document.createElement('label');
      label.className = 'list-picker-option';
      const box = document.createElement('input');
      box.type = 'checkbox';
      box.value = file.path;
      box.checked = selected.has(file.path);
      box.onchange = () => {
        if (box.checked) selected.add(file.path); else selected.delete(file.path);
        renderAddRule();
      };
      label.append(box, `${file.name}（${si(file.domains)}）`);
      options.append(label);
    }
    options.dataset.options = signature;
  }
  for (const box of options.querySelectorAll('input')) box.checked = selected.has(box.value);
  $(config.summary).textContent = selected.size ? `已选 ${selected.size} 项` : '不使用';
}

function renderAddRule() {
  const state = routes.state;
  /* An exit with no next hop a rule can use yet is offered too: the form asks for one. */
  setOptions($('rule-exit'), state.exits.filter(exit => exit.rules || exit.editable).map(exit => ({ value: exit.name, label: exitName(exit.name) + (exit.rules ? '' : '（需要填下一跳）') })));
  renderRuleFilePicker('domains');
  renderRuleFilePicker('ranges');
  const exit = state.exits.find(item => item.name === $('rule-exit').value);
  if (!routes.addDnsTyped) $('rule-dns').value = exit ? exit.dns : '';
  const needsVia = !!exit && !exit.rules;
  $('rule-via-part').hidden = !needsVia;
  if (needsVia && !routes.viaTyped) $('rule-via').value = routes.leases.get(exitInterface(exit)) || '';
  /* A VPP exit without an IPv6 next hop may get one here, suggested from ::/0. */
  const offersVia6 = !!exit && exit.editable && !exit.via6;
  $('rule-via6-part').hidden = !offersVia6;
  if (offersVia6 && (!routes.via6Typed || routes.via6Exit !== exit.name)) {
    $('rule-via6').value = routes.routers6.get(exitInterface(exit)) || '';
    routes.via6Typed = false;
  }
  routes.via6Exit = exit ? exit.name : '';
  const families = exit ? [...exit.families] : [];
  if (offersVia6 && $('rule-via6').value.trim() && !families.includes(6)) families.push(6);
  const host = $('rule-families');
  if (host.dataset.families !== families.join()) {
    host.dataset.families = families.join();
    host.textContent = '';
    for (const family of families) {
      const label = document.createElement('label');
      const box = document.createElement('input');
      box.type = 'checkbox';
      box.checked = true;
      box.value = family;
      label.append(box, ' ' + FAMILY[family]);
      host.append(label);
    }
  }
  const hasList = selectedRuleFiles('domains').length || selectedRuleFiles('ranges').length;
  $('rule-add').disabled = routes.busy || !!state.pending || !families.length || (!hasList && !keywordValues($('rule-keywords').value).length);
  $('upload-submit').disabled = routes.busy || !!state.pending;
}

/* A rule on an exit without a fixed next hop gives the exit one first. Nothing uses the exit
   for rules yet, so that is saved at once, unless it carries the default route. */
async function addRule() {
  const name = $('rule-name').value.trim();
  const families = [...$('rule-families').querySelectorAll('input:checked')].map(box => Number(box.value));
  if (!name) { message('请填写规则名称。', true); return; }
  if (!families.length) { message('至少选择一个地址族。', true); return; }
  const files = selectedRuleFiles('domains');
  const ranges = selectedRuleFiles('ranges');
  const keywords = keywordValues($('rule-keywords').value);
  if (!files.length && !ranges.length && !keywords.length) { message('请选择域名表、网段表或填写关键词。', true); return; }
  const exit = routes.state.exits.find(item => item.name === $('rule-exit').value);
  const newVia6 = exit && exit.editable && !exit.via6 ? $('rule-via6').value.trim() : '';
  if (exit && (!exit.rules || newVia6)) {
    const via4 = exit.rules ? exit.via4 : $('rule-via').value.trim();
    if (!via4 && families.includes(4)) { message('请填写 IPv4 下一跳：经这个出口能到达的地址，比如它的网关。', true); return; }
    try {
      routes.state = await postJSON(API + 'exit', { name: exit.name, interface: exitInterface(exit), via4, via6: newVia6 || exit.via6 || '', dhcp: false });
    } catch (err) {
      message(err.message, true);
      return;
    }
    routes.viaTyped = false;
    routes.via6Typed = false;
    if (routes.state.pending) {
      message(`出口 ${exitName(exit.name)} 的下一跳已改好。它承载着默认出口，所以要先确认这次修改，再添加规则。`);
      routes.deadline = Date.now() + routes.state.seconds_remaining * 1000;
      render();
      return;
    }
    render();
  }
  const done = await apply('rule', { name, exit: $('rule-exit').value, families, file: files, ranges, keywords, dns: $('rule-dns').value.trim() }, `添加规则 ${name}，出口 ${exitName($('rule-exit').value)}。新规则的优先级最低。`);
  if (done) {
    $('rule-name').value = ''; $('rule-keywords').value = '';
    routes.addFiles.clear(); routes.addRanges.clear();
    for (const kind of Object.keys(RULE_FILE_PICKERS)) $(RULE_FILE_PICKERS[kind].picker).querySelector('details').open = false;
    fitKeywords(); routes.addDnsTyped = false; render();
  }
}

/* Grows the keyword box to its lines, up to the CSS limit, past which it scrolls. */
function fitKeywords() {
  const box = $('rule-keywords');
  box.style.height = 'auto';
  box.style.height = box.scrollHeight + 2 + 'px';
}

function keywordValues(text) {
  return text.split(/\r?\n/).map(value => value.trim()).filter(Boolean);
}

/* One dialog edits a rule group's exit, DNS and matches, or the default exit and DNS. */
function fillExitSelect(select, choices, current, label) {
  select.textContent = '';
  for (const exit of choices) {
    const option = document.createElement('option');
    option.value = exit;
    option.textContent = exit === current ? `${label(exit)}（当前）` : label(exit);
    select.append(option);
  }
  select.value = current;
}

function fillEditLists(host, kind, selected) {
  host.textContent = '';
  const files = routes.state.files.filter(file => file.kind === kind && !file.problem);
  const known = new Set(files.map(file => file.path));
  /* A list the rule uses but that cannot be read stays listed, so saving does not drop it. */
  const entries = [...files.map(file => ({ path: file.path, text: `${file.name}（${si(file.domains)}）` })),
    ...[...selected].filter(path => !known.has(path)).map(path => ({ path, text: `${path.split('/').pop()}（读取失败）` }))];
  if (!entries.length) {
    const empty = document.createElement('span');
    empty.className = 'list-picker-empty';
    empty.textContent = `没有可用的${KIND[kind]}`;
    host.append(empty);
  }
  for (const entry of entries) {
    const label = document.createElement('label');
    label.className = 'list-picker-option';
    const box = document.createElement('input');
    box.type = 'checkbox';
    box.checked = selected.has(entry.path);
    box.onchange = () => { if (box.checked) selected.add(entry.path); else selected.delete(entry.path); };
    label.append(box, entry.text);
    host.append(label);
  }
}

function openEditDialog(edit, title) {
  routes.edit = edit;
  $('routes-edit-title').textContent = title;
  $('routes-edit-message').textContent = '';
  $('routes-edit-message').classList.remove('error');
  $('routes-edit-dialog').showModal();
}

function openEdit(group) {
  const mixed = group.exit.includes('、');
  const select = $('routes-edit-exit');
  const choices = [group.exit, ...group.options];
  fillExitSelect(select, choices, group.exit, exit => exit === group.exit && mixed ? `保持现状：${exitNames(exit)}` : exitName(exit));
  const fixed = !!group.locked || !group.options.length;
  select.disabled = fixed;
  $('routes-edit-exit-note').hidden = !fixed;
  $('routes-edit-exit-note').textContent = fixed ? `不能切换出口：${group.locked || '没有可用的其他出口'}` : '';
  const dns = $('routes-edit-dns');
  dns.value = group.dns;
  dns.placeholder = '默认 DNS';
  const edit = { group, files: new Set(group.files), ranges: new Set(group.range_files || []), dnsTyped: false };
  select.onchange = () => {
    /* A Fake-IP exit's DNS belongs to it, so it must not follow the rule to another exit. */
    if (!edit.dnsTyped) dns.value = select.value === group.exit ? group.dns : (group.option_dns[select.value] || '');
  };
  $('routes-edit-matches').hidden = false;
  fillEditLists($('routes-edit-files'), 'domains', edit.files);
  fillEditLists($('routes-edit-ranges'), 'ranges', edit.ranges);
  $('routes-edit-keywords').value = (group.keyword_values || []).join('\n');
  openEditDialog(edit, `编辑规则 ${group.id}`);
}

function openDefaultEdit() {
  const state = routes.state.default;
  const current = state.exit || '';
  const choices = ['', ...(state.options || [])];
  if (current && !choices.includes(current)) choices.push(current);
  const select = $('routes-edit-exit');
  fillExitSelect(select, choices, current, exit => exit ? exitName(exit) : SYSTEM);
  select.disabled = false;
  select.onchange = null;
  $('routes-edit-exit-note').hidden = false;
  $('routes-edit-exit-note').textContent = `没有匹配规则的流量走这个出口，出口断开时自动回落到${SYSTEM}。`;
  $('routes-edit-dns').value = state.dns;
  $('routes-edit-dns').placeholder = '必填';
  $('routes-edit-matches').hidden = true;
  openEditDialog({ group: null }, '编辑默认路由');
}

const sameList = (a, b) => a.length === b.length && a.every((value, i) => value === b[i]);

async function saveEdit() {
  const edit = routes.edit;
  const exit = $('routes-edit-exit').value;
  const dns = $('routes-edit-dns').value.trim();
  let done;
  if (!edit.group) {
    const state = routes.state.default;
    const body = {};
    const parts = [];
    if (exit !== (state.exit || '')) {
      body.exit = exit;
      parts.push(exit
        ? `把默认出口改为 ${exitName(exit)}：没有匹配规则的流量都从这个出口出去，路由器自己的流量（除了隧道端点和私网地址）也一样。出口断开时自动回落到${SYSTEM}。WAN 上的端口转发、IPsec 等入站服务的回包也会走这个出口。这个出口要配好 NAT`
        : `把默认出口改回${SYSTEM}`);
    }
    if (dns !== state.dns) { body.dns = dns; parts.push(`把默认 DNS 改成 ${dns}`); }
    if (!parts.length) { message('默认出口和 DNS 都没有变化。', true); return; }
    done = await apply('defaults', body, parts.join('；\n') + '。');
  } else {
    const group = edit.group;
    const files = [...edit.files];
    const ranges = [...edit.ranges];
    const keywords = keywordValues($('routes-edit-keywords').value);
    const parts = [];
    if (exit !== group.exit) parts.push(`切换到出口 ${exitName(exit)}`);
    if (dns !== group.dns) parts.push(`DNS 用 ${dns || '默认 DNS'}`);
    const names = paths => paths.map(path => path.split('/').pop()).join('、') || '不使用';
    if (!sameList(files, group.files)) parts.push(`域名表：${names(files)}`);
    if (!sameList(ranges, group.range_files || [])) parts.push(`网段表：${names(ranges)}`);
    if (!sameList(keywords, group.keyword_values || [])) parts.push(keywords.length ? `关键词 ${keywords.length} 个` : '删除关键词');
    if (!parts.length) { message('规则没有变化。', true); return; }
    if (!files.length && !ranges.length && !keywords.length && !group.domains) { message('请至少选择一个域名表、网段表或填写关键词。', true); return; }
    done = await apply('rule/edit', { group: group.id, exit, dns, file: files, ranges, keywords }, `修改规则 ${group.id}：${parts.join('，')}。IPv4 和 IPv6 规则一起更新。`);
  }
  if (done) $('routes-edit-dialog').close();
}

function listName(text, kind) {
  const base = text.trim().split(/[\\/]/).pop();
  const extension = '.' + kind;
  return base.endsWith(extension) ? base : base.replace(/\.[^.]*$/, '') + extension;
}

async function uploadFile() {
  const picked = $('upload-file').files[0];
  const typed = $('upload-name').value.trim();
  if (!typed && !picked) { message('请选择文件，或填写新文件名。', true); return; }
  const name = listName(typed || picked.name, $('upload-kind').value);
  const content = picked ? await picked.text() : '';
  const existing = routes.state.files.find(file => file.name === name);
  const body = { name, content, overwrite: !!existing };
  let done;
  if (existing && existing.used_by.length) {
    done = await apply('upload', body, `用上传的内容替换 ${name}，它正被 ${existing.used_by.join('、')} 使用。`, null);
  } else {
    done = await act('upload', '正在保存…', body);
  }
  if (done) { $('upload-file').value = ''; $('upload-name').value = ''; message(`已保存 ${name}`); }
}

/* A file in use is renamed together with the rules that use it, as one change to confirm. */
async function renameFile(file) {
  const typed = prompt(`${KIND[file.kind]} ${file.name} 的新名字：`, file.name);
  if (typed === null || !typed.trim()) return;
  const name = listName(typed, file.kind);
  if (name === file.name) return;
  const description = `把${KIND[file.kind]} ${file.name} 改名为 ${name}`;
  if (file.used_by.length) {
    await apply('file/rename', { path: file.path, name }, `${description}，${file.used_by.join('、')} 改用新名字。确认后删除旧文件，恢复时保留旧文件。`);
  } else if (await act('file/rename', '正在改名…', { path: file.path, name })) {
    message(`已改名为 ${name}`);
  }
}

async function deleteFile(file) {
  if (!confirm(`删除${KIND[file.kind]} ${file.name}？`)) return;
  await act('file/delete', '正在删除…', { path: file.path });
}

/* The list dialog collects additions and removals, then applies them as one change. */
async function openFile(file) {
  routes.file = file;
  routes.add.clear();
  routes.remove.clear();
  $('routes-file-title').textContent = `${KIND[file.kind]} ${file.name}`;
  $('routes-file-existing').textContent = FILE_TEXT[file.kind].existing;
  $('routes-file-add-title').textContent = FILE_TEXT[file.kind].add;
  $('routes-file-add').placeholder = FILE_TEXT[file.kind].hint;
  $('routes-file-search').value = '';
  $('routes-file-add').value = '';
  renderFileChanges();
  $('routes-file-dialog').showModal();
  await searchFile();
}

async function searchFile() {
  const params = new URLSearchParams({ path: routes.file.path, q: $('routes-file-search').value });
  try {
    const result = await fetchJSON(API + 'file?' + params);
    $('routes-file-count').textContent = result.matched > result.domains.length
      ? `共 ${result.total} 个，匹配 ${result.matched} 个，只显示前 ${result.domains.length} 个，请搜索缩小范围`
      : `共 ${result.total} 个，匹配 ${result.matched} 个`;
    fillBody($('routes-file-list').tBodies[0], result.domains.length, (row, i) => {
      const domain = result.domains[i];
      setCells(row, [domain, '']);
      row.className = routes.remove.has(domain) ? 'selected' : '';
      replaceCell(row, 1, button(routes.remove.has(domain) ? '撤销' : '删除', () => {
        if (routes.remove.has(domain)) routes.remove.delete(domain); else routes.remove.add(domain);
        renderFileChanges();
        searchFile();
      }));
    });
  } catch (err) {
    $('routes-file-count').textContent = err.message;
  }
}

function parsedAdditions() {
  return $('routes-file-add').value.split(/[\s,]+/).map(text => text.trim()).filter(Boolean);
}

function renderFileChanges() {
  const additions = parsedAdditions();
  const pending = routes.state && routes.state.pending;
  $('routes-file-changes').textContent = `待应用：添加 ${additions.length} 个，删除 ${routes.remove.size} 个`;
  $('routes-file-apply').disabled = routes.busy || !!pending || (additions.length === 0 && routes.remove.size === 0);
}

async function applyFile() {
  const additions = parsedAdditions();
  const description = `修改${KIND[routes.file.kind]} ${routes.file.name}：添加 ${additions.length} 个，删除 ${routes.remove.size} 个`;
  const done = await apply('file', { path: routes.file.path, add: additions, remove: [...routes.remove] }, description, null);
  if (done) $('routes-file-dialog').close();
}

export function start() {
  $('routes-dns-hijack').onchange = async () => {
    const enabled = $('routes-dns-hijack').checked;
    await apply('dns-hijack', { enabled }, `${enabled ? '开启' : '关闭'} VPP 侧 DNS 劫持。`);
    render();
  };
  $('rule-keywords').oninput = () => { fitKeywords(); renderAddRule(); };
  $('routes-edit-save').onclick = saveEdit;
  $('routes-edit-dns').oninput = () => { if (routes.edit) routes.edit.dnsTyped = true; };
  $('exit-save').onclick = saveExit;
  $('exit-dhcp').onchange = renderExits;
  $('routes-confirm').onclick = () => act('confirm', '正在确认…');
  $('routes-rollback').onclick = () => { if (confirm('立即恢复到修改前？')) act('rollback', '正在恢复…'); };
  $('routes-save-order').onclick = () => {
    const order = currentOrder().map(group => group.id);
    apply('order', { order }, `调整规则优先级：${order.join(' > ')}`);
  };
  $('routes-reset-order').onclick = () => { routes.order = null; render(); };
  $('routes-flush').onclick = () => {
    if (confirm('清空 Gate 安装的全部路由和 DNS 学到的记录，然后重启 Gate？\n\n静态网段和 Fake-IP 地址池会马上重新安装。按域名学到的真实 IP 路由要等客户端重新查询，在此之前这些连接走默认路由。局域网 DNS 会短暂中断，这个操作不能撤销。')) act('flush', '正在清空路由…');
  };
  $('routes-file-apply').onclick = applyFile;
  $('rule-add').onclick = addRule;
  $('rule-dns').oninput = () => { routes.addDnsTyped = true; };
  $('rule-via').oninput = () => { routes.viaTyped = true; };
  $('rule-via6').oninput = () => { routes.via6Typed = true; renderAddRule(); };
  $('rule-exit').onchange = renderAddRule;
  $('upload-submit').onclick = uploadFile;
  $('routes-file-add').oninput = renderFileChanges;
  let searchTimer = 0;
  $('routes-file-search').oninput = () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(searchFile, 250);
  };
}

export function show() {
  load();
  clearInterval(routes.timer);
  clearInterval(routes.tick);
  routes.timer = setInterval(() => { if (!document.hidden && !routes.busy) load(); }, 5000);
  routes.tick = setInterval(() => { if (routes.state && routes.state.pending) renderPending(); }, 1000);
}

export function hide() {
  clearInterval(routes.timer);
  clearInterval(routes.tick);
}
