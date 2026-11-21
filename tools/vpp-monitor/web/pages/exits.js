/* Connections per exit. They come from VPP's API, so they are only requested while this
   dialog is open. */
import { $, si, bytes, FORMATS, fetchJSON, setCells, fillBody, linkCell, idleText } from '../lib.js';

const nat = { timer: 0, report: null };

export function openNAT() {
  const dialog = $('nat-dialog');
  if (dialog.open) return;
  nat.report = null;
  $('nat-filter').value = '';
  renderNAT();
  dialog.showModal();
  loadNAT();
  nat.timer = setInterval(() => { if (!document.hidden) loadNAT(); }, 5000);
}

async function loadNAT() {
  try {
    nat.report = await fetchJSON('api/nat');
  } catch (err) {
    nat.report = { available: false, reason: err.message };
  }
  renderNAT();
}

const KIND_LABEL = { self: '本机', return: '回程残留' };

function renderNAT() {
  const report = nat.report;
  const summary = $('nat-summary');
  const content = $('nat-content');
  if (!report) {
    summary.textContent = '读取中…';
    content.hidden = true;
    return;
  }
  if (!report.available) {
    summary.textContent = '读取失败：' + report.reason;
    content.hidden = true;
    return;
  }
  content.hidden = false;
  const ready = report.rates_ready;
  const rate = value => ready ? value : null;
  const users = report.users || [];
  const exits = report.exits || [];
  fillBody($('nat-exits').tBodies[0], exits.length, (row, i) => {
    const r = exits[i];
    setCells(row, [r.name, ready ? FORMATS.bps(r.bps) : '—', ready ? si(r.pps) : '—', si(r.sessions)]);
  });
  const clients = users.filter(r => r.kind !== 'self' && r.kind !== 'return');
  const others = users.filter(r => r.kind === 'self' || r.kind === 'return');
  const notes = [`${clients.length} 个内网用户`, `${si(report.total_sessions)} 条会话`];
  notes.push(ready ? `合计 ${FORMATS.bps(report.bps)}` : '速率需要两次读取，约 5 秒后显示');
  if (report.truncated) notes.push(`会话太多，只读取了其中 ${si(report.read_sessions)} 条，有些用户的连接未读取`);
  summary.textContent = notes.join(' · ');

  const filter = $('nat-filter').value.trim();
  $('nat-others-box').hidden = others.length === 0;
  $('nat-others-count').textContent = others.length;
  fillUsers($('nat-others'), others, true);
  fillUsers($('nat-users'), clients, false);

  function fillUsers(table, list, showKind) {
  fillBody(table.tBodies[0], list.length, (row, i) => {
    const r = list[i];
    row.className = filter === r.address ? 'selected' : '';
    linkCell(row, r.address, () => {
      $('nat-filter').value = $('nat-filter').value.trim() === r.address ? '' : r.address;
      renderNAT();
    });
    const cells = [...(showKind ? [KIND_LABEL[r.kind]] : []), (r.exits || []).join('、') || '—', si(r.dynamic), si(r.static), r.read ? FORMATS.bps(rate(r.bps)) : '未读取', r.read ? si(rate(r.pps)) : '—'];
    while (row.children.length < cells.length + 1) row.append(document.createElement('td'));
    cells.forEach((text, j) => { row.children[j + 1].textContent = text; });
  });
  }

  const rows = (report.sessions || []).filter(r => !filter || [r.exit, r.inside, r.outside, r.external, r.protocol].some(text => text.includes(filter)));
  $('nat-empty').hidden = rows.length > 0;
  const noExternal = !(report.sessions || []).some(r => r.external);
  $('nat-sessions').classList.toggle('no-external', noExternal);
  $('nat-no-external').hidden = !noExternal;
  fillBody($('nat-sessions').tBodies[0], rows.length, (row, i) => {
    const r = rows[i];
    setCells(row, [r.exit, r.protocol + (r.static ? ' 静态' : ''), r.inside + (KIND_LABEL[r.kind] ? `（${KIND_LABEL[r.kind]}）` : ''), r.external || '—', r.outside || '—', FORMATS.bps(rate(r.bps)), si(rate(r.pps)), bytes(r.bytes), si(r.packets), idleText(r.idle_seconds)]);
  });
}

$('nat-filter').oninput = renderNAT;
$('nat-dialog').addEventListener('close', () => clearInterval(nat.timer));
