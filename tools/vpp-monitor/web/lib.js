/* Formatting, DOM and fetch helpers shared by every page. */
export const SI = ['', 'K', 'M', 'G', 'T'];
export const $ = id => document.getElementById(id);

export function si(value, digits = 3) {
  if (value == null || !isFinite(value)) return '—';
  let i = 0, v = Math.abs(value);
  while (v >= 1000 && i < SI.length - 1) { v /= 1000; i++; }
  const text = i === 0 && Number.isInteger(v) ? String(v) : v.toPrecision(digits);
  return (value < 0 ? '-' : '') + text.replace(/\.0+$/, '') + (i ? ' ' + SI[i] : '');
}
export function bytes(value) {
  if (value == null || !isFinite(value)) return '—';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let i = 0, v = value;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return (i === 0 ? String(Math.round(v)) : v.toPrecision(3)) + ' ' + units[i];
}
export const FORMATS = {
  bps: v => v == null ? '—' : si(v) + 'b/s',
  pps: v => v == null ? '—' : si(v) + ' pps',
  rate: v => v == null ? '—' : si(v) + '/s',
  count: v => si(v),
  bytes,
  percent: v => v == null ? '—' : v.toFixed(1) + '%',
  celsius: v => v == null ? '—' : v.toFixed(1) + ' °C',
};
export function duration(seconds) {
  const days = Math.floor(seconds / 86400), hours = Math.floor(seconds % 86400 / 3600), minutes = Math.floor(seconds % 3600 / 60);
  return days ? `${days} 天 ${hours} 小时` : hours ? `${hours} 小时 ${minutes} 分` : `${minutes} 分钟`;
}

export function read(key) { try { return localStorage.getItem(key); } catch { return null; } }
export function write(key, value) { try { localStorage.setItem(key, value); } catch {} }

export function color(slot) {
  return getComputedStyle(document.documentElement).getPropertyValue('--s' + (slot % 8 + 1)).trim();
}
export function token(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

export function fetchJSON(url) {
  return fetch(url).then(r => {
    if (r.status === 401) { location.href = '/login.html'; throw new Error('需要登录'); }
    if (!r.ok) throw new Error(r.statusText);
    return r.json();
  });
}

export async function postJSON(url, body) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (response.status === 401) { location.href = '/login.html'; throw new Error('需要登录'); }
  const result = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(result.error || response.statusText);
  return result;
}

export function setCells(row, values) {
  while (row.children.length < values.length) row.append(document.createElement('td'));
  while (row.children.length > values.length) row.lastChild.remove();
  values.forEach((value, i) => { if (row.children[i].textContent !== value) row.children[i].textContent = value; });
}

export function fillBody(body, count, render) {
  while (body.children.length < count) body.append(document.createElement('tr'));
  while (body.children.length > count) body.lastChild.remove();
  for (let i = 0; i < count; i++) render(body.children[i], i);
}

export function linkCell(row, text, onClick) {
  let cell = row.firstChild;
  if (!cell) { cell = document.createElement('td'); row.append(cell); }
  let button = cell.firstChild;
  if (!button || button.nodeName !== 'BUTTON') {
    cell.textContent = '';
    button = document.createElement('button');
    cell.append(button);
  }
  button.textContent = text;
  button.onclick = onClick;
}

export function idleText(seconds) {
  if (seconds < 60) return Math.round(seconds) + ' 秒';
  if (seconds < 3600) return Math.round(seconds / 60) + ' 分';
  return (seconds / 3600).toFixed(1) + ' 时';
}
