/* The shell: login state and which page runs. */
import { $, postJSON } from './lib.js';
import { start as startOverview } from './pages/overview.js';
import { start as startRoutes, show as showRoutes, hide as hideRoutes } from './pages/routes.js';
import { show as showVPN, hide as hideVPN } from './pages/vpn.js';
import { start as startInterfaces, show as showInterfaces, hide as hideInterfaces } from './pages/interfaces.js';
import { start as startProxy, show as showProxy, hide as hideProxy } from './pages/proxy.js';
import { start as startFirewall, show as showFirewall, hide as hideFirewall } from './pages/firewall.js';
import { start as startSystem, show as showSystem, hide as hideSystem } from './pages/system.js';
import { start as startLAN, show as showLAN, hide as hideLAN } from './pages/lan.js';
import { start as startMaint, show as showMaint, hide as hideMaint } from './pages/maint.js';

$('logout').onclick = async () => {
  await fetch('api/logout', { method: 'POST' });
  location.href = '/login.html';
};

$('password-open').onclick = () => {
  $('password-form').reset();
  $('password-error').textContent = '';
  $('password-dialog').showModal();
};
$('password-form').onsubmit = async event => {
  event.preventDefault();
  const error = $('password-error');
  if ($('password-new').value !== $('password-confirm').value) {
    error.textContent = '两次输入的新密码不一致。';
    return;
  }
  $('password-submit').disabled = true;
  error.textContent = '';
  try {
    await postJSON('api/password', { current: $('password-current').value, password: $('password-new').value });
    $('password-dialog').close();
    alert('密码已修改。');
  } catch (err) {
    error.textContent = err.message;
  }
  $('password-submit').disabled = false;
};

const PAGES = { overview: {}, routes: { show: showRoutes, hide: hideRoutes }, vpn: { show: showVPN, hide: hideVPN }, interfaces: { show: showInterfaces, hide: hideInterfaces }, proxy: { show: showProxy, hide: hideProxy }, firewall: { show: showFirewall, hide: hideFirewall }, system: { show: showSystem, hide: hideSystem }, lan: { show: showLAN, hide: hideLAN }, maint: { show: showMaint, hide: hideMaint } };

function route() {
  const wanted = location.pathname.slice(1);
  const current = PAGES[wanted] ? wanted : 'overview';
  for (const [name, page] of Object.entries(PAGES)) {
    const active = name === current;
    $('page-' + name).hidden = !active;
    $('nav-' + name).setAttribute('aria-current', active ? 'page' : 'false');
    if (active && page.show) page.show();
    if (!active && page.hide) page.hide();
  }
}

startOverview();
startRoutes();
startInterfaces();
startProxy();
startFirewall();
startSystem();
startLAN();
startMaint();
// Links from when pages were addressed as #routes.
const oldPage = location.hash.slice(1);
if (PAGES[oldPage]) history.replaceState(null, '', oldPage === 'overview' ? '/' : '/' + oldPage);

for (const link of document.querySelectorAll('.main-nav a')) {
  link.onclick = event => {
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) return;
    event.preventDefault();
    history.pushState(null, '', link.getAttribute('href'));
    route();
  };
}
window.addEventListener('popstate', route);
route();
