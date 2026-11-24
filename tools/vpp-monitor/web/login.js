'use strict';
const form = document.getElementById('form');
const button = document.getElementById('submit');
const message = document.getElementById('message');
const help = document.getElementById('help');
const helpOpen = document.getElementById('help-open');
// On this many wrong passwords in a row the page offers how to reset it on the host.
const HELP_AFTER = 3;
let failures = 0;
try { failures = Number(sessionStorage.getItem('login-failures')) || 0; } catch {}
helpOpen.hidden = failures < HELP_AFTER;
helpOpen.onclick = () => help.showModal();

// offerHelp opens the dialog the first time, and leaves the link for later.
function offerHelp() {
  if (helpOpen.hidden) {
    helpOpen.hidden = false;
    help.showModal();
  }
}
function countFailure() {
  failures++;
  try { sessionStorage.setItem('login-failures', String(failures)); } catch {}
  if (failures >= HELP_AFTER) offerHelp();
}

const copy = document.getElementById('help-copy');
copy.onclick = async () => {
  try {
    await navigator.clipboard.writeText(document.getElementById('help-command').textContent);
    copy.textContent = '已复制';
  } catch {
    copy.textContent = '复制失败，请手动选择';
  }
  setTimeout(() => { copy.textContent = '复制命令'; }, 2000);
};

form.onsubmit = async event => {
  event.preventDefault();
  button.disabled = true;
  message.textContent = '正在验证…';
  try {
    const response = await fetch('api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user: document.getElementById('user').value,
        password: document.getElementById('password').value,
      }),
    });
    if (response.ok) {
      try { sessionStorage.removeItem('login-failures'); } catch {}
      location.href = '/';
      return;
    }
    if (response.status === 429) {
      message.textContent = '尝试次数过多，请稍后再试。';
      offerHelp();
    } else {
      message.textContent = '用户名或密码错误。';
      if (response.status === 401) countFailure();
    }
  } catch (err) {
    message.textContent = '无法连接到面板：' + err.message;
  }
  button.disabled = false;
};
