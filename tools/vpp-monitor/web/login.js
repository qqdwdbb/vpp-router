'use strict';
const form = document.getElementById('form');
const button = document.getElementById('submit');
const message = document.getElementById('message');

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
    if (response.ok) { location.href = '/'; return; }
    message.textContent = response.status === 429 ? '尝试次数过多，请稍后再试。' : '用户名或密码错误。';
  } catch (err) {
    message.textContent = '无法连接到面板：' + err.message;
  }
  button.disabled = false;
};
