'use strict';

// 登录页：提交严格 {username, password} 到 /api/admin/login。
// 密码不预填、不持久化；失败提示不区分用户名/密码细节。
(() => {
  const dom = Object.fromEntries(['login-form', 'login-username', 'login-password', 'login-submit', 'login-error']
    .map(id => [id, document.getElementById(id)]));
  const messages = {
    401: '用户名或密码错误。',
    403: '登录请求被服务端拒绝，请刷新页面后重试。',
    422: '登录请求无效，请刷新页面后重试。',
    429: '登录尝试过于频繁，请稍后重试。',
    503: '管理服务暂时不可用，请稍后重试。'
  };
  let busy = false;

  function showError(message) {
    dom['login-error'].textContent = message;
    dom['login-error'].hidden = !message;
  }

  dom['login-form'].addEventListener('submit', async event => {
    event.preventDefault();
    if (busy) return;
    showError('');
    const username = dom['login-username'].value;
    const password = dom['login-password'].value;
    if (!username || !password) {
      showError('请输入用户名和密码。');
      (username ? dom['login-password'] : dom['login-username']).focus();
      return;
    }
    busy = true;
    dom['login-submit'].disabled = true;
    dom['login-submit'].textContent = '正在登录…';
    try {
      const response = await fetch('/api/admin/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ username, password }),
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error'
      });
      if (response.ok) {
        dom['login-password'].value = '';
        window.location.assign('/admin');
        return;
      }
      showError(messages[response.status] || '登录失败，请稍后重试。');
    } catch {
      showError('网络异常，无法连接管理服务，请稍后重试。');
    }
    dom['login-password'].value = '';
    busy = false;
    dom['login-submit'].disabled = false;
    dom['login-submit'].textContent = '登录';
    dom['login-password'].focus();
  });
})();
