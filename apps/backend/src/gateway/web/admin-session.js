'use strict';

// 管理壳会话模块：GET /api/admin/session 启动与轮询（轮询不刷新空闲期限）、
// 内存保存 CSRF token、统一 401/退出清场并跳回 /login。
// CSRF token 只存本模块闭包，不进 DOM、localStorage、sessionStorage 或 URL。
window.AdminSession = (() => {
  const POLL_MS = 60000;
  const REDIRECT_DELAY_MS = 1200;
  let session = null;
  let csrfToken = '';
  let expired = false;
  let readyPromise = null;
  let pollTimer = null;
  const expireListeners = new Set();
  const refreshListeners = new Set();

  function notify(message) {
    const toast = document.getElementById('toast');
    if (!toast) return;
    toast.textContent = message;
    toast.classList.add('visible');
    setTimeout(() => toast.classList.remove('visible'), 4000);
  }

  function statusError(status) {
    const error = new Error('Admin session request failed');
    error.status = status;
    return error;
  }

  function applyPayload(payload) {
    session = payload;
    csrfToken = typeof payload.csrf_token === 'string' ? payload.csrf_token : '';
    for (const listener of [...refreshListeners]) {
      try { listener(session); } catch { /* 监听方自治 */ }
    }
  }

  function expire(message) {
    if (expired) return;
    expired = true;
    if (pollTimer) clearInterval(pollTimer);
    for (const listener of [...expireListeners]) {
      try { listener(); } catch { /* 监听方自治 */ }
    }
    session = null;
    csrfToken = '';
    if (message) notify(message);
    setTimeout(() => window.location.replace('/login'), REDIRECT_DELAY_MS);
  }

  async function fetchSession(signal) {
    const response = await fetch('/api/admin/session', {
      method: 'GET', headers: { Accept: 'application/json' },
      credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal
    });
    if (response.status === 401) {
      expire('会话已失效，请重新登录。');
      throw statusError(401);
    }
    if (!response.ok) throw statusError(response.status);
    applyPayload(await response.json());
    return session;
  }

  // 统一数据请求：同源 Cookie；非 GET 自动附带会话绑定 CSRF 头；401 即清场。
  async function request(path, options = {}) {
    if (expired) throw statusError(401);
    const method = options.method || 'GET';
    const headers = { Accept: 'application/json', ...(options.headers || {}) };
    if (method !== 'GET') headers['X-Admin-CSRF'] = csrfToken;
    const response = await fetch(path, {
      ...options, method, headers,
      credentials: 'same-origin', cache: 'no-store', redirect: 'error'
    });
    if (response.status === 401) {
      expire('会话已失效，请重新登录。');
      throw statusError(401);
    }
    return response;
  }

  async function logout() {
    if (expired) return;
    try {
      const response = await request('/api/admin/logout', { method: 'POST' });
      if (!response.ok) {
        notify(response.status === 403 ? '退出请求被拒绝，请刷新页面后重试。' : '退出失败，请稍后重试。');
        return;
      }
    } catch (error) {
      if (error && error.status === 401) return;
      notify('网络异常，未能完成退出，请稍后重试。');
      return;
    }
    expire('已退出登录。');
  }

  function start() {
    readyPromise = fetchSession();
    pollTimer = setInterval(() => { fetchSession().catch(() => {}); }, POLL_MS);
    return readyPromise;
  }

  return {
    start,
    ready: () => readyPromise,
    request,
    logout,
    notify,
    current: () => session,
    isExpired: () => expired,
    onExpire: listener => expireListeners.add(listener),
    onRefresh: listener => refreshListeners.add(listener)
  };
})();
