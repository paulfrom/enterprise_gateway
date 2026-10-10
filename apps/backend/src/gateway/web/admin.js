'use strict';

// 管理壳：会话标识/范围/有效期展示、退出按钮、导航定位、会话失效清场。
(() => {
  const dom = Object.fromEntries(['session-identity', 'logout-button', 'nav-requests']
    .map(id => [id, document.getElementById(id)]));

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function formatTime(value) {
    if (typeof value !== 'string') return '时间未提供';
    const date = new Date(value);
    if (!Number.isFinite(date.getTime())) return value;
    return new Intl.DateTimeFormat('zh-CN', {
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
    }).format(date);
  }

  function renderSession() {
    const identity = dom['session-identity'];
    identity.replaceChildren();
    const session = window.AdminSession.current();
    if (!session) return;
    identity.append(
      el('span', 'actor', String(session.actor_id || 'admin')),
      el('span', '', '管理范围 '),
      el('code', '', String(session.scope || '未知')),
      el('span', '', '空闲截止 ' + formatTime(session.idle_expires_at)),
      el('span', '', '绝对截止 ' + formatTime(session.absolute_expires_at))
    );
  }

  const path = window.location.pathname;
  if (path === '/admin' || path === '/admin/requests') {
    dom['nav-requests'].setAttribute('aria-current', 'page');
  }

  dom['logout-button'].addEventListener('click', async () => {
    dom['logout-button'].disabled = true;
    await window.AdminSession.logout();
    if (!window.AdminSession.isExpired()) dom['logout-button'].disabled = false;
  });

  window.AdminSession.onExpire(() => {
    dom['session-identity'].replaceChildren();
    dom['logout-button'].disabled = true;
  });
  window.AdminSession.onRefresh(renderSession);
  window.AdminSession.start().catch(error => {
    if (error && error.status === 401) return;
    window.AdminSession.notify('暂时无法确认会话状态，请稍后重试。');
  });
})();
