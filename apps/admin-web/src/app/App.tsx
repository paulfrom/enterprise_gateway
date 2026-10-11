import { useCallback, useEffect, useState } from 'react';
import { Alert, Badge, Button, Card, Form, Input, Layout, Space, Typography } from 'antd';
import { SafetyCertificateOutlined } from '@ant-design/icons';
import { BrowserRouter, Navigate, Route, Routes, Link } from 'react-router-dom';
import { useQueryClient } from '@tanstack/react-query';
import { api, clearSession, errorText, onExpired, setSession, type Session, type Login } from '../api/client';
import { History } from '../features/History';

function Console() {
  const cache = useQueryClient();
  const [session, updateSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);
  const [failure, setFailure] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [form] = Form.useForm<Login>();
  const authenticated = !!session;
  const expire = useCallback(() => {
    clearSession(); void cache.cancelQueries(); cache.clear(); updateSession(null);
    setFailure('会话已过期，请重新登录');
  }, [cache]);
  useEffect(() => {
    const controller = new AbortController();
    const unsubscribe = onExpired(expire);
    api.session(controller.signal).then(value => { setSession(value); updateSession(value); setFailure(undefined); }).catch(error => {
      if (error.name !== 'AbortError' && error.status !== 401) setFailure(errorText(error));
    }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => { controller.abort(); unsubscribe(); };
  }, [expire]);
  useEffect(() => {
    if (!authenticated) return;
    const controller = new AbortController();
    const timer = window.setInterval(() => {
      api.session(controller.signal).then(value => { setSession(value); updateSession(value); setFailure(undefined); }).catch(error => {
        if (error.name !== 'AbortError' && error.status !== 401) setFailure(errorText(error));
      });
    }, 30000);
    return () => { window.clearInterval(timer); controller.abort(); };
  }, [authenticated]);
  async function login(values: Login) {
    setBusy(true); setFailure(undefined);
    try { const value = await api.login(values); setSession(value); updateSession(value); }
    catch (error) { setFailure(errorText(error)); }
    finally { form.resetFields(['password']); setBusy(false); }
  }
  async function logout() {
    setBusy(true);
    // Hide protected content immediately, including when revocation cannot be
    // confirmed because the server or transport is unavailable.
    clearSession(); updateSession(null);
    try {
      await cache.cancelQueries(); cache.clear();
      setSession(session); await api.logout(); setFailure(undefined);
    }
    catch (error) { setFailure(`服务端退出未确认：${errorText(error)}`); }
    finally { clearSession(); cache.clear(); setBusy(false); }
  }
  const loginPage = <Card title="管理员登录" style={{ maxWidth: 440, margin: '48px auto' }}>
    <Form form={form} layout="vertical" onFinish={login} autoComplete="off">
      <Form.Item name="username" label="用户名" rules={[{ required: true, message: '请输入用户名' }]}><Input autoComplete="username" /></Form.Item>
      <Form.Item name="password" label="密码" rules={[{ required: true, message: '请输入密码' }]}><Input.Password autoComplete="current-password" /></Form.Item>
      <Button htmlType="submit" type="primary" loading={busy} block>登录</Button>
    </Form>
  </Card>;
  const protectedPage = (content: React.ReactNode) => session ? content : <Navigate to="/login" replace />;
  return <Layout style={{ minHeight: '100vh' }}>
    <Layout.Header style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '0 24px' }}>
      <SafetyCertificateOutlined style={{ fontSize: 24, color: '#1677ff' }} />
      <Typography.Title level={4} style={{ color: '#fff', margin: 0, flex: 1 }}>企业隐私网关管理端</Typography.Title>
      {session && <Space><Link to="/admin">概览</Link><Link to="/admin/requests">请求历史</Link><Button loading={busy} onClick={logout}>退出</Button></Space>}
    </Layout.Header>
    <Layout.Content style={{ padding: 24, maxWidth: 1200, margin: '0 auto', width: '100%' }}>
      {failure && <Alert type="error" message={failure} showIcon style={{ marginBottom: 16 }} />}
      {loading ? <Card loading aria-label="正在恢复会话" /> : <Routes>
        <Route path="/login" element={session ? <Navigate to="/admin" replace /> : loginPage} />
        <Route path="/admin" element={protectedPage(<Card title="系统概览"><Space direction="vertical">
          <Badge status={failure ? 'error' : 'success'} text={failure ? '管理 API 校验失败' : '管理 API 已连接，会话有效'} />
          <Typography.Text>当前管理员：{session?.actor_id}</Typography.Text>
          <Typography.Text type="secondary">数据库及历史可用性以请求历史页面实际查询为准。</Typography.Text>
          <Link to="/admin/requests">查看请求历史</Link>
        </Space></Card>)} />
        <Route path="/admin/requests" element={protectedPage(<History />)} />
        <Route path="*" element={<Navigate to={session ? '/admin' : '/login'} replace />} />
      </Routes>}
    </Layout.Content>
    <Layout.Footer style={{ textAlign: 'center' }}>企业隐私网关 © 2026</Layout.Footer>
  </Layout>;
}
export const App = () => <BrowserRouter><Console /></BrowserRouter>;
export default App;
