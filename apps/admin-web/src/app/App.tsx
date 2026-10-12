import { useCallback, useEffect, useState } from 'react';
import { Alert, Button, Card, Form, Input, Layout, Menu, Space, Typography } from 'antd';
import {
  SafetyCertificateOutlined,
  DashboardOutlined,
  HistoryOutlined,
  BookOutlined,
  CheckCircleOutlined,
  SendOutlined,
  EyeOutlined,
  AuditOutlined,
  LogoutOutlined,
  BranchesOutlined,
} from '@ant-design/icons';
import { BrowserRouter, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import { useQueryClient } from '@tanstack/react-query';
import {
  api,
  clearSession,
  errorText,
  onExpired,
  setSession,
  type Session,
  type Login,
} from '../api/client';
import {
  Dashboard,
  History,
  KnowledgeSources,
  KnowledgeCandidates,
  KnowledgePublications,
  KnowledgeObservations,
  KnowledgeGraph,
  SecurityAudit,
} from '../features';

function Console() {
  const cache = useQueryClient();
  const location = useLocation();
  const navigate = useNavigate();
  const [session, updateSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);
  const [failure, setFailure] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [form] = Form.useForm<Login>();
  const authenticated = !!session;

  const expire = useCallback(() => {
    clearSession();
    void cache.cancelQueries();
    cache.clear();
    updateSession(null);
    setFailure('会话已过期，请重新登录');
  }, [cache]);

  useEffect(() => {
    const controller = new AbortController();
    const unsubscribe = onExpired(expire);
    api
      .session(controller.signal)
      .then((value) => {
        setSession(value);
        updateSession(value);
        setFailure(undefined);
      })
      .catch((error) => {
        if (error.name !== 'AbortError' && error.status !== 401) {
          setFailure(errorText(error));
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => {
      controller.abort();
      unsubscribe();
    };
  }, [expire]);

  useEffect(() => {
    if (!authenticated) return;
    const controller = new AbortController();
    const timer = window.setInterval(() => {
      api
        .session(controller.signal)
        .then((value) => {
          setSession(value);
          updateSession(value);
          setFailure(undefined);
        })
        .catch((error) => {
          if (error.name !== 'AbortError' && error.status !== 401) {
            setFailure(errorText(error));
          }
        });
    }, 30000);
    return () => {
      window.clearInterval(timer);
      controller.abort();
    };
  }, [authenticated]);

  async function login(values: Login) {
    setBusy(true);
    setFailure(undefined);
    try {
      const value = await api.login(values);
      setSession(value);
      updateSession(value);
    } catch (error) {
      setFailure(errorText(error));
    } finally {
      form.resetFields(['password']);
      setBusy(false);
    }
  }

  async function logout() {
    setBusy(true);
    clearSession();
    updateSession(null);
    try {
      await cache.cancelQueries();
      cache.clear();
      setSession(session);
      await api.logout();
      setFailure(undefined);
    } catch (error) {
      setFailure(`服务端退出未确认：${errorText(error)}`);
    } finally {
      clearSession();
      cache.clear();
      setBusy(false);
    }
  }

  const menuItems = [
    { key: '/admin', icon: <DashboardOutlined />, label: '系统概览' },
    { key: '/admin/requests', icon: <HistoryOutlined />, label: '请求历史' },
    { key: '/admin/sources', icon: <BookOutlined />, label: '知识来源' },
    { key: '/admin/candidates', icon: <CheckCircleOutlined />, label: '候选审核' },
    { key: '/admin/publications', icon: <SendOutlined />, label: '资产发布' },
    { key: '/admin/observations', icon: <EyeOutlined />, label: '采集观察' },
    { key: '/admin/graph', icon: <BranchesOutlined />, label: '图谱分析' },
    { key: '/admin/audit', icon: <AuditOutlined />, label: '安全审计' },
  ];

  const selectedKey = location.pathname.startsWith('/admin') ? location.pathname : '/admin';

  const loginPage = (
    <Card title="管理员登录" style={{ maxWidth: 440, margin: '48px auto' }}>
      <Form form={form} layout="vertical" onFinish={login} autoComplete="off">
        <Form.Item
          name="username"
          label="用户名"
          rules={[{ required: true, message: '请输入用户名' }]}
        >
          <Input autoComplete="username" />
        </Form.Item>
        <Form.Item
          name="password"
          label="密码"
          rules={[{ required: true, message: '请输入密码' }]}
        >
          <Input.Password autoComplete="current-password" />
        </Form.Item>
        <Button htmlType="submit" type="primary" loading={busy} block>
          登录
        </Button>
      </Form>
    </Card>
  );

  const protectedPage = (content: React.ReactNode) =>
    session ? content : <Navigate to="/login" replace />;

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Layout.Header
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 16,
          padding: '0 24px',
          background: '#001529',
        }}
      >
        <SafetyCertificateOutlined style={{ fontSize: 24, color: '#1677ff' }} />
        <Typography.Title level={4} style={{ color: '#fff', margin: 0, whiteSpace: 'nowrap' }}>
          企业隐私网关管理端
        </Typography.Title>
        {session && (
          <div style={{ flex: 1, minWidth: 0 }}>
            <Menu
              theme="dark"
              mode="horizontal"
              selectedKeys={[selectedKey]}
              items={menuItems}
              onClick={({ key }) => navigate(key)}
              style={{ flex: 1, minWidth: 0, borderBottom: 'none' }}
            />
          </div>
        )}
        {session && (
          <Space>
            <Typography.Text style={{ color: '#rgba(255,255,255,0.65)' }}>
              管理员：{session.actor_id}
            </Typography.Text>
            <Button
              icon={<LogoutOutlined />}
              loading={busy}
              onClick={logout}
              danger
              size="small"
            >
              退出
            </Button>
          </Space>
        )}
      </Layout.Header>

      <Layout.Content style={{ padding: 24, maxWidth: 1280, margin: '0 auto', width: '100%' }}>
        {failure && <Alert type="error" message={failure} showIcon style={{ marginBottom: 16 }} />}
        {loading ? (
          <Card loading aria-label="正在恢复会话" />
        ) : (
          <Routes>
            <Route
              path="/login"
              element={session ? <Navigate to="/admin" replace /> : loginPage}
            />
            <Route path="/admin" element={protectedPage(<Dashboard session={session} />)} />
            <Route path="/admin/requests" element={protectedPage(<History />)} />
            <Route path="/admin/sources" element={protectedPage(<KnowledgeSources />)} />
            <Route path="/admin/candidates" element={protectedPage(<KnowledgeCandidates />)} />
            <Route path="/admin/publications" element={protectedPage(<KnowledgePublications />)} />
            <Route path="/admin/observations" element={protectedPage(<KnowledgeObservations />)} />
            <Route path="/admin/graph" element={protectedPage(<KnowledgeGraph />)} />
            <Route path="/admin/audit" element={protectedPage(<SecurityAudit />)} />
            <Route path="*" element={<Navigate to={session ? '/admin' : '/login'} replace />} />
          </Routes>
        )}
      </Layout.Content>
      <Layout.Footer style={{ textAlign: 'center' }}>
        企业隐私网关 © 2026
      </Layout.Footer>
    </Layout>
  );
}

export const App = () => (
  <BrowserRouter>
    <Console />
  </BrowserRouter>
);
export default App;
