import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import App from './App';

afterEach(() => vi.unstubAllGlobals());

describe('App session admission and routes', () => {
  it('redirects anonymous visitors to login after checking the server session', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({ error: { code: 'ADMIN_SESSION_INVALID' } }),
          { status: 401, headers: { 'Content-Type': 'application/json' } }
        )
      )
    );
    window.history.replaceState({}, '', '/admin/requests');
    render(
      <QueryClientProvider client={new QueryClient()}>
        <App />
      </QueryClientProvider>
    );
    await waitFor(
      () => expect(screen.getByRole('button', { name: /登\s*录/ })).toBeInTheDocument(),
      { timeout: 10000 }
    );
    expect(screen.getByText('企业隐私网关管理端')).toBeInTheDocument();
    expect(window.location.pathname).toBe('/login');
    expect(screen.queryByText('网关就绪')).not.toBeInTheDocument();
  }, 15000);

  it('renders dashboard and navigation for authenticated session', async () => {
    const sessionPayload = {
      actor_id: 'admin',
      scope: 'test-tenant/test-domain',
      authenticated_at: '2026-10-11T10:00:00Z',
      idle_expires_at: '2026-10-11T10:30:00Z',
      absolute_expires_at: '2026-10-11T18:00:00Z',
      csrf_token: 'valid-csrf-token-12345',
    };
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify(sessionPayload), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      )
    );
    window.history.replaceState({}, '', '/admin');
    render(
      <QueryClientProvider client={new QueryClient()}>
        <App />
      </QueryClientProvider>
    );
    await waitFor(() => expect(screen.getByText('网关控制台概览')).toBeInTheDocument(), {
      timeout: 10000,
    });
    expect(screen.getByText('系统概览')).toBeInTheDocument();
    expect(screen.getByText('知识来源')).toBeInTheDocument();
    expect(screen.getByText('候选审核')).toBeInTheDocument();
    expect(screen.getByText('资产发布')).toBeInTheDocument();
    expect(screen.getByText('采集观察')).toBeInTheDocument();
    expect(screen.getByText('图谱分析')).toBeInTheDocument();
    expect(screen.getByText('安全审计')).toBeInTheDocument();
  }, 15000);
});
