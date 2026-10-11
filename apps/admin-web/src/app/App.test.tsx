import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import App from './App';

afterEach(() => vi.unstubAllGlobals());
describe('App session admission', () => {
  it('redirects anonymous visitors to login after checking the server session', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: { code: 'ADMIN_SESSION_INVALID' } }), { status: 401, headers: { 'Content-Type': 'application/json' } })));
    window.history.replaceState({}, '', '/admin/requests');
    render(<QueryClientProvider client={new QueryClient()}><App /></QueryClientProvider>);
    await waitFor(() => expect(screen.getByRole('button', { name: /登\s*录/ })).toBeInTheDocument(), { timeout: 10000 });
    expect(screen.getByText('企业隐私网关管理端')).toBeInTheDocument();
    expect(window.location.pathname).toBe('/login');
    expect(screen.queryByText('网关就绪')).not.toBeInTheDocument();
  }, 15000);
});
