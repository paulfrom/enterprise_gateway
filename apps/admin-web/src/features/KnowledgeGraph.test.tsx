import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { KnowledgeGraph } from './KnowledgeGraph';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('KnowledgeGraph component', () => {
  it('renders graph query panel and executes cypher query successfully', async () => {
    const mockGraphResponse = {
      nodes: [
        {
          id: 'ent-1',
          name: '甲公司',
          type: 'ORG',
          tenant_id: 'tenant-test',
          domain: 'corp',
          properties: {},
        },
        {
          id: 'ent-2',
          name: '乙公司',
          type: 'ORG',
          tenant_id: 'tenant-test',
          domain: 'corp',
          properties: {},
        },
      ],
      edges: [
        {
          claim_id: 'claim-1',
          source_id: 'ent-1',
          target_id: 'ent-2',
          predicate: 'supplies',
          polarity: 'positive',
          modality: 'asserted',
          publication_id: 'pub-1',
          valid_until: '2026-12-31T00:00:00Z',
          is_active: true,
          properties: {},
        },
      ],
      raw_records: [],
      execution_time_ms: 12.5,
    };

    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify(mockGraphResponse), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      )
    );

    render(
      <QueryClientProvider client={new QueryClient()}>
        <KnowledgeGraph />
      </QueryClientProvider>
    );

    expect(screen.getByText('Apache AGE 知识图谱拓扑与 Cypher 分析')).toBeInTheDocument();
    expect(screen.getByText('执行受控图查询')).toBeInTheDocument();
    expect(screen.getByText('重建图投影（当前范围）')).toBeInTheDocument();

    const queryBtn = screen.getByRole('button', { name: /执行受控图查询/ });
    fireEvent.click(queryBtn);

    await waitFor(() => {
      expect(screen.getByText('甲公司')).toBeInTheDocument();
    });

    expect(screen.getByText('乙公司')).toBeInTheDocument();
    expect(screen.getByText('supplies')).toBeInTheDocument();
    expect(screen.getByText('已激活')).toBeInTheDocument();
  }, 15000);

  it('triggers graph rebuild successfully', async () => {
    const mockRebuildResponse = {
      nodes_rebuilt: 42,
      edges_rebuilt: 18,
      status: 'completed',
    };

    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify(mockRebuildResponse), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      )
    );

    render(
      <QueryClientProvider client={new QueryClient()}>
        <KnowledgeGraph />
      </QueryClientProvider>
    );

    const rebuildBtn = screen.getByRole('button', { name: /重建图投影/ });
    fireEvent.click(rebuildBtn);

    await waitFor(() => {
      expect(fetch).toHaveBeenCalledWith(
        '/api/admin/graph/rebuild',
        expect.objectContaining({ method: 'POST' })
      );
    });
  }, 15000);
});
