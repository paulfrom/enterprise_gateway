import { useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Descriptions,
  Form,
  Input,
  InputNumber,
  Modal,
  Select,
  Space,
  Table,
  Tag,
  Typography,
  message,
} from 'antd';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  api,
  errorText,
  type SourceFilters,
  type Governance,
  type Withdraw,
} from '../api/client';

export function KnowledgeSources() {
  const queryClient = useQueryClient();
  const [filters, setFilters] = useState<SourceFilters>({ limit: 10 });
  const [cursors, setCursors] = useState<Array<string | undefined>>([undefined]);
  const [selectedId, setSelectedId] = useState<string>();
  const [governingSource, setGoverningSource] = useState<Record<string, unknown> | null>(null);
  const [withdrawingSource, setWithdrawingSource] = useState<Record<string, unknown> | null>(null);

  const [governForm] = Form.useForm<Governance>();
  const [withdrawForm] = Form.useForm<Withdraw>();

  const cursor = cursors[cursors.length - 1];
  const listing = useQuery({
    queryKey: ['admin-sources', filters, cursor],
    queryFn: ({ signal }) => api.sources({ ...filters, cursor }, signal),
  });

  const detail = useQuery({
    queryKey: ['admin-source-detail', selectedId],
    queryFn: ({ signal }) => api.sourceDetail(selectedId!, undefined, signal),
    enabled: !!selectedId,
    gcTime: 0,
  });

  const governMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Governance }) => api.governSource(id, data),
    onSuccess: () => {
      message.success('知识来源治理登记成功');
      setGoverningSource(null);
      governForm.resetFields();
      void queryClient.invalidateQueries({ queryKey: ['admin-sources'] });
    },
    onError: (err) => {
      message.error(errorText(err));
    },
  });

  const withdrawMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Withdraw }) => api.withdrawSource(id, data),
    onSuccess: () => {
      message.success('知识来源已成功撤回');
      setWithdrawingSource(null);
      withdrawForm.resetFields();
      void queryClient.invalidateQueries({ queryKey: ['admin-sources'] });
    },
    onError: (err) => {
      message.error(errorText(err));
    },
  });

  function startGovern(record: Record<string, unknown>) {
    setGoverningSource(record);
    governForm.setFieldsValue({
      source_version: String(record.source_version ?? ''),
      expected_governance_version: record.governance_version ? String(record.governance_version) : undefined,
      ownership: (record.ownership as 'confirmed' | 'unassigned') ?? 'confirmed',
      use: String(record.use ?? 'general-knowledge'),
      audiences: Array.isArray(record.audiences) ? (record.audiences as string[]) : ['internal-ai'],
      valid_until: record.valid_until ? String(record.valid_until) : new Date(Date.now() + 86400000 * 30).toISOString(),
      basis: '',
    });
  }

  function startWithdraw(record: Record<string, unknown>) {
    setWithdrawingSource(record);
    withdrawForm.setFieldsValue({
      source_version: String(record.source_version ?? ''),
      basis: '',
    });
  }

  const columns = [
    {
      title: '来源 ID',
      dataIndex: 'source_id',
      key: 'source_id',
      render: (val: unknown) => <Typography.Text copyable ellipsis style={{ maxWidth: 160 }}>{String(val ?? '')}</Typography.Text>,
    },
    {
      title: '版本',
      dataIndex: 'source_version',
      key: 'source_version',
      render: (val: unknown) => <Tag>{String(val ?? '-')}</Tag>,
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (val: unknown) => {
        const text = String(val ?? '');
        const color = text === 'verified' ? 'green' : text === 'withdrawn' ? 'red' : 'default';
        return <Tag color={color}>{text || 'unverified'}</Tag>;
      },
    },
    {
      title: '用途 / 受众',
      key: 'usage',
      render: (_: unknown, row: Record<string, unknown>) => (
        <Space direction="vertical" size={2}>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            用途: {String(row.use ?? '-')}
          </Typography.Text>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            受众: {Array.isArray(row.audiences) ? row.audiences.join(', ') : '-'}
          </Typography.Text>
        </Space>
      ),
    },
    {
      title: '有效期至',
      dataIndex: 'valid_until',
      key: 'valid_until',
      render: (val: unknown) => String(val ?? '-'),
    },
    {
      title: '操作',
      key: 'actions',
      render: (_: unknown, row: Record<string, unknown>) => {
        const id = String(row.source_id ?? '');
        return (
          <Space size="small">
            <Button size="small" onClick={() => setSelectedId(id)}>
              详情
            </Button>
            <Button size="small" type="primary" onClick={() => startGovern(row)}>
              治理登记
            </Button>
            <Button size="small" danger onClick={() => startWithdraw(row)}>
              撤回
            </Button>
          </Space>
        );
      },
    },
  ];

  return (
    <>
      <Card title="知识来源治理（Sources）">
        <Form
          layout="inline"
          initialValues={filters}
          onFinish={(values: SourceFilters) => {
            setFilters(values);
            setCursors([undefined]);
            setSelectedId(undefined);
          }}
          style={{ gap: 12, marginBottom: 20 }}
        >
          <Form.Item name="status" label="状态">
            <Select
              style={{ width: 140 }}
              allowClear
              options={[
                { value: 'unverified', label: '未验证' },
                { value: 'verified', label: '已验证' },
                { value: 'withdrawn', label: '已撤回' },
                { value: 'expired', label: '已过期' },
              ]}
            />
          </Form.Item>
          <Form.Item name="use" label="用途">
            <Input placeholder="用途名称" allowClear />
          </Form.Item>
          <Form.Item name="audience" label="受众">
            <Input placeholder="受众标识" allowClear />
          </Form.Item>
          <Form.Item name="limit" label="每页">
            <InputNumber min={1} max={100} />
          </Form.Item>
          <Button htmlType="submit" type="primary">
            筛选
          </Button>
        </Form>

        {listing.error && (
          <Alert
            type="error"
            message={errorText(listing.error)}
            action={<Button onClick={() => void listing.refetch()}>重试</Button>}
            style={{ marginBottom: 16 }}
          />
        )}

        <Table
          rowKey={(r) => String(r.source_id ?? Math.random())}
          loading={listing.isFetching}
          dataSource={listing.data?.items ?? []}
          pagination={false}
          locale={{ emptyText: '没有知识来源记录' }}
          columns={columns}
          scroll={{ x: 800 }}
        />

        <Space style={{ marginTop: 16 }}>
          <Button
            disabled={cursors.length === 1 || listing.isFetching}
            onClick={() => setCursors((val) => val.slice(0, -1))}
          >
            上一页
          </Button>
          <Typography.Text>第 {cursors.length} 页</Typography.Text>
          <Button
            disabled={!listing.data?.next_cursor || listing.isFetching}
            onClick={() => setCursors((val) => [...val, listing.data!.next_cursor!])}
          >
            下一页
          </Button>
        </Space>
      </Card>

      {/* 来源详情 Modal */}
      <Modal
        title="知识来源详情"
        open={!!selectedId}
        onCancel={() => setSelectedId(undefined)}
        footer={null}
        width={720}
        destroyOnClose
      >
        {detail.error && <Alert type="error" message={errorText(detail.error)} />}
        {detail.isFetching && <Card loading />}
        {detail.data?.item && (
          <Descriptions bordered column={1} size="small">
            <Descriptions.Item label="来源 ID">{String(detail.data.item.source_id ?? '-')}</Descriptions.Item>
            <Descriptions.Item label="来源版本">{String(detail.data.item.source_version ?? '-')}</Descriptions.Item>
            <Descriptions.Item label="状态">{String(detail.data.item.status ?? '-')}</Descriptions.Item>
            <Descriptions.Item label="归属（Ownership）">{String(detail.data.item.ownership ?? '-')}</Descriptions.Item>
            <Descriptions.Item label="授权用途">{String(detail.data.item.use ?? '-')}</Descriptions.Item>
            <Descriptions.Item label="授权受众">
              {Array.isArray(detail.data.item.audiences) ? detail.data.item.audiences.join(', ') : '-'}
            </Descriptions.Item>
            <Descriptions.Item label="有效期至">{String(detail.data.item.valid_until ?? '-')}</Descriptions.Item>
            <Descriptions.Item label="完整元数据">
              <pre style={{ maxHeight: 200, overflow: 'auto' }}>
                {JSON.stringify(detail.data.item, null, 2)}
              </pre>
            </Descriptions.Item>
          </Descriptions>
        )}
      </Modal>

      {/* 治理确认 Modal */}
      <Modal
        title="确认来源治理与授权"
        open={!!governingSource}
        onCancel={() => setGoverningSource(null)}
        footer={null}
        destroyOnClose
      >
        <Form
          form={governForm}
          layout="vertical"
          onFinish={(values) => {
            const audiences = Array.isArray(values.audiences)
              ? values.audiences
              : String(values.audiences).split(',').map((s) => s.trim()).filter(Boolean);
            governMutation.mutate({
              id: String(governingSource?.source_id),
              data: {
                ...values,
                audiences,
              },
            });
          }}
        >
          <Form.Item name="source_version" label="当前来源版本" rules={[{ required: true }]}>
            <Input disabled />
          </Form.Item>
          <Form.Item name="expected_governance_version" label="期望治理版本（乐观锁）">
            <Input placeholder="留空则不校验前序治理版本" />
          </Form.Item>
          <Form.Item name="ownership" label="资产归属确认" rules={[{ required: true }]}>
            <Select
              options={[
                { value: 'confirmed', label: '已明确确认归属 (confirmed)' },
                { value: 'unassigned', label: '未明确归属 (unassigned)' },
              ]}
            />
          </Form.Item>
          <Form.Item name="use" label="允许用途" rules={[{ required: true }]}>
            <Input placeholder="如：general-knowledge, audit-only" />
          </Form.Item>
          <Form.Item name="audiences" label="受众列表" rules={[{ required: true }]}>
            <Select mode="tags" placeholder="输入并回车，如：internal-ai, tenant-worker" />
          </Form.Item>
          <Form.Item name="valid_until" label="有效期截止（ISO 8601）" rules={[{ required: true }]}>
            <Input placeholder="2026-12-31T23:59:59Z" />
          </Form.Item>
          <Form.Item name="basis" label="治理决策依据（审计追踪）" rules={[{ required: true }]}>
            <Input.TextArea rows={3} placeholder="管理员输入审批依据、合规单号或业务用途证明" />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={governMutation.isPending} block>
            提交治理登记
          </Button>
        </Form>
      </Modal>

      {/* 撤回来源 Modal */}
      <Modal
        title="撤回知识来源"
        open={!!withdrawingSource}
        onCancel={() => setWithdrawingSource(null)}
        footer={null}
        destroyOnClose
      >
        <Form
          form={withdrawForm}
          layout="vertical"
          onFinish={(values) => {
            withdrawMutation.mutate({
              id: String(withdrawingSource?.source_id),
              data: values,
            });
          }}
        >
          <Typography.Paragraph type="danger">
            撤回知识来源后，所有依赖此来源的知识发布将触发作废，且不可逆。
          </Typography.Paragraph>
          <Form.Item name="source_version" label="来源版本" rules={[{ required: true }]}>
            <Input disabled />
          </Form.Item>
          <Form.Item name="basis" label="撤回理由依据" rules={[{ required: true }]}>
            <Input.TextArea rows={3} placeholder="请输入撤回理由，将记入不可篡改审计记录" />
          </Form.Item>
          <Button danger type="primary" htmlType="submit" loading={withdrawMutation.isPending} block>
            确认撤回
          </Button>
        </Form>
      </Modal>
    </>
  );
}
