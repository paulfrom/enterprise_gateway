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
  type CandidateFilters,
  type Publish,
  type Basis,
  type Revise,
} from '../api/client';

export function KnowledgeCandidates() {
  const queryClient = useQueryClient();
  const [filters, setFilters] = useState<CandidateFilters>({ limit: 10 });
  const [cursors, setCursors] = useState<Array<string | undefined>>([undefined]);
  const [selectedId, setSelectedId] = useState<string>();

  const [publishingCandidate, setPublishingCandidate] = useState<Record<string, unknown> | null>(null);
  const [rejectingCandidate, setRejectingCandidate] = useState<Record<string, unknown> | null>(null);
  const [revisingCandidate, setRevisingCandidate] = useState<Record<string, unknown> | null>(null);

  const [publishForm] = Form.useForm<Publish>();
  const [rejectForm] = Form.useForm<Basis>();
  const [reviseForm] = Form.useForm<Revise & { modifications_raw: string }>();

  const cursor = cursors[cursors.length - 1];
  const listing = useQuery({
    queryKey: ['admin-candidates', filters, cursor],
    queryFn: ({ signal }) => api.candidates({ ...filters, cursor }, signal),
  });

  const detail = useQuery({
    queryKey: ['admin-candidate-detail', selectedId],
    queryFn: ({ signal }) => api.candidateDetail(selectedId!, undefined, undefined, signal),
    enabled: !!selectedId,
    gcTime: 0,
  });

  const publishMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Publish }) => api.publishCandidate(id, data),
    onSuccess: () => {
      message.success('候选知识已成功发布为资产');
      setPublishingCandidate(null);
      publishForm.resetFields();
      void queryClient.invalidateQueries({ queryKey: ['admin-candidates'] });
    },
    onError: (err) => message.error(errorText(err)),
  });

  const rejectMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Basis }) => api.rejectCandidate(id, data),
    onSuccess: () => {
      message.success('候选知识已驳回');
      setRejectingCandidate(null);
      rejectForm.resetFields();
      void queryClient.invalidateQueries({ queryKey: ['admin-candidates'] });
    },
    onError: (err) => message.error(errorText(err)),
  });

  const reviseMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Revise }) => api.reviseCandidate(id, data),
    onSuccess: () => {
      message.success('候选知识已生成新修订版本');
      setRevisingCandidate(null);
      reviseForm.resetFields();
      void queryClient.invalidateQueries({ queryKey: ['admin-candidates'] });
    },
    onError: (err) => message.error(errorText(err)),
  });

  function startPublish(record: Record<string, unknown>) {
    setPublishingCandidate(record);
    publishForm.setFieldsValue({
      expected_version: Number(record.candidate_version ?? 1),
      use: String(record.use ?? 'general-knowledge'),
      audiences: Array.isArray(record.audiences) ? (record.audiences as string[]) : ['internal-ai'],
      valid_until: record.valid_until ? String(record.valid_until) : new Date(Date.now() + 86400000 * 30).toISOString(),
      basis: '',
    });
  }

  function startReject(record: Record<string, unknown>) {
    setRejectingCandidate(record);
    rejectForm.setFieldsValue({ basis: '' });
  }

  function startRevise(record: Record<string, unknown>) {
    setRevisingCandidate(record);
    reviseForm.setFieldsValue({
      basis: '',
      modifications_raw: JSON.stringify(record.content ?? {}, null, 2),
    });
  }

  const columns = [
    {
      title: '候选 ID',
      dataIndex: 'candidate_id',
      key: 'candidate_id',
      render: (val: unknown) => <Typography.Text copyable ellipsis style={{ maxWidth: 160 }}>{String(val ?? '')}</Typography.Text>,
    },
    {
      title: '版本',
      dataIndex: 'candidate_version',
      key: 'candidate_version',
      render: (val: unknown) => <Tag>{String(val ?? '-')}</Tag>,
    },
    {
      title: '状态',
      dataIndex: 'state',
      key: 'state',
      render: (val: unknown) => {
        const text = String(val ?? '');
        const color = text === 'approved' ? 'green' : text === 'rejected' ? 'red' : text === 'revised' ? 'orange' : 'blue';
        return <Tag color={color}>{text || 'pending'}</Tag>;
      },
    },
    {
      title: '关联来源 ID',
      dataIndex: 'source_id',
      key: 'source_id',
      render: (val: unknown) => <Typography.Text copyable ellipsis style={{ maxWidth: 140 }}>{String(val ?? '-')}</Typography.Text>,
    },
    {
      title: '操作',
      key: 'actions',
      render: (_: unknown, row: Record<string, unknown>) => {
        const id = String(row.candidate_id ?? '');
        return (
          <Space size="small">
            <Button size="small" onClick={() => setSelectedId(id)}>
              详情
            </Button>
            <Button size="small" type="primary" onClick={() => startPublish(row)}>
              发布
            </Button>
            <Button size="small" onClick={() => startRevise(row)}>
              修订
            </Button>
            <Button size="small" danger onClick={() => startReject(row)}>
              驳回
            </Button>
          </Space>
        );
      },
    },
  ];

  return (
    <>
      <Card title="知识候选集审核（Candidates）">
        <Form
          layout="inline"
          initialValues={filters}
          onFinish={(values: CandidateFilters) => {
            setFilters(values);
            setCursors([undefined]);
            setSelectedId(undefined);
          }}
          style={{ gap: 12, marginBottom: 20 }}
        >
          <Form.Item name="state" label="状态">
            <Select
              style={{ width: 140 }}
              allowClear
              options={[
                { value: 'pending', label: '待审核' },
                { value: 'approved', label: '已发布' },
                { value: 'rejected', label: '已驳回' },
                { value: 'revised', label: '已修订' },
              ]}
            />
          </Form.Item>
          <Form.Item name="source_id" label="来源 ID">
            <Input placeholder="关联来源 ID" allowClear />
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
          rowKey={(r) => String(r.candidate_id ?? Math.random())}
          loading={listing.isFetching}
          dataSource={listing.data?.items ?? []}
          pagination={false}
          locale={{ emptyText: '没有候选记录' }}
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

      {/* 候选详情 Modal */}
      <Modal
        title="知识候选详情"
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
            <Descriptions.Item label="候选 ID">{String(detail.data.item.candidate_id ?? '-')}</Descriptions.Item>
            <Descriptions.Item label="候选版本">{String(detail.data.item.candidate_version ?? '-')}</Descriptions.Item>
            <Descriptions.Item label="状态">{String(detail.data.item.state ?? '-')}</Descriptions.Item>
            <Descriptions.Item label="关联来源 ID">{String(detail.data.item.source_id ?? '-')}</Descriptions.Item>
            <Descriptions.Item label="派生来源版本">{String(detail.data.item.derived_from ?? '-')}</Descriptions.Item>
            <Descriptions.Item label="内容与元数据">
              <pre style={{ maxHeight: 240, overflow: 'auto' }}>
                {JSON.stringify(detail.data.item, null, 2)}
              </pre>
            </Descriptions.Item>
          </Descriptions>
        )}
      </Modal>

      {/* 发布候选 Modal */}
      <Modal
        title="发布知识资产（单管理员一次提交）"
        open={!!publishingCandidate}
        onCancel={() => setPublishingCandidate(null)}
        footer={null}
        destroyOnClose
      >
        <Form
          form={publishForm}
          layout="vertical"
          onFinish={(values) => {
            const audiences = Array.isArray(values.audiences)
              ? values.audiences
              : String(values.audiences).split(',').map((s) => s.trim()).filter(Boolean);
            publishMutation.mutate({
              id: String(publishingCandidate?.candidate_id),
              data: {
                ...values,
                audiences,
              },
            });
          }}
        >
          <Form.Item name="expected_version" label="期望候选版本（并发乐观锁）" rules={[{ required: true }]}>
            <Input disabled />
          </Form.Item>
          <Form.Item name="use" label="允许用途" rules={[{ required: true }]}>
            <Input placeholder="例如：general-knowledge, audit-only" />
          </Form.Item>
          <Form.Item name="audiences" label="授权受众" rules={[{ required: true }]}>
            <Select mode="tags" placeholder="输入并回车" />
          </Form.Item>
          <Form.Item name="valid_until" label="有效期截止（ISO 8601）" rules={[{ required: true }]}>
            <Input placeholder="2026-12-31T23:59:59Z" />
          </Form.Item>
          <Form.Item name="basis" label="发布合规依据" rules={[{ required: true }]}>
            <Input.TextArea rows={3} placeholder="管理员审核确认依据与批准单号" />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={publishMutation.isPending} block>
            确认原子发布
          </Button>
        </Form>
      </Modal>

      {/* 驳回候选 Modal */}
      <Modal
        title="驳回知识候选"
        open={!!rejectingCandidate}
        onCancel={() => setRejectingCandidate(null)}
        footer={null}
        destroyOnClose
      >
        <Form
          form={rejectForm}
          layout="vertical"
          onFinish={(values) => {
            rejectMutation.mutate({
              id: String(rejectingCandidate?.candidate_id),
              data: values,
            });
          }}
        >
          <Form.Item name="basis" label="驳回理由" rules={[{ required: true }]}>
            <Input.TextArea rows={3} placeholder="请输入驳回理由，将持久化留存证据" />
          </Form.Item>
          <Button danger type="primary" htmlType="submit" loading={rejectMutation.isPending} block>
            确认驳回
          </Button>
        </Form>
      </Modal>

      {/* 修订候选 Modal */}
      <Modal
        title="修订知识候选"
        open={!!revisingCandidate}
        onCancel={() => setRevisingCandidate(null)}
        footer={null}
        destroyOnClose
      >
        <Form
          form={reviseForm}
          layout="vertical"
          onFinish={(values) => {
            try {
              const modifications = JSON.parse(values.modifications_raw || '{}');
              reviseMutation.mutate({
                id: String(revisingCandidate?.candidate_id),
                data: {
                  modifications,
                  basis: values.basis,
                },
              });
            } catch {
              message.error('修订内容不是合法的 JSON');
            }
          }}
        >
          <Form.Item name="modifications_raw" label="修订修改项 (JSON)" rules={[{ required: true }]}>
            <Input.TextArea rows={6} />
          </Form.Item>
          <Form.Item name="basis" label="修订依据" rules={[{ required: true }]}>
            <Input.TextArea rows={3} placeholder="说明本次修订的背景和原由" />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={reviseMutation.isPending} block>
            提交新修订版本
          </Button>
        </Form>
      </Modal>
    </>
  );
}
