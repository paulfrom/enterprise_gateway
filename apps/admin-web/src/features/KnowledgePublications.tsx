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
  type PublicationFilters,
  type Basis,
} from '../api/client';

export function KnowledgePublications() {
  const queryClient = useQueryClient();
  const [filters, setFilters] = useState<PublicationFilters>({ limit: 10 });
  const [cursors, setCursors] = useState<Array<string | undefined>>([undefined]);
  const [selectedId, setSelectedId] = useState<string>();
  const [revokingPub, setRevokingPub] = useState<Record<string, unknown> | null>(null);

  const [revokeForm] = Form.useForm<Basis>();

  const cursor = cursors[cursors.length - 1];
  const listing = useQuery({
    queryKey: ['admin-publications', filters, cursor],
    queryFn: ({ signal }) => api.publications({ ...filters, cursor }, signal),
  });

  const detail = useQuery({
    queryKey: ['admin-publication-detail', selectedId],
    queryFn: ({ signal }) => api.publicationDetail(selectedId!, undefined, undefined, signal),
    enabled: !!selectedId,
    gcTime: 0,
  });

  const revokeMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Basis }) => api.revokePublication(id, data),
    onSuccess: () => {
      message.success('发布资产已成功作废并撤回');
      setRevokingPub(null);
      revokeForm.resetFields();
      void queryClient.invalidateQueries({ queryKey: ['admin-publications'] });
    },
    onError: (err) => message.error(errorText(err)),
  });

  function startRevoke(record: Record<string, unknown>) {
    setRevokingPub(record);
    revokeForm.setFieldsValue({ basis: '' });
  }

  const columns = [
    {
      title: '发布资产 ID',
      dataIndex: 'publication_id',
      key: 'publication_id',
      render: (val: unknown) => <Typography.Text copyable ellipsis style={{ maxWidth: 160 }}>{String(val ?? '')}</Typography.Text>,
    },
    {
      title: '候选版本',
      dataIndex: 'candidate_version',
      key: 'candidate_version',
      render: (val: unknown) => <Tag>{String(val ?? '-')}</Tag>,
    },
    {
      title: '授权用途',
      dataIndex: 'use',
      key: 'use',
      render: (val: unknown) => String(val ?? '-'),
    },
    {
      title: '授权受众',
      dataIndex: 'audiences',
      key: 'audiences',
      render: (val: unknown) => (Array.isArray(val) ? val.join(', ') : String(val ?? '-')),
    },
    {
      title: '到期时间',
      dataIndex: 'valid_until',
      key: 'valid_until',
      render: (val: unknown) => String(val ?? '-'),
    },
    {
      title: '可用性状态',
      key: 'availability',
      render: (_: unknown, row: Record<string, unknown>) => {
        const avail = (row.availability as Record<string, unknown>) ?? {};
        const govStatus = String(avail.governance_status ?? 'active');
        const deliveryStatus = String(avail.delivery_status ?? '-');
        return (
          <Space direction="vertical" size={2}>
            <Tag color={govStatus === 'active' ? 'green' : 'red'}>{govStatus}</Tag>
            <Typography.Text type="secondary" style={{ fontSize: 11 }}>
              投递: {deliveryStatus}
            </Typography.Text>
          </Space>
        );
      },
    },
    {
      title: '操作',
      key: 'actions',
      render: (_: unknown, row: Record<string, unknown>) => {
        const id = String(row.publication_id ?? '');
        return (
          <Space size="small">
            <Button size="small" onClick={() => setSelectedId(id)}>
              详情
            </Button>
            <Button size="small" danger onClick={() => startRevoke(row)}>
              作废撤回
            </Button>
          </Space>
        );
      },
    },
  ];

  return (
    <>
      <Card title="发布资产库（Publications）">
        <Form
          layout="inline"
          initialValues={filters}
          onFinish={(values: PublicationFilters) => {
            setFilters(values);
            setCursors([undefined]);
            setSelectedId(undefined);
          }}
          style={{ gap: 12, marginBottom: 20 }}
        >
          <Form.Item name="consumer" label="评估消费者">
            <Input placeholder="输入受众标识" allowClear />
          </Form.Item>
          <Form.Item name="use" label="评估用途">
            <Input placeholder="输入用途标识" allowClear />
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
          rowKey={(r) => String(r.publication_id ?? Math.random())}
          loading={listing.isFetching}
          dataSource={listing.data?.items ?? []}
          pagination={false}
          locale={{ emptyText: '没有发布资产记录' }}
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

      {/* 资产详情 Modal */}
      <Modal
        title="发布资产详情与可用性评估"
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
            <Descriptions.Item label="资产 ID">{String(detail.data.item.publication_id ?? '-')}</Descriptions.Item>
            <Descriptions.Item label="候选版本">{String(detail.data.item.candidate_version ?? '-')}</Descriptions.Item>
            <Descriptions.Item label="授权用途">{String(detail.data.item.use ?? '-')}</Descriptions.Item>
            <Descriptions.Item label="授权受众">
              {Array.isArray(detail.data.item.audiences) ? detail.data.item.audiences.join(', ') : '-'}
            </Descriptions.Item>
            <Descriptions.Item label="有效期至">{String(detail.data.item.valid_until ?? '-')}</Descriptions.Item>
            <Descriptions.Item label="可用性结构 (Availability)">
              <pre style={{ maxHeight: 200, overflow: 'auto' }}>
                {JSON.stringify(detail.data.item.availability ?? {}, null, 2)}
              </pre>
            </Descriptions.Item>
          </Descriptions>
        )}
      </Modal>

      {/* 撤回发布 Modal */}
      <Modal
        title="作废撤回发布资产"
        open={!!revokingPub}
        onCancel={() => setRevokingPub(null)}
        footer={null}
        destroyOnClose
      >
        <Form
          form={revokeForm}
          layout="vertical"
          onFinish={(values) => {
            revokeMutation.mutate({
              id: String(revokingPub?.publication_id),
              data: values,
            });
          }}
        >
          <Typography.Paragraph type="danger">
            撤回发布后，下游消费者的复用资产将在下一次同步中作废，禁止继续用于推理或外部访问。
          </Typography.Paragraph>
          <Form.Item name="basis" label="撤回作废依据" rules={[{ required: true }]}>
            <Input.TextArea rows={3} placeholder="请输入撤回理由依据" />
          </Form.Item>
          <Button danger type="primary" htmlType="submit" loading={revokeMutation.isPending} block>
            确认撤回作废
          </Button>
        </Form>
      </Modal>
    </>
  );
}
