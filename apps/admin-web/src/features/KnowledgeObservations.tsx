import { useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Descriptions,
  Form,
  InputNumber,
  Modal,
  Space,
  Table,
  Typography,
} from 'antd';
import { useQuery } from '@tanstack/react-query';
import { api, errorText, type ObservationFilters } from '../api/client';

export function KnowledgeObservations() {
  const [filters, setFilters] = useState<ObservationFilters>({ limit: 10 });
  const [cursors, setCursors] = useState<Array<string | undefined>>([undefined]);
  const [selectedId, setSelectedId] = useState<string>();

  const cursor = cursors[cursors.length - 1];
  const listing = useQuery({
    queryKey: ['admin-observations', filters, cursor],
    queryFn: ({ signal }) => api.observations({ ...filters, cursor }, signal),
  });

  const detail = useQuery({
    queryKey: ['admin-observation-detail', selectedId],
    queryFn: ({ signal }) => api.observationDetail(selectedId!, signal),
    enabled: !!selectedId,
    gcTime: 0,
  });

  const columns = [
    {
      title: '观察事件 ID',
      dataIndex: 'observation_id',
      key: 'observation_id',
      render: (val: unknown) => (
        <Typography.Text copyable ellipsis style={{ maxWidth: 180 }}>
          {String(val ?? '')}
        </Typography.Text>
      ),
    },
    {
      title: '产生时间',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (val: unknown) => String(val ?? '-'),
    },
    {
      title: '保护域 (Domain)',
      dataIndex: 'domain',
      key: 'domain',
      render: (val: unknown) => String(val ?? '-'),
    },
    {
      title: '用途',
      dataIndex: 'purpose',
      key: 'purpose',
      render: (val: unknown) => String(val ?? '-'),
    },
    {
      title: '来源坐标 / 键',
      dataIndex: 'source_key',
      key: 'source_key',
      render: (val: unknown) => String(val ?? '-'),
    },
    {
      title: '操作',
      key: 'actions',
      render: (_: unknown, row: Record<string, unknown>) => {
        const id = String(row.observation_id ?? '');
        return (
          <Button size="small" onClick={() => setSelectedId(id)}>
            查看详情
          </Button>
        );
      },
    },
  ];

  return (
    <>
      <Card title="知识采集观察记录（Observations）">
        <Form
          layout="inline"
          initialValues={filters}
          onFinish={(values: ObservationFilters) => {
            setFilters(values);
            setCursors([undefined]);
            setSelectedId(undefined);
          }}
          style={{ gap: 12, marginBottom: 20 }}
        >
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
          rowKey={(r) => String(r.observation_id ?? Math.random())}
          loading={listing.isFetching}
          dataSource={listing.data?.items ?? []}
          pagination={false}
          locale={{ emptyText: '没有知识观察记录' }}
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

      <Modal
        title="观察记录事件详情"
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
            <Descriptions.Item label="事件 ID">
              {String(detail.data.item.observation_id ?? '-')}
            </Descriptions.Item>
            <Descriptions.Item label="租户 / 域">
              {String(detail.data.item.tenant_id ?? '-')}/{String(detail.data.item.domain ?? '-')}
            </Descriptions.Item>
            <Descriptions.Item label="用途">
              {String(detail.data.item.purpose ?? '-')}
            </Descriptions.Item>
            <Descriptions.Item label="生成时刻">
              {String(detail.data.item.created_at ?? '-')}
            </Descriptions.Item>
            <Descriptions.Item label="原始事件载荷 (Spool Payload)">
              <pre style={{ maxHeight: 260, overflow: 'auto' }}>
                {JSON.stringify(detail.data.item, null, 2)}
              </pre>
            </Descriptions.Item>
          </Descriptions>
        )}
      </Modal>
    </>
  );
}
