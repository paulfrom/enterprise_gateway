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
  Tabs,
  Tag,
  Typography,
} from 'antd';
import { useQuery } from '@tanstack/react-query';
import {
  api,
  errorText,
  type AuditFilters,
  type AuditEventsFilters,
} from '../api/client';

export function SecurityAudit() {
  const [activeTab, setActiveTab] = useState<'records' | 'events'>('records');

  // Records state
  const [recordFilters, setRecordFilters] = useState<AuditFilters>({ limit: 10 });
  const [recordCursors, setRecordCursors] = useState<Array<string | undefined>>([undefined]);
  const [selectedRecordId, setSelectedRecordId] = useState<string>();
  const [copied, setCopied] = useState<string>();

  const recordCursor = recordCursors[recordCursors.length - 1];
  const recordsListing = useQuery({
    queryKey: ['admin-audit-records', recordFilters, recordCursor],
    queryFn: ({ signal }) => api.auditRecords({ ...recordFilters, cursor: recordCursor }, signal),
    enabled: activeTab === 'records',
  });

  const recordDetail = useQuery({
    queryKey: ['admin-audit-detail', selectedRecordId],
    queryFn: ({ signal }) => api.auditRecordDetail(selectedRecordId!, signal),
    enabled: !!selectedRecordId,
    gcTime: 0,
  });

  // Events state
  const [eventFilters, setEventFilters] = useState<AuditEventsFilters>({ limit: 10 });
  const [eventCursors, setEventCursors] = useState<Array<string | undefined>>([undefined]);
  const eventCursor = eventCursors[eventCursors.length - 1];
  const eventsListing = useQuery({
    queryKey: ['admin-audit-events', eventFilters, eventCursor],
    queryFn: ({ signal }) => api.auditEvents({ ...eventFilters, cursor: eventCursor }, signal),
    enabled: activeTab === 'events',
  });

  const recordColumns = [
    {
      title: '留证记录 ID',
      dataIndex: 'record_id',
      key: 'record_id',
      render: (val: unknown) => (
        <Typography.Text copyable ellipsis style={{ maxWidth: 160 }}>
          {String(val ?? '')}
        </Typography.Text>
      ),
    },
    {
      title: '意图 ID',
      dataIndex: 'intent_id',
      key: 'intent_id',
      render: (val: unknown) => (
        <Typography.Text copyable ellipsis style={{ maxWidth: 140 }}>
          {String(val ?? '-')}
        </Typography.Text>
      ),
    },
    {
      title: '域 / 存储桶',
      key: 'domain_bucket',
      render: (_: unknown, row: Record<string, unknown>) => (
        <span>
          {String(row.domain ?? '-')}/{String(row.bucket ?? '-')}
        </span>
      ),
    },
    {
      title: '产生时间',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (val: unknown) => String(val ?? '-'),
    },
    {
      title: '留存截止',
      dataIndex: 'retention_until',
      key: 'retention_until',
      render: (val: unknown) => String(val ?? '-'),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (val: unknown) => {
        const text = String(val ?? '');
        return <Tag color={text === 'available' ? 'green' : 'orange'}>{text || 'unknown'}</Tag>;
      },
    },
    {
      title: '操作',
      key: 'actions',
      render: (_: unknown, row: Record<string, unknown>) => {
        const id = String(row.record_id ?? '');
        return (
          <Button
            size="small"
            type="primary"
            onClick={() => {
              setSelectedRecordId(id);
              setCopied(undefined);
            }}
          >
            调阅明文
          </Button>
        );
      },
    },
  ];

  const eventColumns = [
    {
      title: '事件代码',
      dataIndex: 'event_code',
      key: 'event_code',
      render: (val: unknown) => <Tag color="blue">{String(val ?? '-')}</Tag>,
    },
    {
      title: '操作者',
      dataIndex: 'actor_id',
      key: 'actor_id',
      render: (val: unknown) => String(val ?? '-'),
    },
    {
      title: '操作时间',
      dataIndex: 'timestamp',
      key: 'timestamp',
      render: (val: unknown) => String(val ?? '-'),
    },
    {
      title: '会话摘要 / 凭证',
      dataIndex: 'session_digest',
      key: 'session_digest',
      render: (val: unknown) => (
        <Typography.Text copyable ellipsis style={{ maxWidth: 160 }}>
          {String(val ?? '-')}
        </Typography.Text>
      ),
    },
  ];

  return (
    <>
      <Card title="安全审计与留存管理（Audit & Retention）">
        <Tabs
          activeKey={activeTab}
          onChange={(k) => setActiveTab(k as 'records' | 'events')}
          items={[
            {
              key: 'records',
              label: '证据目录与明文调阅',
              children: (
                <>
                  <Form
                    layout="inline"
                    initialValues={recordFilters}
                    onFinish={(values: AuditFilters) => {
                      setRecordFilters(values);
                      setRecordCursors([undefined]);
                      setSelectedRecordId(undefined);
                    }}
                    style={{ gap: 12, marginBottom: 20 }}
                  >
                    <Form.Item name="intent_id" label="意图 ID">
                      <Input placeholder="ReleaseIntent ID" allowClear />
                    </Form.Item>
                    <Form.Item name="status" label="状态">
                      <Input placeholder="available / expired" allowClear />
                    </Form.Item>
                    <Form.Item name="limit" label="每页">
                      <InputNumber min={1} max={100} />
                    </Form.Item>
                    <Button htmlType="submit" type="primary">
                      筛选
                    </Button>
                  </Form>

                  {recordsListing.data?.catalog_backlog !== null &&
                    recordsListing.data?.catalog_backlog !== undefined && (
                      <Alert
                        type="info"
                        message={`证据目录扫描积压数：${recordsListing.data.catalog_backlog} 条`}
                        style={{ marginBottom: 16 }}
                      />
                    )}

                  {recordsListing.error && (
                    <Alert
                      type="error"
                      message={errorText(recordsListing.error)}
                      action={<Button onClick={() => void recordsListing.refetch()}>重试</Button>}
                      style={{ marginBottom: 16 }}
                    />
                  )}

                  <Table
                    rowKey={(r) => String(r.record_id ?? Math.random())}
                    loading={recordsListing.isFetching}
                    dataSource={recordsListing.data?.items ?? []}
                    pagination={false}
                    locale={{ emptyText: '没有留证记录' }}
                    columns={recordColumns}
                    scroll={{ x: 800 }}
                  />

                  <Space style={{ marginTop: 16 }}>
                    <Button
                      disabled={recordCursors.length === 1 || recordsListing.isFetching}
                      onClick={() => setRecordCursors((val) => val.slice(0, -1))}
                    >
                      上一页
                    </Button>
                    <Typography.Text>第 {recordCursors.length} 页</Typography.Text>
                    <Button
                      disabled={!recordsListing.data?.next_cursor || recordsListing.isFetching}
                      onClick={() => setRecordCursors((val) => [...val, recordsListing.data!.next_cursor!])}
                    >
                      下一页
                    </Button>
                  </Space>
                </>
              ),
            },
            {
              key: 'events',
              label: '受控调阅事件日志',
              children: (
                <>
                  <Form
                    layout="inline"
                    initialValues={eventFilters}
                    onFinish={(values: AuditEventsFilters) => {
                      setEventFilters(values);
                      setEventCursors([undefined]);
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

                  {eventsListing.error && (
                    <Alert
                      type="error"
                      message={errorText(eventsListing.error)}
                      action={<Button onClick={() => void eventsListing.refetch()}>重试</Button>}
                      style={{ marginBottom: 16 }}
                    />
                  )}

                  <Table
                    rowKey={(r) => String(r.timestamp ?? Math.random())}
                    loading={eventsListing.isFetching}
                    dataSource={eventsListing.data?.items ?? []}
                    pagination={false}
                    locale={{ emptyText: '没有调阅事件日志' }}
                    columns={eventColumns}
                    scroll={{ x: 800 }}
                  />

                  <Space style={{ marginTop: 16 }}>
                    <Button
                      disabled={eventCursors.length === 1 || eventsListing.isFetching}
                      onClick={() => setEventCursors((val) => val.slice(0, -1))}
                    >
                      上一页
                    </Button>
                    <Typography.Text>第 {eventCursors.length} 页</Typography.Text>
                    <Button
                      disabled={!eventsListing.data?.next_cursor || eventsListing.isFetching}
                      onClick={() => setEventCursors((val) => [...val, eventsListing.data!.next_cursor!])}
                    >
                      下一页
                    </Button>
                  </Space>
                </>
              ),
            },
          ]}
        />
      </Card>

      {/* 调阅明文 Modal */}
      <Modal
        title="审计留证记录受控调阅"
        open={!!selectedRecordId}
        onCancel={() => setSelectedRecordId(undefined)}
        footer={null}
        width={840}
        destroyOnClose
      >
        {recordDetail.error && <Alert type="error" message={errorText(recordDetail.error)} />}
        {recordDetail.isFetching && <Card loading />}
        {recordDetail.data && (
          <Space direction="vertical" style={{ width: '100%' }}>
            <Descriptions bordered column={2} size="small">
              <Descriptions.Item label="记录 ID">
                {String(recordDetail.data.item.record_id)}
              </Descriptions.Item>
              <Descriptions.Item label="意图 ID">
                {String(recordDetail.data.item.intent_id)}
              </Descriptions.Item>
              <Descriptions.Item label="产生时间">
                {String(recordDetail.data.item.created_at)}
              </Descriptions.Item>
              <Descriptions.Item label="有效期至">
                {String(recordDetail.data.item.retention_until)}
              </Descriptions.Item>
              <Descriptions.Item label="证据 SHA-256" span={2}>
                <Typography.Text copyable code>
                  {String(recordDetail.data.item.evidence_sha256)}
                </Typography.Text>
              </Descriptions.Item>
            </Descriptions>

            <Space style={{ marginTop: 8 }}>
              <Typography.Text strong>解密明文内容：</Typography.Text>
              <Button
                size="small"
                onClick={async () => {
                  try {
                    await navigator.clipboard.writeText(recordDetail.data!.plaintext);
                    setCopied('已复制明文');
                  } catch {
                    setCopied('复制失败，请检查浏览器权限');
                  }
                }}
              >
                复制明文
              </Button>
              {copied && <Typography.Text type="success">{copied}</Typography.Text>}
            </Space>

            <pre
              style={{
                whiteSpace: 'pre-wrap',
                overflowWrap: 'anywhere',
                maxHeight: '45vh',
                overflow: 'auto',
                background: '#f5f5f5',
                padding: 12,
                borderRadius: 4,
              }}
            >
              {recordDetail.data.plaintext}
            </pre>
          </Space>
        )}
      </Modal>
    </>
  );
}
