import { useState } from 'react';
import { Alert, Button, Card, Form, Input, InputNumber, Modal, Select, Space, Table, Tabs, Typography } from 'antd';
import { useQuery } from '@tanstack/react-query';
import { api, errorText, type HistoryFilters } from '../api/client';

function explain(body: string | null, media: string | null): string {
  if (body === null) return '此阶段未产生正文';
  if (media === 'application/json') { try { return JSON.stringify(JSON.parse(body), null, 2); } catch { return body; } }
  if (media === 'text/event-stream') return body.split('\n').map(line => {
    if (!line.startsWith('data:')) return line;
    try { return 'data: ' + JSON.stringify(JSON.parse(line.slice(5)), null, 2); } catch { return line; }
  }).join('\n');
  return body;
}
export function History() {
  const [filters, setFilters] = useState<HistoryFilters>({ limit: 10 });
  const [cursors, setCursors] = useState<Array<string | undefined>>([undefined]);
  const [selected, setSelected] = useState<string>();
  const [copied, setCopied] = useState<string>();
  const cursor = cursors[cursors.length - 1];
  const listing = useQuery({ queryKey: ['history', filters, cursor], queryFn: ({ signal }) => api.history({ ...filters, cursor }, signal) });
  const detail = useQuery({ queryKey: ['history-detail', selected], queryFn: ({ signal }) => api.detail(selected!, signal), enabled: !!selected, gcTime: 0 });
  return <>
    <Card title="请求历史">
      <Form layout="inline" initialValues={filters} onFinish={(values: HistoryFilters) => { setFilters(values); setCursors([undefined]); setSelected(undefined); }} style={{ gap: 12, marginBottom: 20 }}>
        <Form.Item name="model" label="模型"><Input placeholder="模型名称" allowClear /></Form.Item>
        <Form.Item name="protocol" label="协议"><Select style={{ width: 190 }} allowClear options={['deepseek-chat-completions', 'claude-messages'].map(value => ({ value, label: value }))} /></Form.Item>
        <Form.Item name="status" label="状态"><Select style={{ width: 130 }} allowClear options={['processing','completed','blocked','failed','partial'].map(value => ({ value, label: value }))} /></Form.Item>
        <Form.Item name="error_code" label="错误码"><Input allowClear /></Form.Item>
        <Form.Item name="created_after" label="开始时间"><Input placeholder="ISO 8601（含时区）" /></Form.Item>
        <Form.Item name="created_before" label="结束时间"><Input placeholder="ISO 8601（含时区）" /></Form.Item>
        <Form.Item name="limit" label="每页"><InputNumber min={1} max={100} /></Form.Item>
        <Button htmlType="submit" type="primary">筛选</Button>
      </Form>
      {listing.error && <Alert type="error" message={errorText(listing.error)} action={<Button onClick={() => void listing.refetch()}>重试</Button>} />}
      <Table rowKey="request_id" loading={listing.isFetching} dataSource={listing.data?.items ?? []} pagination={false} locale={{ emptyText: '没有请求记录' }} scroll={{ x: 800 }} columns={[
        { title: '创建时间', dataIndex: 'created_at' }, { title: '模型', dataIndex: 'model' },
        { title: '协议', dataIndex: 'protocol' }, { title: '状态', dataIndex: 'status' }, { title: '错误码', dataIndex: 'error_code' },
        { title: '操作', render: (_, row) => <Button onClick={() => { setSelected(row.request_id); setCopied(undefined); }}>查看详情</Button> },
      ]} />
      <Space style={{ marginTop: 16 }}>
        <Button disabled={cursors.length === 1 || listing.isFetching} onClick={() => setCursors(value => value.slice(0, -1))}>上一页</Button>
        <Typography.Text>第 {cursors.length} 页</Typography.Text>
        <Button disabled={!listing.data?.next_cursor || listing.isFetching} onClick={() => setCursors(value => [...value, listing.data!.next_cursor!])}>下一页</Button>
      </Space>
    </Card>
    <Modal title="请求详情" open={!!selected} onCancel={() => setSelected(undefined)} footer={null} width={1000} destroyOnClose>
      {detail.error && <Alert type="error" message={errorText(detail.error)} />}
      {detail.isFetching && <Card loading />}
      {detail.data && <><Typography.Paragraph>模型：{detail.data.model} · 状态：{detail.data.status}</Typography.Paragraph>
        <Tabs items={detail.data.stages.map(stage => ({ key: stage.stage, label: ({ input: '输入', redacted: '脱敏', upstream: '上游', restored: '还原' })[stage.stage], children: <>
          <Space><Typography.Text>状态：{stage.state} · {stage.media_type ?? '无正文'}</Typography.Text>
            <Button disabled={stage.body === null} onClick={async () => { try { await navigator.clipboard.writeText(stage.body!); setCopied('已复制原始正文'); } catch { setCopied('复制失败，请检查浏览器权限'); } }}>复制正文</Button>
            <Typography.Text role="status">{copied}</Typography.Text>
          </Space>
          <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', maxHeight: '55vh', overflow: 'auto' }}>{explain(stage.body, stage.media_type)}</pre>
        </> }))} />
      </>}
    </Modal>
  </>;
}
