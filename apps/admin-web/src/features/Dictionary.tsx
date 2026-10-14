import { useState } from 'react';
import {
  Alert, AutoComplete, Button, Card, Drawer, Form, Input, Popconfirm,
  Select, Space, Switch, Table, Tag, Typography,
} from 'antd';
import { PlusOutlined, SendOutlined } from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  api, ApiError, errorText, type DictionaryEdit, type DictionaryEntry, type DictionaryFilters,
} from '../api/client';

const types = ['PER', 'ORG', 'SUPPLIER', 'LOC', 'PHONE_NUMBER', 'CN_ID_NUMBER',
  'CN_USCC', 'ACCOUNT_NUMBER', 'CONTRACT_NUMBER', 'MONEY_AMOUNT', 'PROJECT', 'DEPARTMENT'];
type Editor = { entry?: DictionaryEntry; revision: number };

export function Dictionary() {
  const cache = useQueryClient();
  const [filters, setFilters] = useState<DictionaryFilters>({ offset: 0, limit: 50 });
  const [editor, setEditor] = useState<Editor>();
  const [showVersions, setShowVersions] = useState(false);
  const [failure, setFailure] = useState<string>();
  const [notice, setNotice] = useState<string>();
  const [conflict, setConflict] = useState(false);
  const [form] = Form.useForm<DictionaryEdit>();
  const listing = useQuery({
    queryKey: ['admin-dictionary', filters],
    queryFn: ({ signal }) => api.dictionary(filters, signal),
    gcTime: 0,
  });
  const versions = useQuery({
    queryKey: ['admin-dictionary-versions'],
    queryFn: ({ signal }) => api.dictionaryVersions(signal),
    enabled: showVersions,
    gcTime: 0,
  });
  const state = listing.data;

  function refresh() {
    void cache.invalidateQueries({ queryKey: ['admin-dictionary'] });
    void cache.invalidateQueries({ queryKey: ['admin-dictionary-versions'] });
  }
  function failed(error: unknown) {
    setFailure(errorText(error));
    if (error instanceof ApiError && error.code === 'DICTIONARY_REVISION_CONFLICT') {
      setConflict(true);
      refresh();
    }
  }
  const saving = useMutation({
    mutationFn: ({ body, entryId }: { body: DictionaryEdit; entryId?: string }) =>
      api.saveDictionaryEntry(body, entryId),
    onSuccess: () => {
      setEditor(undefined);
      form.resetFields();
      setFailure(undefined);
      setNotice('词条已保存到草稿。发布后用于脱敏。');
      refresh();
    },
    onError: failed,
  });
  const deleting = useMutation({
    mutationFn: (entry: DictionaryEntry) => api.deleteDictionaryEntry(entry.entry_id, state!.revision),
    onSuccess: () => {
      setFailure(undefined);
      setNotice('词条已从草稿删除。发布后生效。');
      refresh();
    },
    onError: failed,
  });
  const publishing = useMutation({
    mutationFn: () => api.publishDictionary(state!.revision),
    onSuccess: () => {
      setFailure(undefined);
      setNotice('词典已发布，用于新的聊天请求和文件脱敏。');
      refresh();
    },
    onError: failed,
  });
  const busy = saving.isPending || deleting.isPending || publishing.isPending;

  function openEditor(entry?: DictionaryEntry) {
    if (!state) return;
    setFailure(undefined);
    setNotice(undefined);
    setConflict(false);
    setEditor({ entry, revision: state.revision });
    form.resetFields();
    form.setFieldsValue({ text: entry?.text ?? '', entity_type: entry?.entity_type ?? 'ORG',
      enabled: entry?.enabled ?? true });
  }

  return (
    <Space direction="vertical" size="large" style={{ width: '100%' }}>
      <Card title="本地脱敏词典" extra={
        <Space>
          <Button onClick={() => setShowVersions((value) => !value)}>发布记录</Button>
          <Button aria-label="新增词条" icon={<PlusOutlined />} disabled={!state || busy} onClick={() => openEditor()}>新增词条</Button>
          <Button aria-label="发布词典" type="primary" icon={<SendOutlined />} loading={publishing.isPending}
            disabled={!state || state.revision === state.published_revision || busy}
            onClick={() => publishing.mutate()}>发布词典</Button>
        </Space>
      }>
        <Typography.Paragraph type="secondary">
          保存只更新草稿；发布后用于新请求和文件脱敏。实体的甲方、乙方、担保人等角色根据正文识别。
        </Typography.Paragraph>
        {state && <Space wrap style={{ marginBottom: 20 }}>
          <Tag color="green">已发布版本 {state.published_revision}</Tag>
          <Typography.Text>生效词条 {state.published_entries}</Typography.Text>
          <Tag color={state.revision === state.published_revision ? 'default' : 'orange'}>
            {state.revision === state.published_revision ? '草稿与发布版本一致' : '草稿有未发布修改'}
          </Tag>
        </Space>}
        {(listing.error || failure) && <Alert showIcon type="error"
          message={failure ?? errorText(listing.error)}
          action={<Button onClick={() => void listing.refetch()}>刷新</Button>}
          style={{ marginBottom: 16 }} />}
        {notice && <Alert showIcon type="success" message={notice} style={{ marginBottom: 16 }} />}
        <Form name="dictionary-filters" layout="inline" onFinish={(values: DictionaryFilters) => {
          setFilters({ ...values, offset: 0, limit: 50 });
          setNotice(undefined);
        }} style={{ gap: 12, marginBottom: 20 }}>
          <Form.Item name="query" label="实体文本"><Input allowClear maxLength={512} placeholder="搜索词条" /></Form.Item>
          <Form.Item name="entity_type" label="类型">
            <AutoComplete options={types.map((value) => ({ value }))} style={{ width: 170 }} allowClear />
          </Form.Item>
          <Form.Item name="enabled" label="状态">
            <Select allowClear style={{ width: 110 }} options={[
              { value: true, label: '启用' }, { value: false, label: '停用' },
            ]} />
          </Form.Item>
          <Button htmlType="submit">查询</Button>
        </Form>
        <Table<DictionaryEntry> rowKey="entry_id" dataSource={state?.items ?? []}
          loading={listing.isFetching} scroll={{ x: 760 }}
          locale={{ emptyText: '没有匹配的词条' }}
          pagination={{ current: Math.floor((filters.offset ?? 0) / 50) + 1, pageSize: 50,
            total: state?.total ?? 0, showSizeChanger: false,
            onChange: (page) => setFilters((value) => ({ ...value, offset: (page - 1) * 50 })) }}
          columns={[
            { title: '实体文本', dataIndex: 'text', key: 'text' },
            { title: '实体类型', dataIndex: 'entity_type', key: 'entity_type',
              render: (value: string) => <Tag>{value}</Tag> },
            { title: '状态', dataIndex: 'enabled', key: 'enabled',
              render: (value: boolean) => <Tag color={value ? 'green' : 'default'}>{value ? '启用' : '停用'}</Tag> },
            { title: '更新时间', dataIndex: 'updated_at', key: 'updated_at',
              render: (value: string) => new Date(value).toLocaleString() },
            { title: '操作', key: 'actions', render: (_, entry) => <Space>
              <Button aria-label="编辑" size="small" disabled={busy} onClick={() => openEditor(entry)}>编辑</Button>
              <Popconfirm title="从草稿删除此词条？" description="发布后才改变脱敏行为。"
                onConfirm={() => deleting.mutate(entry)} okText="删除" cancelText="取消">
                <Button size="small" danger disabled={busy}>删除</Button>
              </Popconfirm>
            </Space> },
          ]} />
      </Card>
      {showVersions && <Card title="词典发布记录">
        {versions.error && <Alert type="error" message={errorText(versions.error)} />}
        <Table rowKey="revision" dataSource={versions.data?.items ?? []} loading={versions.isFetching}
          pagination={false} locale={{ emptyText: '没有发布记录' }} columns={[
            { title: '版本', dataIndex: 'revision', key: 'revision' },
            { title: '生效词条', dataIndex: 'entries', key: 'entries' },
            { title: '发布人', dataIndex: 'created_by', key: 'created_by' },
            { title: '发布时间', dataIndex: 'created_at', key: 'created_at',
              render: (value: string) => new Date(value).toLocaleString() },
          ]} />
      </Card>}
      <Drawer title={editor?.entry ? '编辑词条' : '新增词条'} open={!!editor} width={440}
        onClose={() => { setEditor(undefined); form.resetFields(); }}
        destroyOnClose>
        {failure && <Alert type="error" message={failure} style={{ marginBottom: 16 }} />}
        <Form name="dictionary-editor" form={form} layout="vertical" onFinish={(values) => {
          if (!editor) return;
          saving.mutate({ entryId: editor.entry?.entry_id,
            body: { ...values, expected_revision: editor.revision } });
        }}>
          <Form.Item name="text" label="实体文本" rules={[
            { required: true, whitespace: true, message: '请输入需要保护的实体文本' },
          ]}><Input.TextArea rows={3} maxLength={512} showCount /></Form.Item>
          <Form.Item name="entity_type" label="实体类型" rules={[
            { required: true, message: '请输入实体类型' },
            { pattern: /^[A-Z][A-Z0-9_]{0,31}$/, message: '使用大写字母、数字和下划线，最多 32 字符' },
          ]}><AutoComplete options={types.map((value) => ({ value }))} /></Form.Item>
          <Form.Item name="enabled" label="启用此词条" valuePropName="checked"><Switch /></Form.Item>
          <Typography.Paragraph type="secondary">全称和简称分别登记为词条，以保留各自的原始写法。</Typography.Paragraph>
          {conflict && <Alert type="warning" message="词典已发生修改，请关闭编辑并重新打开后核对。" style={{ marginBottom: 16 }} />}
          <Button aria-label="保存草稿" htmlType="submit" type="primary" loading={saving.isPending} disabled={conflict}>保存草稿</Button>
        </Form>
      </Drawer>
    </Space>
  );
}
