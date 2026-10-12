import { useState } from 'react';
import {
  Button,
  Card,
  Col,
  Descriptions,
  Drawer,
  Empty,
  Form,
  Input,
  Row,
  Space,
  Spin,
  Table,
  Tag,
  Typography,
  message,
} from 'antd';
import {
  BranchesOutlined,
  PlayCircleOutlined,
  ReloadOutlined,
} from '@ant-design/icons';
import { useMutation } from '@tanstack/react-query';
import {
  api,
  errorText,
  type GraphEdgeDTO,
  type GraphNodeDTO,
  type GraphQueryResponse,
} from '../api/client';

const DEFAULT_CYPHER =
  "MATCH (s:Entity)-[r:Claim]->(o:Entity) RETURN s, r, o LIMIT 50";

export function KnowledgeGraph() {
  const [cypherQuery, setCypherQuery] = useState(DEFAULT_CYPHER);
  const [queryResult, setQueryResult] = useState<GraphQueryResponse | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNodeDTO | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<GraphEdgeDTO | null>(null);

  const queryMutation = useMutation({
    mutationFn: (cypher: string) =>
      api.graphQuery({
        cypher,
        params: {},
        purpose: 'admin-graph-explorer',
      }),
    onSuccess: (data) => {
      setQueryResult(data);
      message.success(`图查询成功：耗时 ${data.execution_time_ms}ms，发现 ${data.nodes.length} 个节点，${data.edges.length} 条关系`);
    },
    onError: (err) => {
      message.error(`查询失败: ${errorText(err)}`);
    },
  });

  const rebuildMutation = useMutation({
    mutationFn: () => api.graphRebuild(),
    onSuccess: (data) => {
      message.success(`AGE 图投影全量重建完成：已同步 ${data.nodes_rebuilt} 个顶点，${data.edges_rebuilt} 条边`);
      queryMutation.mutate(cypherQuery);
    },
    onError: (err) => {
      message.error(`重建失败: ${errorText(err)}`);
    },
  });

  const handleRunQuery = () => {
    if (!cypherQuery.trim()) {
      message.warning('请输入 Cypher 查询语句');
      return;
    }
    queryMutation.mutate(cypherQuery);
  };

  const nodeColumns = [
    {
      title: '实体名称',
      dataIndex: 'name',
      key: 'name',
      render: (name: string, record: GraphNodeDTO) => (
        <Button
          type="link"
          style={{ padding: 0 }}
          onClick={() => setSelectedNode(record)}
        >
          {name}
        </Button>
      ),
    },
    {
      title: '类别',
      dataIndex: 'type',
      key: 'type',
      render: (type: string) => <Tag color="blue">{type}</Tag>,
    },
    {
      title: '实体 ID',
      dataIndex: 'id',
      key: 'id',
      render: (id: string) => <Typography.Text copyable ellipsis style={{ maxWidth: 180 }}>{id}</Typography.Text>,
    },
    {
      title: '所属租户 / 域',
      key: 'scope',
      render: (_: unknown, record: GraphNodeDTO) => (
        <span>{record.tenant_id} / {record.domain}</span>
      ),
    },
  ];

  const edgeColumns = [
    {
      title: '谓词关系',
      dataIndex: 'predicate',
      key: 'predicate',
      render: (predicate: string, record: GraphEdgeDTO) => (
        <Button
          type="link"
          style={{ padding: 0 }}
          onClick={() => setSelectedEdge(record)}
        >
          <Tag color="cyan">{predicate}</Tag>
        </Button>
      ),
    },
    {
      title: '极性 (Polarity)',
      dataIndex: 'polarity',
      key: 'polarity',
      render: (polarity: string) => (
        <Tag color={polarity === 'positive' ? 'green' : 'red'}>
          {polarity}
        </Tag>
      ),
    },
    {
      title: '模态 (Modality)',
      dataIndex: 'modality',
      key: 'modality',
      render: (modality: string) => (
        <Tag color={modality === 'asserted' ? 'purple' : 'orange'}>
          {modality}
        </Tag>
      ),
    },
    {
      title: '状态',
      dataIndex: 'is_active',
      key: 'is_active',
      render: (active: boolean) => (
        <Tag color={active ? 'success' : 'default'}>
          {active ? '已激活' : '已失效(Tombstone)'}
        </Tag>
      ),
    },
    {
      title: '有效期截止',
      dataIndex: 'valid_until',
      key: 'valid_until',
      render: (valid: string) => <span>{valid}</span>,
    },
  ];

  return (
    <Space direction="vertical" size="large" style={{ width: '100%' }}>
      <Card
        title={
          <Space>
            <BranchesOutlined />
            <span>Apache AGE 知识图谱拓扑与 Cypher 分析</span>
          </Space>
        }
        extra={
          <Button
            icon={<ReloadOutlined />}
            loading={rebuildMutation.isPending}
            onClick={() => rebuildMutation.mutate()}
            danger
          >
            重建图投影 (Rebuild Projection)
          </Button>
        }
      >
        <Typography.Paragraph type="secondary">
            支持 Entity 节点与最多四跳 Claim 关系的 MATCH 查询、属性等值过滤、RETURN 和 LIMIT。后端强制租户与业务域隔离，只展示有效关系；其他语法会被拒绝。
        </Typography.Paragraph>

        <Form layout="vertical">
          <Form.Item label="openCypher 查询语句">
            <Input.TextArea
              rows={3}
              value={cypherQuery}
              onChange={(e) => setCypherQuery(e.target.value)}
              placeholder="MATCH (s:Entity)-[r:Claim]->(o:Entity) RETURN s, r, o LIMIT 50"
              style={{ fontFamily: 'monospace' }}
            />
          </Form.Item>
          <Button
            type="primary"
            icon={<PlayCircleOutlined />}
            loading={queryMutation.isPending}
            onClick={handleRunQuery}
          >
            执行受控图查询
          </Button>
        </Form>
      </Card>

      {queryMutation.isPending && (
        <Card style={{ textAlign: 'center', padding: '40px 0' }}>
          <Spin size="large" />
          <div style={{ marginTop: 8, color: '#8c8c8c' }}>正在执行 openCypher 拓扑遍历...</div>
        </Card>
      )}

      {queryResult && (
        <Row gutter={[16, 16]}>
          <Col span={12}>
            <Card
              title={`实体节点列表 (${queryResult.nodes.length})`}
              size="small"
            >
              <Table
                dataSource={queryResult.nodes}
                columns={nodeColumns}
                rowKey="id"
                pagination={{ pageSize: 8 }}
                size="small"
              />
            </Card>
          </Col>

          <Col span={12}>
            <Card
              title={`关系断言边列表 (${queryResult.edges.length})`}
              size="small"
            >
              <Table
                dataSource={queryResult.edges}
                columns={edgeColumns}
                rowKey="claim_id"
                pagination={{ pageSize: 8 }}
                size="small"
              />
            </Card>
          </Col>
        </Row>
      )}

      {!queryResult && !queryMutation.isPending && (
        <Card>
          <Empty description="点击上方的“执行受控图查询”探索关系知识图谱" />
        </Card>
      )}

      {/* 节点详情抽屉 */}
      <Drawer
        title="实体节点元数据详情"
        placement="right"
        width={480}
        onClose={() => setSelectedNode(null)}
        open={!!selectedNode}
      >
        {selectedNode && (
          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label="实体名称">{selectedNode.name}</Descriptions.Item>
            <Descriptions.Item label="实体类型">
              <Tag color="blue">{selectedNode.type}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="实体 UUID (UUID5)">
              <Typography.Text copyable>{selectedNode.id}</Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="租户 ID">{selectedNode.tenant_id}</Descriptions.Item>
            <Descriptions.Item label="业务域">{selectedNode.domain}</Descriptions.Item>
            <Descriptions.Item label="附加属性">
              <pre style={{ fontSize: 12 }}>
                {JSON.stringify(selectedNode.properties, null, 2)}
              </pre>
            </Descriptions.Item>
          </Descriptions>
        )}
      </Drawer>

      {/* 关系边详情抽屉 */}
      <Drawer
        title="知识主张 (Claim) 与发布证据详情"
        placement="right"
        width={520}
        onClose={() => setSelectedEdge(null)}
        open={!!selectedEdge}
      >
        {selectedEdge && (
          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label="谓词 (Predicate)">
              <Tag color="cyan">{selectedEdge.predicate}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="极性 (Polarity)">
              <Tag color={selectedEdge.polarity === 'positive' ? 'green' : 'red'}>
                {selectedEdge.polarity}
              </Tag>
            </Descriptions.Item>
            <Descriptions.Item label="模态 (Modality)">
              <Tag color={selectedEdge.modality === 'asserted' ? 'purple' : 'orange'}>
                {selectedEdge.modality}
              </Tag>
            </Descriptions.Item>
            <Descriptions.Item label="发布状态">
              <Tag color={selectedEdge.is_active ? 'success' : 'default'}>
                {selectedEdge.is_active ? '有效发布资产' : '已撤回/已失效 (Tombstoned)'}
              </Tag>
            </Descriptions.Item>
            <Descriptions.Item label="主张标识 (Claim ID)">
              <Typography.Text copyable>{selectedEdge.claim_id}</Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="发布标识 (Publication ID)">
              <Typography.Text copyable>{selectedEdge.publication_id}</Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="有效期截止">{selectedEdge.valid_until}</Descriptions.Item>
            <Descriptions.Item label="边扩展属性">
              <pre style={{ fontSize: 12 }}>
                {JSON.stringify(selectedEdge.properties, null, 2)}
              </pre>
            </Descriptions.Item>
          </Descriptions>
        )}
      </Drawer>
    </Space>
  );
}
