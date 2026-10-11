import { Card, Col, Row, Space, Typography, Tag, Button } from 'antd';
import {
  HistoryOutlined,
  BookOutlined,
  AuditOutlined,
  CheckCircleOutlined,
  SafetyCertificateOutlined,
  EyeOutlined,
  SendOutlined,
} from '@ant-design/icons';
import { Link } from 'react-router-dom';
import type { Session } from '../api/client';

interface DashboardProps {
  session: Session | null;
}

export function Dashboard({ session }: DashboardProps) {
  return (
    <Space direction="vertical" size="large" style={{ width: '100%' }}>
      <Card
        title={
          <Space>
            <SafetyCertificateOutlined style={{ color: '#1677ff', fontSize: 20 }} />
            <span>网关控制台概览</span>
          </Space>
        }
      >
        <Row gutter={[16, 16]}>
          <Col xs={24} md={12}>
            <Typography.Paragraph>
              <strong>当前管理员：</strong> {session?.actor_id ?? '未认证'}
            </Typography.Paragraph>
            <Typography.Paragraph>
              <strong>管理权限范围（Scope）：</strong>{' '}
              <Tag color="blue">{session?.scope ?? '无'}</Tag>
            </Typography.Paragraph>
            <Typography.Paragraph>
              <strong>认证时间：</strong> {session?.authenticated_at ?? '-'}
            </Typography.Paragraph>
          </Col>
          <Col xs={24} md={12}>
            <Typography.Paragraph>
              <strong>空闲超时时间（Idle）：</strong> {session?.idle_expires_at ?? '-'}
            </Typography.Paragraph>
            <Typography.Paragraph>
              <strong>绝对过期时间（Absolute）：</strong> {session?.absolute_expires_at ?? '-'}
            </Typography.Paragraph>
            <Typography.Paragraph type="secondary">
              所有管理写操作受会话绑定 CSRF 令牌保护，会话过期后将自动拒绝并登出。
            </Typography.Paragraph>
          </Col>
        </Row>
      </Card>

      <Typography.Title level={4}>运营管理功能</Typography.Title>
      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} lg={8}>
          <Card
            title={
              <Space>
                <HistoryOutlined style={{ color: '#1677ff' }} />
                <span>请求历史追溯</span>
              </Space>
            }
            extra={<Link to="/admin/requests"><Button type="link" size="small">进入</Button></Link>}
          >
            <Typography.Paragraph type="secondary">
              按时间、模型、协议和状态筛选网关入站请求，分阶段检查输入、脱敏、上游与还原全流程。
            </Typography.Paragraph>
          </Card>
        </Col>

        <Col xs={24} sm={12} lg={8}>
          <Card
            title={
              <Space>
                <BookOutlined style={{ color: '#52c41a' }} />
                <span>知识来源治理</span>
              </Space>
            }
            extra={<Link to="/admin/sources"><Button type="link" size="small">进入</Button></Link>}
          >
            <Typography.Paragraph type="secondary">
              管理已采集或申报的知识来源，核验归属与受众许可，执行单管理员治理登记或依法撤回。
            </Typography.Paragraph>
          </Card>
        </Col>

        <Col xs={24} sm={12} lg={8}>
          <Card
            title={
              <Space>
                <CheckCircleOutlined style={{ color: '#fa8c16' }} />
                <span>候选集审核</span>
              </Space>
            }
            extra={<Link to="/admin/candidates"><Button type="link" size="small">进入</Button></Link>}
          >
            <Typography.Paragraph type="secondary">
              审核由网关模型与流水线提取的知识候选，支持直接发布至资产库、驳回或受控字段修订。
            </Typography.Paragraph>
          </Card>
        </Col>

        <Col xs={24} sm={12} lg={8}>
          <Card
            title={
              <Space>
                <SendOutlined style={{ color: '#13c2c2' }} />
                <span>发布资产库</span>
              </Space>
            }
            extra={<Link to="/admin/publications"><Button type="link" size="small">进入</Button></Link>}
          >
            <Typography.Paragraph type="secondary">
              查看对外生效的知识发布版本及下游消费可用性状态，支持紧急撤回已发布资产。
            </Typography.Paragraph>
          </Card>
        </Col>

        <Col xs={24} sm={12} lg={8}>
          <Card
            title={
              <Space>
                <EyeOutlined style={{ color: '#722ed1' }} />
                <span>采集观察记录</span>
              </Space>
            }
            extra={<Link to="/admin/observations"><Button type="link" size="small">进入</Button></Link>}
          >
            <Typography.Paragraph type="secondary">
              浏览从网关通过流水线自动投递入 Spool 的原始最小知识观察事件与元数据。
            </Typography.Paragraph>
          </Card>
        </Col>

        <Col xs={24} sm={12} lg={8}>
          <Card
            title={
              <Space>
                <AuditOutlined style={{ color: '#eb2f96' }} />
                <span>安全审计与留证</span>
              </Space>
            }
            extra={<Link to="/admin/audit"><Button type="link" size="small">进入</Button></Link>}
          >
            <Typography.Paragraph type="secondary">
              按受控目录检索信封加密的留证记录，在严格配额与权限保护下安全调阅明文及审计事件流。
            </Typography.Paragraph>
          </Card>
        </Col>
      </Row>
    </Space>
  );
}
