import React from 'react';
import { Layout, Typography, Card, Space, Badge } from 'antd';
import { SafetyCertificateOutlined } from '@ant-design/icons';

const { Header, Content, Footer } = Layout;
const { Title, Text } = Typography;

export const App: React.FC = () => {
  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Header
        style={{
          display: 'flex',
          alignItems: 'center',
          backgroundColor: '#001529',
          padding: '0 24px',
        }}
      >
        <SafetyCertificateOutlined
          style={{ fontSize: 24, color: '#1677ff', marginRight: 12 }}
        />
        <Title level={4} style={{ color: '#fff', margin: 0 }}>
          企业隐私网关管理端
        </Title>
      </Header>
      <Content style={{ padding: '24px', maxWidth: 1200, margin: '0 auto', width: '100%' }}>
        <Card title="系统概览" variant="borderless">
          <Space direction="vertical" size="middle" style={{ width: '100%' }}>
            <div>
              <Text strong>服务状态：</Text>
              <Badge status="processing" text="网关就绪" style={{ marginLeft: 8 }} />
            </div>
            <div>
              <Text type="secondary">
                React + TypeScript + Vite + Ant Design 管理端工程骨架已建立。
              </Text>
            </div>
          </Space>
        </Card>
      </Content>
      <Footer style={{ textAlign: 'center', color: '#8c8c8c' }}>
        企业隐私网关 &copy; 2026
      </Footer>
    </Layout>
  );
};

export default App;
