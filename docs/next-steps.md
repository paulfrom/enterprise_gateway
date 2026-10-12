# 后续工作

本文件只列当前代码尚未完成的装配与验证，不记录执行进度。已实现契约见 `contracts/`；后端管理路由和字段以 `gateway.admin_contract`、`contracts/admin.openapi.json` 为准。

## 1. 知识消费与资产复用部署

`knowledge.worker.GovernedConsumer`、授权导出和词典编译已有服务实现；`start_knowledge_worker.py` 当前只装配采集入库。下一步装配正常部署的消费执行器、Outbox 投递与回执，以及导出和词典编译作业。

- 提供受限消费连接与明确的消费受众、用途和有效期。
- 接通投递、消费成功、撤回及到期失效；状态必须来自实际回执与资产版本。
- 词典编译产物经完整保护包校验后发布；新请求使用新版本，在途请求保持原版本。

## 2. 管理 API 与运行作业

补齐运行指标、配置读取/校验/发布/回退、留存管理、维护与作业查询。对应目标入口为 `/api/admin/runtime`、`/api/admin/config/*`、`/api/admin/publications/export`、`/api/admin/dictionary/compile`、`/api/admin/retention`、`/api/admin/maintenance/*`、`/api/admin/jobs`。

- 所有入口复用管理员会话、同源检查及写操作 CSRF 校验，明确枚举可操作对象。
- 配置发布绑定预期版本、完整制品及幂等键，区分接受、执行完成和实际生效。
- 删除、密钥生命周期及恢复操作必须由可靠审计与真实资源结果支持。
- API 实现、OpenAPI、前端生成类型与路由枚举测试同步更新。

## 3. React 管理页面

当前 `App.tsx` 与 `History.tsx` 提供登录和历史。下一步接入已有知识来源、候选、发布、观察和审计 API；运行配置、复用资产、留存与维护页面依赖上一节相应 API。

- 显示服务端真实版本、期限、阻断原因、投递状态及作业结果。
- 来源确认、直接发布、拒绝、修订、撤回及审计读取使用现有权限边界。
- 浏览器覆盖会话到期、退出后的迟到响应、正文清除、版本冲突与依赖故障。

## 4. 实际部署验证

- 使用业务样本校准快速风险筛选与 NER，评估漏检、误报和长文本处理。
- 联调实际客户端、供应商协议及签名信任材料，确认严格字段准入与缓冲 SSE 的超时行为。
- 核验生产网络出口、数据库 TLS、IAM/KMS、资源权限、业务留存政策及备份恢复/删除。
- 使用现有 Linux、Compose、镜像和浏览器检查验证部署资源；合成测试结果不替代实际环境验证。

## 5. 知识图谱体系演进（OpenSPG / DeepKE / Apache AGE）

详见架构设计规范 [docs/knowledge-graph-design.md](knowledge-graph-design.md)。

- **上游标准化摄取**：已完成接口契约与抽象基类（`knowledge.ingestion.BaseKnowledgeImporter`）；下一步分步对接权威主数据、非结构化文档与受信任工具连接器。
- **关系抽取与证据校准（DeepKE）**：将 `extractor.py` 升级为解耦的多阶管线（NER -> RE -> AE），融合端侧离线轻量模型与语法规则双轨校验，加强否定（`Polarity.NEGATIVE`）与假设（`Modality.HYPOTHETICAL`）判定，模型生成内容严禁自证。
- **语义属性图与关系治理（OpenSPG）**：引入概念谓词强类型约束（Predicate Schema Guard），实现业务事实一致性与正负互斥检测（Disputed Claim），完善基于 UUID5 的实体对齐与别名链。
- **Apache AGE 图查询投影**：在已有 PostgreSQL 5433 上装配 `apache-age` 扩展，基于事务 Outbox 异步同步至只读图空间，支持受控 openCypher 多跳图查询，并在网关层强制注入租户过滤与审计留痕。
