# 管理控制台契约（认证、会话、授权与单管理员发布）

本契约定义管理员登录、服务端会话、统一管理授权、管理路由、知识单管理员发布与数据库结构契约。管理端只供管理员使用；当前只有一个固定账号 admin。字段与路由以 `gateway.admin_contract` 和 `contracts/admin.openapi.json` 为准。

当前管理端页面提供登录、会话恢复、退出和请求历史；后端另提供知识治理与审计 API。尚待装配内容集中记录在 [后续工作](../next-steps.md)。

## 1. 账号与密码

- 固定用户名 admin，初始密码由部署方在显式初始化时指定。
- 服务端运行态只保存随机盐（至少16字节）与 scrypt 派生值（N=2^17、r=8、p=1，设置足够 maxmem），不保存明文密码；登录页不预填、不内置正确密码。
- 登录校验限并发，重 CPU 派生不在事件循环内执行；初始化与校验均验证实际运行环境可用，不降级为明文比较或弱哈希。
- 显式初始化工具（`scripts/prepare_admin_state.py`）只作用于不存在的新管理员状态；重复初始化拒绝，服务重启不覆盖状态或重置默认账号。

## 2. 服务端会话

- 会话令牌为 32 字节密码学随机不透明值，浏览器只通过 Cookie 携带；服务端仅保存令牌摘要与会话记录。
- 固定空闲期限 30 分钟、绝对期限 8 小时，由服务端时钟执行。正常业务请求刷新空闲期限，绝对期限不延长；后台自动状态轮询不延长空闲期限。
- 每次登录签发新令牌；退出持久注销会话。伪造、到期、已注销或损坏会话一律拒绝。
- 管理员状态与会话位于持久状态卷的 admin 专用目录，沿用 durable_write、OS 锁与原子提交模式，明确进程间互斥、崩溃恢复、配额与过期清理；不使用仅进程内缓存代替权威存储。
- 恢复管理员状态备份时重建会话代际并使恢复前会话失效；不能恢复已注销令牌为有效会话。
- Cookie 固定 `Path=/`、不设置 Domain，HttpOnly、SameSite=Strict；HTTPS 设置 Secure，HTTP 按既有显式传输配置工作，不新增强制 TLS 或降级分支。
- 密码、Cookie 及 CSRF token 不写 localStorage、sessionStorage、URL、分析遥测或业务日志；CSRF token 仅在内存使用并随会话绑定。
- 登录节流：每来源地址每分钟至多 5 次失败尝试，并对总密码校验并发限额；客户端不能用自报转发头改变来源地址。登录错误统一返回，不泄漏比较细节。登录成功、刷新与失败登录均留认证事件。

## 3. AdminContext 与统一授权

- 管理会话产生不可由客户端构造的 `AdminContext`：actor_id=admin、部署管理范围（租户/保护域）、session_reference、认证时间与到期时间。所有管理 API 从会话取得该上下文，不接受客户端自报角色、租户、域或 ACL 授予管理权。
- 统一管理员依赖逐请求保护全部管理读写 API；写操作同时校验同源及会话绑定 CSRF token，严格校验请求 schema 和目标标识，拒绝任意文件路径、SQL、Python 模块或 shell 命令。
- 同步正文释放前再次校验会话和期限；关键审计失败不释放正文。
- 管理授权不改变数据生命周期与业务有效性：到期、已销毁、未产生的正文不能伪造为可读。

## 4. 路由契约

页面：`GET /login`（登录页，已登录可进入 /admin）；`GET /admin` 及 /admin 下管理页面（未登录跳转 /login）。

API（全部经统一管理员依赖）：

| 方法与路由 | 语义 |
|---|---|
| POST /api/admin/login | 严格 username/password，正确凭据签发 Cookie，统一错误与节流，验证同源 |
| GET /api/admin/session | 当前管理员、管理范围、有效期及 CSRF token；无有效会话 401 |
| POST /api/admin/logout | 立即持久注销当前会话，清 Cookie；同源及 CSRF 校验 |
| GET /api/admin/requests、/{request_id} | 全部历史列表和详情；支持时间/模型/协议/状态/错误码筛选 |
| GET /api/admin/observations、/sources、/candidates、/publications 及对应详情 | 全状态管理查询；管理读取与消费者 active 过滤分开 |
| POST /api/admin/sources/{id}/governance | 确认归属/用途/消费受众/期限与依据，登记来源验证记录及治理可信状态，产生新治理版本 |
| POST /api/admin/candidates/{id}/publish | 一次提交管理员验证依据和发布参数，直接完成合法发布 |
| POST /api/admin/candidates/{id}/reject、/revise | 拒绝或生成新修订，不原位改写旧证据 |
| POST /api/admin/sources/{id}/withdraw、/publications/{id}/revoke | 直接撤回，事务级联及 outbox 可追踪 |
| GET /api/admin/audit/records 及 /{id}、/api/admin/audit/events | 查询受控审计记录，直接读取可用正文；不接收任意密文或文件路径 |

错误语义统一：未登录 401，CSRF/越界 403，不存在 404，版本冲突 409，数据不合法 422，依赖不可用 503。接口实现与全路由枚举测试必须一致。

现有 `/healthz` 和 `/readyz` 保留为受信部署内部探针，只返回运维所需最小状态。管理控制台不提供匿名业务数据入口；模型 /v1 接口继续由 BYOK 及部署入口边界保护。

## 5. 知识单管理员发布与来源治理

- admin 一次提交验证依据与发布参数即可原子完成合法发布：publication 与 outbox 同事务提交；发布事务绑定一次有效管理员动作及当前来源版本。
- 来源治理授权与事实验证形成新版本记录，至少绑定 admin 主体、对象版本、动作、用途、消费受众、依据、时间和结果；原始 ACL、原始证据与原始 BYOK 来源可信度（unverified）不原位改写、不被登录自动覆盖。
- 派生输出以有效来源的消费授权交集为边界；受限来源未获消费授权时可管理可查看，但不自动向下游开放。发布校验采用当前有效的治理/验证记录，不因原始来源仍为 unverified 而永久禁止已完成合法验证的数据发布。
- 数据校验失败返回明确业务错误，不伪装成"缺另一个人批准"；失败不得伪造已发布。

## 6. 数据库权限与 DDL 契约

- 管理服务使用专用受限 PG 应用连接，worker 与 consumer 继续使用各自受限连接；均不得为 owner、superuser 或 BYPASSRLS。
- 管理 RLS 分支同时绑定专用管理数据库身份、服务端 AdminContext 和本部署租户/域；不只相信 app.roles 字符串。worker/consumer 数据库身份不能 SET ROLE 到管理服务身份，部署门禁验证可达成员关系及各表 forced RLS。
- DDL 带明确结构版本/指纹及单管理员验证/动作记录；初始化检查表、函数、触发器及 RLS 完整契约。首次上线使用新的隔离 schema/实例，初始化器继续拒绝已有 namespace。
- 初始化仅创建新的 schema；结构不符时拒绝对应能力，不修改已有对象。
- admin 查询受限/拒绝/撤回/到期元数据不使用消费者 active publication 过滤；正文读取遵守实际保留与密钥状态。

DDL v2 新增 `knowledge_admin_actions`、`knowledge_governance_versions`、`knowledge_publication_sources`。候选具有 `candidate_version` 和 `derived_from`，发布绑定精确候选版本、用途、消费受众、有效期限、管理员动作和幂等键；消费者资产、回执与 Outbox 保存实际版本、谱系和投递状态。结构准入使用 `SCHEMA_VERSION=3` 和 `SCHEMA_FINGERPRINT_V3`：对数据库元数据规范化后计算，保留列、约束、函数体、触发器和策略语义，剔除部署 schema/角色名字面量及 OID。

DDL v3 将 `entity_aliases` 纳入固定结构与指纹，强制租户、业务域及专用管理员 RLS；别名读写不执行 DDL。普通应用角色即使设置管理员 GUC 也不能读写别名。已有完整 v2 namespace 通过显式、仅新增的迁移升级；运行时和初始化器仍不自动改动已有结构。停止旧版本服务后，在 `apps/backend` 执行 `PYTHONPATH=src .venv/bin/python scripts/migrate_knowledge_aliases.py --config /private/database-deployment.json`，配置需包含 owner `admin_dsn`、`schema`、`application_role` 与 `admin_role`。迁移保留既有数据，对 v3 重复执行无变更，未知结构漂移拒绝并回滚。

`GATEWAY_ADMIN_KNOWLEDGE_PG_DSN` 与 `_FILE` 恰选一个；它是管理应用的专用受限登录连接，与初始化 DDL 的 owner 连接区分。管理事务设置 `app.tenant`、`app.domain`、`app.admin_context='true'`，管理 RLS 同时校验 `current_user` 的专用身份与部署范围。普通 worker/consumer 不能靠设置 GUC 或自报受众进入管理分支。启动及管理连接池每次取出连接时检查全部 schema 表/序列、函数和 namespace 的属主及可达成员路径，包括 NOINHERIT 下可切换的路径；结构指纹不替代权限检查。

权限或连接失败返回净化的 `KNOWLEDGE_ADMIN_UNAVAILABLE`；结构不匹配返回 `KNOWLEDGE_SCHEMA_INCOMPATIBLE`，均为 503，不返回 SQL、DSN、密码或内部路径。拒绝路径不创建、迁移或修复数据库对象。

## 7. 管理审计

- 正文读取、来源授权、验证发布、拒绝、修订和撤回动作记录 actor=admin、会话关联摘要、操作、对象、范围、时间和真实结果；审计不存正文、密码、Cookie、供应商 Key、DSN 密码或密钥材料。

## 8. BYOK 边界（不变量）

- 管理员 Cookie 不替代模型 BYOK，不传给供应商；admin 密码不参与供应商鉴权、来源 HMAC 或计费。
- 管理 API 测试模型连通时只能使用该次操作临时提供的 BYOK，操作结束即清除，不落配置、历史、作业参数或普通日志。
- 管理权限不提供原文直连或跳过检测开关；原文外发政策、检测、加密、AAD 绑定、版本固定、事务一致性、用途与来源追溯、下游撤回及操作审计继续执行。

## 9. 治理查询、请求体与复用状态

列表响应为 `{items, next_cursor}`，详情为 `{item}`。候选和发布的列表项与详情项包含相同 `availability` 对象。列表默认 50 项，最多 100 项，使用稳定游标；管理查询包括未确认、拒绝、撤回和到期元数据。来源支持 `status/use/audience` 筛选，详情可指定 `version`；候选支持 `state/source_id`，候选和发布支持 `consumer/use` 状态评估。筛选及评估不授予消费者读取权。

写请求严格拒绝未知字段、重复 JSON 键、无效类型和无时区期限；不接受客户端提供的 actor、会话、租户、域或管理员角色。

| 动作 | 请求字段 |
|---|---|
| 来源治理 | `source_version, expected_governance_version?, ownership, use, audiences[], valid_until, basis` |
| 发布 | `expected_version, use, audiences[], valid_until, idempotency_key?, basis` |
| 拒绝/撤销发布 | `basis` |
| 修订 | `modifications{}, basis`；仅支持受控的 ACL/用途修订 |
| 撤回来源 | `source_version, basis` |

成功响应使用真实 `governance_version_id`、`publication_id` 或新 `candidate_id`。版本冲突为 409，来源不存在为 404，授权交集/用途/期限不满足为 422；来源到期固定码 `KNOWLEDGE_SOURCE_EXPIRED` 为 422。已接受的写动作按事务执行，即使会话随后注销也不伪称取消；失效会话不能读取迟到的成功响应。

可用性字段反映服务端权威状态：

| 字段 | 含义 |
|---|---|
| `governance_status, blocking_reasons` | 当前治理状态与固定阻断码 |
| `eligibility, evaluated_consumer, evaluated_use` | 按指定受众/用途评估；未指定时为 `not_evaluated` |
| `effective_audiences, effective_use, valid_until` | 有效授权交集、用途与实际期限 |
| `delivery_status, pending_event_count, last_attempt_at, last_error_code` | 权威 Outbox/回执导出的投递状态，不以发布成功代替消费成功 |
| `reuse_assets[]` | `consumer_id, asset_id, asset_version, asset_kind, receipt_id, applied_at, invalidation_status`；无资产则为空 |
| `evidence_status, evaluated_at, state_version` | 证据可用性、服务端评估时刻和快照标识；未知依赖不得显示可用 |

固定阻断码为 `GOVERNANCE_MISSING`、`GOVERNANCE_SUPERSEDED`、`AUDIENCE_DENIED`、`PURPOSE_DENIED`、`SOURCE_EXPIRED`、`SOURCE_WITHDRAWN`、`PUBLICATION_REVOKED`、`EVIDENCE_UNAVAILABLE`。撤回已阻止新消费但失效事件尚无回执时显示 `invalidation_pending`。当前消费者资产以发布标识作为持久资产键，`asset_version` 来自实际资产行；不能将它解释为在线保护包版本。知识发布不会直接切换词典或在线检测器。

## 10. 审计目录、释放边界与资源隔离

后台构建器只扫描装配固定的 intent/evidence 根，以持久化的精确 `evidence_record_id`、摘要、AAD 与服务端生命周期关联入目录；没有可信关联或完整持久生命周期元数据的记录不可见。新记录沿用一次既有 intent 提交写入关联和保留元数据，不新增模型请求同步写入。默认策略为 30 天、版本 `model-query-retention-30d-v1`。

审计列表返回 `{items, next_cursor, catalog_backlog, catalog_error_code}`，不批量解密；详情返回 `{item, plaintext}`，一次仅释放一条有效记录。事件返回 `{items, next_cursor}`，包含固定事件码、操作者、会话摘要、记录句柄摘要、部署范围和时间，不含正文或密钥。`AUDIT_READ_RELEASED` 表示可靠记录了解密结果检查点；此后预算、生命周期或最后会话复检仍可能拒绝响应，不能将事件视为客户端已收到正文的证明。

知识和审计各有独立的 4 并发执行器，管理操作预算 5 秒；知识 PG 池上限 2，获取、SQL 和锁等待限时 5 秒。超限/依赖不可用返回固定 503。后台目录批量上限 200、间隔 5 秒，目录与访问事件各 64 MiB 配额、最多扫描 20,000 条；有扫描或配额失败时如实报告相应能力不可用，不伪造积压为零。

审计记录不存在为 404 `AUDIT_RECORD_NOT_FOUND`，到期或不可用为 409 `AUDIT_RECORD_UNAVAILABLE`，摘要/AAD/密文损坏为 409 `AUDIT_EVIDENCE_CORRUPTED`，读取权限或预算拒绝为 403 `AUDIT_ACCESS_REJECTED`，关键留痕失败为 503 `AUDIT_WRITE_FAILED`。最终认证失败保留认证错误语义；最终复检跨过读取预算或记录期限时不释放正文。

管理 PG、目录构建与解密队列独立于模型检测/NER；知识能力故障不关闭审计能力，新增管理能力故障不改变模型准入。既有必需加密留证、密钥、水位和 Spool 门禁仍执行。独立目录配额限制新增使用量，不承诺共享磁盘、共享 KMS 或整机完全故障时仍可外发。

知识管理与历史共用部署 schema，知识管理角色不得获得历史表权限；启动与取连接时同时检查跨用途授权。知识 v3 指纹仅排除两张已知历史表及其元数据，未知知识结构漂移仍拒绝。完整布局见 [ADR 0008](../adr/0008-unified-database-namespace.md)。


## 受控图查询

默认图空间绑定数据库和事实源 SQL namespace，采用稳定哈希后缀；不同 namespace 的数据与重建互不影响，测试 namespace 不复用部署图空间。

部署 owner 在 `apps/backend` 执行 `PYTHONPATH=src .venv/bin/python scripts/prepare_age_graph.py --config /private/database-deployment.json`，预建图、Entity/Claim 标签并向专用受限管理员角色授权。管理 API 重建仅删除和重放固定租户/业务域的投影，保留其他范围；其数据库连接设置对应管理员 RLS 上下文。

`POST /api/admin/graph/query` 仅接受能完整解析和改写的 openCypher 子集：带明确变量和 `Entity` 标签的节点模式，以及最多四跳、每条边均带 `Claim` 标签的固定长度关系模式；支持属性字面量/参数匹配、由 `AND` 连接的简单属性比较、`RETURN` 节点/边/属性或 `count`、可选 `DISTINCT`/列别名及整数 `LIMIT`。默认最多 100 行，显式上限为 1000 行、16 列，数据库事务只读且查询超时为 5 秒。未支持的语法、匿名变量、无标签节点、可变长度路径、`UNION`、`WITH`、子查询、注释、多语句和写操作均在执行前拒绝。

服务端为每个节点和边加入可信租户及业务域条件，为每条边加入 `is_active=true` 和 `valid_until_epoch` 有效期条件。请求参数不能覆盖这些内部绑定；过滤发生在聚合和投影之前，同时约束结构化结果、属性值与 `raw_records`。SQL 包装使用安全图名字面量与不出现在查询文本中的 dollar delimiter，拒绝查询文本逃逸到 SQL。

图查询前按可信租户/业务域消费最多 1000 条相关 Outbox 事件，先排空已有投影工作再读取；同步失败或达到批次上限时拒绝返回图数据，不静默读取旧投影。同步与重建统一写入时间戳形式的 `valid_until_epoch`；已有旧图需执行图投影重建。

示例：`MATCH (n:Entity) RETURN n LIMIT 100`，以及 `MATCH (s:Entity)-[r:Claim]->(o:Entity) WHERE s.name = $name RETURN s, r, o LIMIT 50`。AGE 扩展必须由部署管理员预先安装；CI 使用带扩展的 PostgreSQL 17 镜像，真实数据库测试不得跳过扩展缺失。
