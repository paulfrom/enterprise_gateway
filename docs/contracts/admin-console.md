# 管理控制台契约（认证、会话、授权与单管理员发布）

本契约定义管理员登录、服务端会话、统一管理授权、管理路由、知识单管理员发布与数据库结构契约。管理端只供管理员使用；当前只有一个固定账号 admin。本文是实施契约，相关能力的落地状态以代码与验收证据为准。

## 1. 账号与密码

- 固定用户名 admin，初始密码由部署方在显式初始化时指定；本阶段不提供账号 CRUD、密码修改页、强制改密、MFA 或注册/邀请流程。
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
- 同步正文释放前再次校验会话和期限；关键审计失败不释放正文。长作业在提交时验证管理员权限并保存执行上下文；已可靠接受的作业按服务端状态继续执行，管理员退出阻止新请求但不伪称取消已提交操作。
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
| GET /api/admin/runtime | 运行组件、真实指标、版本与采集时间 |
| GET /api/admin/config/{kind} | 读取允许的政策、路由、词典、模板和制品元数据；kind 枚举固定 |
| POST /api/admin/config/{kind}/validate | 服务端校验草案及变更影响，返回实际校验结果 |
| POST /api/admin/config/{kind}/publish | 指定预期版本和已校验草案，创建真实发布作业 |
| POST /api/admin/config/rollback | 回退至已存在、校验通过且资源完整的完整版本 |
| GET /api/admin/observations、/sources、/candidates、/publications 及对应详情 | 全状态管理查询；管理读取与消费者 active 过滤分开 |
| POST /api/admin/sources/{id}/governance | 确认归属/用途/消费受众/期限与依据，登记来源验证记录及治理可信状态，产生新治理版本 |
| POST /api/admin/candidates/{id}/publish | 一次提交管理员验证依据和发布参数，直接完成合法发布 |
| POST /api/admin/candidates/{id}/reject、/revise | 拒绝或生成新修订，不原位改写旧证据 |
| POST /api/admin/sources/{id}/withdraw、/publications/{id}/revoke | 直接撤回，事务级联及 outbox 可追踪 |
| POST /api/admin/publications/export、/dictionary/compile | 执行导出或词典编译；明确目标消费受众，保存版本/结果 |
| GET /api/admin/audit/records 及 /{id}、/api/admin/audit/events | 查询受控审计记录，直接读取可用正文；不接收任意密文或文件路径 |
| GET /api/admin/retention、POST /api/admin/retention | 查看和设置明确保留策略，按版本校验，不能延长已销毁资产 |
| POST /api/admin/maintenance/{action} | action 固定枚举：消费、隔离重试、到期清理、受控密钥生命周期及恢复验证；返回真实 job_id |
| GET /api/admin/jobs、/{job_id} | 作业状态、实际结果、幂等键及失败码，输出不带敏感正文 |

错误语义统一：未登录 401，CSRF/越界 403，不存在 404，版本冲突 409，数据不合法 422，依赖不可用 503；异步作业接受 202，只有执行完成才标成功。接口实现与全路由枚举测试必须一致。

现有 `/healthz` 和 `/readyz` 保留为受信部署内部探针，只返回运维所需最小状态。管理控制台不提供匿名业务数据入口；模型 /v1 接口继续由 BYOK 及部署入口边界保护。旧 `/history`、`/api/requests` 路由与独立查询 Key 入口整体删除，不保留重定向或兼容路径。

## 5. 知识单管理员发布与来源治理

- 删除双人审批模型：不再有 Approval 实体、审批角色槽、approval_count=2 条件、审批身份触发器或等待第二批准状态。
- admin 一次提交验证依据与发布参数即可原子完成合法发布：publication 与 outbox 同事务提交；发布事务绑定一次有效管理员动作及当前来源版本。
- 来源治理授权与事实验证形成新版本记录，至少绑定 admin 主体、对象版本、动作、用途、消费受众、依据、时间和结果；原始 ACL、原始证据与原始 BYOK 来源可信度（unverified）不原位改写、不被登录自动覆盖。
- 派生输出以有效来源的消费授权交集为边界；受限来源未获消费授权时可管理可查看，但不自动向下游开放。发布校验采用当前有效的治理/验证记录，不因原始来源仍为 unverified 而永久禁止已完成合法验证的数据发布。
- 数据校验失败返回明确业务错误，不伪装成"缺另一个人批准"；失败不得伪造已发布。

## 6. 数据库权限与 DDL 契约

- 管理服务使用专用受限 PG 应用连接，worker 与 consumer 继续使用各自受限连接；均不得为 owner、superuser 或 BYPASSRLS。
- 管理 RLS 分支同时绑定专用管理数据库身份、服务端 AdminContext 和本部署租户/域；不只相信 app.roles 字符串。worker/consumer 数据库身份不能 SET ROLE 到管理服务身份，部署门禁验证可达成员关系及各表 forced RLS。
- 新 DDL 带明确结构版本/指纹，删除旧审批表与触发器，替换为单管理员验证/动作记录；初始化检查表、函数、触发器及 RLS 完整契约。首次上线使用新的隔离 schema/实例，初始化器继续拒绝已有 namespace。
- 不写 migration，不对旧 schema 执行自动 ALTER/DROP，不自动搬运旧数据；旧知识 schema 与新管理服务不混用，启动给出固定净化错误并拒绝相应能力。
- admin 查询受限/拒绝/撤回/到期元数据不使用消费者 active publication 过滤；正文读取遵守实际保留与密钥状态。

## 7. 审计与配置发布

- 所有正文读取、配置发布、来源授权、验证发布、撤回、删除和维护动作记录 actor=admin、会话关联摘要、操作、对象、范围、时间和真实结果；审计不存正文、密码、Cookie、供应商 Key、DSN 密码或密钥材料。
- 配置发布遵循既有 manifest/蓝绿原则：校验草案 → 构建完整制品 → 验证资源/依赖 → 受管发布 → 切换新请求 → 在途请求保留原包 → 排空与资源关闭 → 记录实际生效版本。保存、校验、发布接受、发布成功、回退成功是不同状态；作业返回 job_id、幂等键、源/目标版本、实际开始/结束、结果和固定错误码；重试检查原任务状态，不重复销毁密钥或重复外发模型请求。

## 8. BYOK 边界（不变量）

- 管理员 Cookie 不替代模型 BYOK，不传给供应商；admin 密码不参与供应商鉴权、来源 HMAC 或计费。
- 管理 API 测试模型连通时只能使用该次操作临时提供的 BYOK，操作结束即清除，不落配置、历史、作业参数或普通日志。
- 管理权限不提供原文直连或跳过检测开关；原文外发政策、检测、加密、AAD 绑定、版本固定、事务一致性、用途与来源追溯、下游撤回及操作审计继续执行。
