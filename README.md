# 企业级大模型隐私与知识网关 (Enterprise Privacy & Knowledge Gateway)

面向企业大模型应用的隐私保护与受控知识沉淀项目。目标架构位于企业内部受信网络与模型供应商之间，覆盖两个目标：

1. **外发分级与精确隐私脱敏**：
   * **分级拦截**：高敏与禁止外发数据强阻断在企业本地网络；获准内容经过多引擎检测与脱敏后安全外发。
   * **请求级精确伪名替换**：基于 HMAC 机制在请求内存中建立临时原值映射，在受支持文本字段内精确恢复已知令牌；不保证检测零漏检或模型语义正确。
   * **全链路安全防护**：涵盖上游错误正文丢弃、异常断链防泄露、AES-GCM 信封加密落盘重放（Spool）、以及持久密钥认证包封与明确销毁边界。
2. **企业受控知识资产沉淀**：
   * 当前完成来源可追溯的受限观察与候选沉淀，知识归属保持待定；员工 SSO、所有者分配与发布审批不作为沉淀前置。已有可信 ACL 保留，未知权限限制到服务端处理域。代码包含本地关系抽取、PostgreSQL/RLS、审批、Outbox、授权消费与撤回组件，后续发布仍须验证。

已支持 Chat Completions 与 Messages 的文本选择性处理的受保护 HTTP 非流式、SSE、工具与多轮往返，以及加密采集产物到独立 worker、PostgreSQL、审批、授权消费、词典和撤回/到期的本地闭环。技术验证使用合成上游与业务身份，不能代表实际客户端、供应商或生产基础设施准入；未装配默认服务保持503。

HTTP 入口采用选择性处理：只检测和脱敏 `user`/`assistant` 消息中的字符串与 `text` 块、assistant 的 `reasoning`/`reasoning_content` 及工具/MCP 结果（名为 `Skill` 的技能加载工具结果豁免）。系统提示词、工具定义与参数、客户端追踪字段、用量字段、未知参数、图片/文件及未知内容块保持原样，不因超出网关处理能力而拒绝。网关不承担未处理内容的脱敏，也不替供应商校验工具 schema 和模型控制参数。完整原始请求仍交给可信分类器和已装配的加密历史；客户端自报身份不授予处理域或知识权限。

NER 前默认启用本地快速风险筛选，无模型推理、网络请求或磁盘访问。每次请求的全部可检测文本共用默认 2ms 筛选预算：词典、敏感格式、姓名/机构等线索命中时进入完整规则 + 词典 + NER 检测；低风险文本保留原文并跳过检测。超预算或无法覆盖自定义规则时转完整检测，不因筛选预算耗尽而拒绝请求。长文本逐块扫描，未扫描部分不会被判为低风险。该评分是未经训练数据校准的启发式风险估计，不是保证无隐私的概率；调整阈值前应使用实际业务样本评估漏检和误报。鉴权、审计、留存和响应还原仍照常执行。操作系统调度可能使实际耗时超过预算，因此 2ms 是计算预算而非硬实时承诺。

请求期间检测故障默认报错。设置 `GATEWAY_DETECTION_FAILURE_MODE=passthrough` 可在检测器故障或检测超时时透传未脱敏文本，并记录仅含错误码的 `DETECTION_FAILURE_PASSTHROUGH` 日志；默认值为 `error`。该开关只作用于检测阶段，不改变鉴权、请求总超时、持久化失败或已检测到高敏秘密时的处理。

SSE业务内容在协议终态与真实响应体EOF都验证后统一释放，此前只发送固定保活。原始及恢复后响应各有8MiB预算，工具参数恢复后每调用64KiB、全请求256KiB。该模式的首业务内容等待时间需要实际客户端联调；未处理的签名历史内容保持原样，不要求客户端携带网关receipt。

---

## 核心安全与架构原则

* **明确处理边界**：支持的内容字段执行检测与脱敏；未支持字段透传。检测故障默认报错，可由服务端显式配置故障透传。
* **请求级隔离映射**：原值恢复映射仅保存在单次请求生命周期内存中，严禁写入外部持久数据库或审计日志，避免放大攻击面。
* **多级流水线检测**：集成预置中文规则（身份证、手机号、统一信用代码等）、敏感私钥/密码探测、企业自定义词典、以及 ONNX 本地 NER 模型长文本滑动窗口推理。
* **受控异常体系**：全系统使用统一的受控错误注册表（`SafetyError`），异常诊断绝不携带业务明文，切断堆栈回溯链，杜绝错误回显泄露。
* **信封加密异步 Spool**：外发与重放报文采用 DEK/KEK 两级 AES-GCM 信封加密落盘，保障不可抗力下的持久化审计与断点恢复。

架构决策记录详见 [docs/adr/](docs/adr/)，系统接口契约规范详见 [docs/contracts.md](docs/contracts.md)。

---

## 系统架构与模块划分

```
[ 客户端请求 ]
      │
      ▼
┌─────────────────────────────────────────────────────────────────┐
│ 1. 协议准入与免检 (protocol)                                     │
│    ├── 提取可处理文本、保留未知结构 (OpenAI / Claude)                         │
│    ├── BYOK 来源关联与服务端处理域 (identity / admission)       │
│    └── 静态审批模板精确免检 (static_exemption)                  │
├─────────────────────────────────────────────────────────────────┤
│ 2. 分级政策匹配 (policy)                                         │
│    └── 受信政策矩阵判定 (approved_external / secret / local_only)│
├─────────────────────────────────────────────────────────────────┤
│ 3. 混合隐私检测流水线 (detection)                                 │
│    ├── 规则识别器 (Presidio / Regex: 证件、手机、银行卡、PEM密钥)│
│    ├── 企业词典匹配器 (Dictionary)                              │
│    ├── 本地 ONNX NER 模型与滑动窗口分块 (NER & Windowing)        │
│    └── Span 区间合并与冲突消歧 (Span Resolver)                  │
├─────────────────────────────────────────────────────────────────┤
│ 4. 请求脱敏与映射 (masking)                                      │
│    ├── 内存 HMAC 伪名映射表 (Mapping)                            │
│    └── 原文占位符精确替换 (Replacer)                             │
├─────────────────────────────────────────────────────────────────┤
│ 5. 加密落盘与安全外发 (infra & gateway)                           │
│    ├── AES-GCM 信封加密磁盘缓冲 (Spool & Envelope Crypto)       │
│    ├── 向上游大模型发起外发调用 (Egress Client)                  │
│    └── 出口错误净化 (Error Sanitizer: 剥离上游报错明文)          │
├─────────────────────────────────────────────────────────────────┤
│ 6. 响应还原与交付 (masking)                                      │
│    └── 伪名标记精确回填还原 (Restorer)                          │
└─────────────────────────────────────────────────────────────────┘
      │
      ▼
[ 安全清洗后的模型响应 ]
```

---

## 模块结构一览

| 模块目录 | 核心职责 |
|---|---|
| `src/infra` | 基础设施：系统配置、受控错误码（`SafetyCode`）、严格 JSON 解析、版本清单、可观测性、AES-GCM 信封加密、持久化 Spool 落盘、密钥销毁与出站 HTTP 传输 |
| `src/gateway` | 网关入口与编排：FastAPI 服务路由、端到端脱敏流水线（`pipeline`）、入口屏障与出口错误脱敏净化器 |
| `src/protocol` | 协议与准入：OpenAI Chat Completions 与 Claude Messages 严格协议模型、受信身份、准入预算与静态模板免检 |
| `src/policy` | 外发政策：受信外发分级政策契约与出站权限评估 |
| `src/detection` | 隐私检测：混合检测编排器、Presidio 正则识别器、企业词典匹配、本地 ONNX NER 推理及长文本分窗 |
| `src/masking` | 脱敏与映射：请求级 HMAC 伪名映射生成、正向敏感文本替换与反向响应原值还原 |
| `src/audit` | 审计与质检：释放意图台账、审计存储容量水位、质量评价口径与外发留证门禁 |
| `src/knowledge` | 受控知识域：知识实体与关系模型、多方授权审批流、版本快照与失效 Tombstone 状态机 |

---

## 快速上手与验证

### 环境要求
* Python 3.11 ～ 3.13
* 依赖管理工具：`uv`

### 1. 安装与同步依赖
~~~powershell
git clone git@github.com:paulfrom/enterprise_gateway.git
cd enterprise_gateway
uv sync --frozen --no-editable --group dev --cache-dir .uv-cache
~~~

### 2. 运行自动化测试套件
完整测试需要真实隔离PostgreSQL及非owner、无superuser/BYPASSRLS的应用角色。通过`GATEWAY_TEST_PG_CONFIG`指定受控JSON配置文件，或使用被Git忽略的`.env.test`；字段为`app_dsn`、`admin_dsn`、`schema`、`application_role`。`schema`必须使用`gw_test_`前缀；每个测试进程创建新的随机schema，缺配置直接失败。管理连接需有创建schema和定义受限函数的权限；管理owner与应用角色分别使用独立连接，不使用生产数据库替代隔离测试。

~~~powershell
# Windows 快速验证脚本
.\scripts\check.ps1

# 或直接使用 uv 执行全量测试
uv run --frozen --no-editable --group dev --cache-dir .uv-cache python -m unittest discover -s tests -t . -v
~~~

应用集成通过`gateway.app.create_app`装配完整`ProviderRouter`、`ByokAuthenticator`、至少32字节`hmac_key`和服务端可信分类函数`classifier(raw_body: bytes) -> str`。分类必须来自受信业务系统或获准分类器，客户端自报头或正文不提供授权依据。流水线使用实际规则/词典/NER、固定供应商映射、真实磁盘水位、持久审计和加密 spool；缺可信分类时就绪与模型接口返回503。配置变化构造新装配，在途请求继续使用原路由快照。

`gateway.runtime.create_runtime_app`是独立多供应商 BYOK 的唯一装配工厂。调用者提供处理租户/域、独立来源关联与映射 HMAC 密钥、KMS、词典、NER目录、状态目录、受信政策、水位政策及证据留存桶。`config/providers.json`仅包含服务端固定 URL、协议、模型白名单与超时，不接受供应商 Key、重复渠道/模型、未知字段或客户端选址。默认配置仅是可修改的路由样例，不证明对应模型仍供应或已经准入；Claude 已停用模型已移出默认配置，Messages 协议须使用另行核验的供应商配置。

网关入口和供应商上游均支持 HTTP/HTTPS，HTTPS 为可选配置。上游 URL 可使用域名、私网或公网 HTTP 地址，例如 `http://10.0.0.8:8000/v1/chat/completions`；仍须匹配配置的协议路径和模型白名单。两种传输都执行 BYOK、分类、检测、留证、固定出口和 DNS 地址集校验。选择 HTTPS 时验证证书链与主机名，失败即拒绝，不自动降级；HTTP 不提供传输加密。

客户端通过规范 `Authorization: Bearer ...` 或 `x-api-key` 携带凭据；允许两个头同时出现，但去掉 Bearer 前缀后的令牌必须相同且非空。同名鉴权头重复、令牌冲突或任一凭据格式错误均拒绝。外发仅生成渠道指定的一个鉴权头。网关转发当次客户端 Key，账单归供应商账户；不持有付费供应商 Key、不提供模型推理算力、不垫资、不换 Key/供应商重试。Key 的带密钥关联标识只标记未验证来源，不授予企业员工角色、知识所有权或阅读权限。内部 `TrustedIdentity` 和 `EnterpriseAuthenticator` 仅保留给受信审阅组件，不能作为 BYOK 入口的默认身份。

DeepSeek响应恢复支持普通 `content`、`reasoning_content`、`reasoning_details` 文本和可解析的工具参数中的已知映射令牌；未知字段、用量明细和 `logprobs` 保持原值。无法恢复的保留令牌仍报告恢复错误。

`audit.record_review.RecordReviewService`提供受控单记录审阅：限时工单绑定请求者、租户、域及精确加密记录，由两名不同角色审批者批准，持久化一次性消费标记并审计后才解密交付。记录与租户的关联须由可信存储提供；模块没有公开HTTP或批量审阅接口。生产身份、KMS及审计卷政策由部署方接入。

### 3. 启动网关服务 (本地与 Docker)

启动前由部署方准备受控文件与以下显式设置。密钥为小写十六进制；每项密钥只允许环境值或对应 `_FILE` 文件二选一，文件可含末尾换行。密钥文件置于受限目录并排除版本控制；整个运行期保持主密钥与持久状态卷一致。

| 设置 | 用途 |
|---|---|
| `GATEWAY_PROCESSING_DOMAIN` / `GATEWAY_PROCESSING_TENANT` | 服务端受限处理范围，不能从供应商 Key 推导 |
| `GATEWAY_STATE_DIR` | 持久目录，包含 `keys/`、`intents/`、`evidence/`、`spool/` |
| `GATEWAY_KMS_MASTER_KEY` 或 `_FILE` | 恰好32字节，包封本地持久独立 KEK |
| `GATEWAY_HMAC_KEY` 或 `_FILE` | 至少32字节，请求映射/完整性用途 |
| `GATEWAY_SOURCE_CORRELATION_KEY` 或 `_FILE` | 至少32字节，仅未验证来源关联 |
| `GATEWAY_DICTIONARY_FILE` | 符合现有词典 schema 和内容哈希的受控 JSON |
| `GATEWAY_POLICY_FILE` | 符合 `ClassificationPolicy` schema 的受信政策 JSON |
| `GATEWAY_NER_PACKAGE_DIR` | 已核验完整本地 ONNX 模型包 |
| `GATEWAY_NER_TIMEOUT_SECONDS` | 可选的 NER 单次检测时间预算（秒），代码默认 30，Compose 部署默认 120；大文本 CPU 推理需按硬件调整，仍受请求总超时约束 |
| `GATEWAY_EVIDENCE_BUCKET` | 受控原始请求证据留存桶 |
| `PROVIDERS_CONFIG` 或 `--config` | 路由文件，默认 `config/providers.json` |
| `GATEWAY_CLASSIFIER` 或 `--classifier` | 运维批准的同步 Python `module:callable`，接收请求 bytes 并返回政策分类；未配置保持拒绝 |
| `GATEWAY_CLIENT_PROFILE` | 默认 `compatible`，忽略客户端自报身份；`strict` 拒绝自报身份头 |
| `GATEWAY_QUICK_SCREEN_ENABLED` | 默认 `true`；`false` 恢复对全部可检测文本的完整检测 |
| `GATEWAY_QUICK_SCREEN_THRESHOLD` | 默认 `0.35`，范围 `(0,1]`；分数达到阈值进入完整检测，越低越保守 |
| `GATEWAY_QUICK_SCREEN_BUDGET_MS` | 默认 `2`，范围 `(0,10]`；整个请求共享的筛选预算，耗尽后转完整检测 |
| `GATEWAY_DETECTION_FAILURE_MODE` | 默认 `error`；`passthrough` 在请求检测故障时透传未脱敏文本，客户端无法通过请求切换 |
| `GATEWAY_SSL_CERTFILE` / `GATEWAY_SSL_KEYFILE` | 可选的原生 HTTPS PEM 证书与私钥；启用时必须成对提供，也可用同名命令行参数；未配置时使用 HTTP |

Compose 使用一个受控只读 `GATEWAY_OPERATOR_DIR`，其中放置 `dictionary.json`、`policy.json`、受信分类器模块和可选 TLS 文件。该目录加入容器 Python 模块路径；例如 `deployment_classifier.py` 的 `classify` 函数对应 `GATEWAY_CLASSIFIER=deployment_classifier:classify`。这是部署方受信代码，会执行 Python 导入；不得挂载用户上传文件或把合成测试分类器用于真实业务。密钥仍使用独立 Docker secrets。端口默认只绑定 `127.0.0.1:8080`；对外监听须显式设置 `GATEWAY_BIND_ADDRESS` 与 `GATEWAY_PUBLISHED_PORT`，并配置入口访问控制。入口允许 HTTP；需要原生 HTTPS 时再配置证书对。

本机启动时，受信分类器须安装到运行环境，或将其受控目录加入 `PYTHONPATH`；仅设置模块名称不会创建分类逻辑。路径和证书使用本机实际文件，容器内使用 `/app/operator/...`。

`FileKmsProvider`是受控本地文件后端，使用随机独立 KEK、进程锁、认证包封和持久销毁墓碑；不等同企业 KMS，也不证明备份/快照已删除。首次使用必须显式初始化密钥，常规启动绝不补建丢失的密钥。有任何历史意图/证据/spool记录时，初始化命令仅验证既有键，缺键拒绝。应备份受控密钥状态与主密钥；不能通过重新初始化恢复丢键后的密文。

~~~powershell
# 已设置上表所需环境后，首次显式初始化
python start_gateway.py --provision-keys

# 常规启动；缺可信服务端分类时健康200、就绪/模型接口503
python start_gateway.py --host 0.0.0.0 --port 8080

# 配齐受信模块及正式证书后，原生 HTTPS 示例
python start_gateway.py --host 127.0.0.1 --port 8443 --classifier deployment_classifier:classify --ssl-certfile <certificate.pem> --ssl-keyfile <private-key.pem>

# Compose 使用必填 _FILE 密钥路径与 GATEWAY_OPERATOR_DIR，另准备受限 PG 连接
docker compose build gateway
docker compose run --rm --no-deps gateway python start_gateway.py --provision-keys
docker compose up -d
~~~

启动器调用同一工厂；不创建示例词典、默认获准分类或长期企业身份。受信 Python 集成可调用 `start_gateway.build_app(classifier=approved_classifier)`，CLI/镜像可通过上述运维模块引用装配同一分类器。配置模块引用只解决装配，不提供业务外发批准；无分类器保持503，错误引用、异步/错误签名函数或无效 TLS 证书对安全退出。有效 BYOK、合法协议与可信分类结果已到达时，高敏/禁止外发或未知分类输入可先形成受限加密观察，再拒绝外发；秘密检测/协议/存储失败仍拒绝采集。就绪会检查路由完整版本、分类接入、存储/密钥和真实水位；通过技术就绪仍不代表生产准入。容器探针适配 HTTP/HTTPS，仅表示本机存活；选择 HTTPS 时客户端须校验证书链与服务域名。

独立 `start_knowledge_worker.py`读取相同状态卷、主密钥、处理域和租户，将受限 spool 幂等提交到现有 PostgreSQL 表。另外显式配置 `GATEWAY_KNOWLEDGE_PG_DSN` 或 `_FILE`，以及服务端 `GATEWAY_KNOWLEDGE_WORKER_SUBJECT`；连接角色须非表 owner、非超级用户、无 BYPASSRLS，现有 schema/RLS 必须先部署。worker 不初始化数据库、不创建密钥、不批准或发布知识；可用 `--once` 执行单次重放。Compose 的 worker 连接部署方既有 PG，镜像不内置生产数据库。当前观察沿用30天技术留存和 `standard-retention` 桶，具体真实留存政策仍需业务核准。

数据库初始化与 worker 启动共享最小权限检查：应用角色不能具有创建数据库/角色、复制能力、切换到特权角色或直接/间接成为 PostgreSQL `pg_*` 全局预定义角色的成员。登录用户、会话用户与当前 SQL 用户须一致，不接受管理连接降级成应用角色。worker 对当前定义的全部13张资产表检查 forced RLS，且应用角色不能拥有表或成为表 owner 的成员。单次执行 `--once` 在提交失败或隔离异常时返回非零；成功提交或幂等跳过返回0，失败记录仍保留以便重放。

首次部署 PostgreSQL 时，管理方使用受控 JSON 文件（`schema`、`application_role`、`admin_dsn`、`app_dsn` 四个字段）显式初始化一个尚不存在的 schema：

~~~powershell
.\.venv\Scripts\python.exe scripts/prepare_knowledge_database.py --config <private-input.json> --output-config <new-private-bound-config.json>
~~~

工具复用当前数据库定义，在一个管理事务中建立表、受限授权与 forced RLS；拒绝已有 schema、特权应用角色和可切换到管理角色的账号，不修改既有数据或提供迁移。输出文件包含连接秘密，必须置于受限、Git 忽略的目录；取其 `app_dsn` 写入 worker 的 DSN 秘密文件，不能把 `admin_dsn`交给 worker。真实远端部署必须启用并验证数据库 TLS（如 `sslmode=verify-full` 与受信 CA）；仅完成连接或建表不能证明传输安全。

本地合成部署验证入口为 `scripts/verify_local_deployment.py`，参数通过 `--help` 查看。它使用实际网关、检测、加密与独立 worker，本机合成上游只模拟供应商协议；结果写入调用方指定目录。合成分类与上游不构成真实供应商或业务准入。

### 4. 接口与 BYOK 使用说明

| 请求端点 | 协议类型 | 典型调用方式 |
|---|---|---|
| `GET /healthz` | 进程存活探针 | `curl http://127.0.0.1:8080/healthz` -> 返回 `200 OK` |
| `GET /readyz` | 实际装配就绪探针 | 缺分类/密钥/存储或水位不足返回503 |
| `POST /v1/chat/completions` | OpenAI / DeepSeek 协议 | 携带客户端自备 Key：`-H "Authorization: Bearer sk-user-key"`，Body 指定 `"model": "deepseek-chat"` 或 `"gpt-4o"` |
| `POST /v1/messages` | Claude Messages 协议 | 携带自备 Key：`-H "x-api-key: sk-ant-user-key"`，Body 指定部署方已经核验并配置的模型 |

* **费用与配额归属**：网关自身不垫资、不持有供应商 Key，请求外发时动态注入调用方自备的 API Key，费用由供应商直接扣减调用方的账户。
* **多供应商路由**：网关读取 `config/providers.json` 自动将清洗后的请求路由到对应供应商（DeepSeek、OpenAI、Claude 或本地私有 vLLM）。

---

## 请求历史网页

访问同源 `/history`，输入部署方配置的网关查询 Key，可查看当前租户/保护域内全部未过期请求的输入、脱敏外发、供应商回复、还原输出。无需账号系统，不按用户或供应商 Key 分组；持有查询 Key 即能读取全部历史。输入与还原正文默认遮挡，可主动显示和复制。列表支持模型/协议/请求ID搜索、状态筛选和分页，部分或未产生的阶段单独标记，网关拒绝正文不会标成成功模型回复。

历史使用独立 PostgreSQL schema、用途为 `request-history` 的加密密钥和访问留痕。完整四阶段可推断原值关系，须按原文敏感级别治理。供应商 Key 不作为查询凭据，不保存到历史；网页查询 Key 只在浏览器内存中，刷新或退出后重新输入。

部署须显式提供以下整组配置，缺项拒绝启动；未选择历史装配时不采集四阶段正文：

| 设置 | 内容 |
|---|---|
| `GATEWAY_HISTORY_PG_DSN` 或 `_FILE` | 独立历史 schema 的受限应用连接，不是管理连接 |
| `GATEWAY_HISTORY_READ_KEY` 或 `_FILE` | 独立32字节随机 Key，编码为64字符小写十六进制 |
| `GATEWAY_HISTORY_RETENTION_DAYS` | 明确的留存天数，范围1～36500，无默认值 |
| `GATEWAY_HISTORY_BUCKET` | 历史加密用途的受控留存桶 |

先使用 `scripts/prepare_request_database.py --config <private-input.json> --output-config <new-private-bound.json>` 初始化尚不存在的历史 schema。输入字段为 `schema`、`application_role`、`admin_dsn`、`app_dsn`；应用账号须预先具备数据库连接权限且不能拥有或切换到管理角色。工具在事务内建立2张表及forced RLS，拒绝已有 schema，不提供迁移。将输出的应用连接存入受限秘密文件；管理连接不交给服务。

历史配置完成后，首次显式执行 `start_gateway.py --provision-keys` 初始化用途密钥，再正常启动。已有历史（包括过期但未删除的记录）而密钥丢失时拒绝补建。查询 API 是 `GET /api/requests?limit=50&q=&status=&cursor=` 和 `GET /api/requests/{request_id}`，仅接受一个 `Authorization: Bearer <网关查询Key>`；模型调用返回 `x-request-id`。搜索仅针对元数据，不索引正文。

启用历史后，持久化失败会停止模型外发或正文释放。流式保存实际供应商字节及网关输出片段，断连可显示部分记录；`completed`表示完整生成和留存，不能证明客户端已收到。过期记录不可查询，使用 `scripts/purge_request_history.py --config <private-purge.json>` 定期物理删除；配置字段及密钥输入见工具 `--help`。在线删除不证明备份和复制密钥已销毁。HTTP不加密查询 Key 和正文，远端访问应依据数据敏感度选择受验证的HTTPS；生产数据库TLS、目录权限、备份/删除、性能和真实客户端/供应商仍须验证。

## 生产部署与安全边界声明

1. **不可绕过性**：完整覆盖必须由企业网络/客户端管理约束模型出口，并在供应商支持时实施来源限制；客户端持有供应商 Key，单纯配置 Base URL 无法阻止其绕过网关直连。
2. **内存物理擦除限制**：原值映射在请求结束时由 Python 垃圾回收机制释放对象引用，在解释器层面不保证物理 RAM 位的硬件擦除。
3. **推断风险防范**：文本实体替换能够消除直接标识符泄露，但不能完全阻止模型基于上下文语境产生的反向间接推断，高敏绝密数据应直接配置为 `LOCAL_ONLY` 强阻断。
4. **知识数据库权限**：候选读取核验自身和全部来源权限，拒绝状态持久化。归一描述表不并集ACL；固定search_path、撤销PUBLIC执行权的受限管理函数需要专用管理owner，应用角色不得继承其BYPASSRLS权限。读取与来源撤回/到期通过行锁明确事务顺序。
5. **客观限制**：不支持任意协议或未知字段透传；没有真实供应商签名接受、实际WorkBuddy组合、企业IAM/KMS、生产网络与发布的通用通过声明。具体验签算法及信任材料仍须审查准入，语法守卫不能证明任意Python算法安全。
