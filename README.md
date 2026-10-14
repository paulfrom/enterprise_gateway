# 企业级大模型隐私与知识网关 (Enterprise Privacy & Knowledge Gateway)

面向企业大模型应用的隐私保护与受控知识沉淀项目。目标架构位于企业内部受信网络与模型供应商之间，覆盖两个目标：

1. **外发分级与精确隐私脱敏**：
   * **分级拦截**：高敏与禁止外发数据强阻断在企业本地网络；获准内容经过多引擎检测与脱敏后安全外发。
   * **请求级类型与角色替换**：以 `<ORG_001>`、`<PARTYA_001>` 等短占位符在请求内存建立原值映射，保留类型与明确交易角色，在受支持文本字段内精确恢复已知令牌；不保证检测零漏检或模型语义正确。
   * **全链路安全防护**：涵盖上游错误正文丢弃、异常断链防泄露、AES-GCM 信封加密落盘重放（Spool）、以及持久密钥认证包封与明确销毁边界。
2. **企业受控知识资产沉淀**：
   * 已实现来源可追溯的受限观察与候选沉淀，以及单管理员来源治理、直接发布、修订、拒绝和撤回。未知权限限制到服务端处理域；消费授权通过版本化治理显式确认，并取全部贡献来源的授权交集。原始 ACL 与未验证来源身份保留，PostgreSQL/RLS、Outbox 和授权读取执行实际权限边界。

已支持 Chat Completions 与 Messages 的受保护 HTTP 非流式、SSE、工具与多轮往返，以及加密采集产物到独立 worker、PostgreSQL、单管理员治理与直接发布、授权消费、词典和撤回/到期的本地闭环。技术验证使用合成上游与业务身份，不能代表实际客户端、供应商或生产基础设施准入；未装配默认服务保持503。

HTTP 入口按已准入的 Chat Completions / Claude Messages 协议严格校验，未知字段、错误类型和未准入内容块拒绝。检测范围是 `user`/`assistant` 消息文本及工具/MCP 结果，名为 `Skill` 的工具结果豁免；系统提示词、工具定义和工具参数不进入检测，但执行协议及工具 schema 校验。完整原始请求交给可信分类器和已装配的加密历史。客户端自报身份头拒绝，处理范围和知识权限来自服务端。

NER 前默认启用本地快速风险筛选，无模型推理、网络请求或磁盘访问。每次请求的全部可检测文本共用默认 2ms 筛选预算：词典、敏感格式、姓名/机构等线索命中时进入完整规则 + 词典 + NER 检测；低风险文本保留原文并跳过检测。超预算或无法覆盖自定义规则时转完整检测，不因筛选预算耗尽而拒绝请求。长文本逐块扫描，未扫描部分不会被判为低风险。该评分是未经训练数据校准的启发式风险估计，不是保证无隐私的概率；调整阈值前应使用实际业务样本评估漏检和误报。鉴权、审计、留存和响应还原仍照常执行。操作系统调度可能使实际耗时超过预算，因此 2ms 是计算预算而非硬实时承诺。

请求期间检测故障默认报错。设置 `GATEWAY_DETECTION_FAILURE_MODE=passthrough` 可在检测器故障或检测超时时透传未脱敏文本，并记录仅含错误码的 `DETECTION_FAILURE_PASSTHROUGH` 日志；默认值为 `error`。该开关只作用于检测阶段，不改变鉴权、请求总超时、持久化失败或已检测到高敏秘密时的处理。

NER 默认使用有界常驻工作进程：一个执行槽、四个等待任务，复用 tokenizer 与 ONNX Session。Linux 启动时完整校验并建立内核封印的不可变模型快照，全部执行槽完成实际前向预热后服务；请求复用快照摘要和运行资源。源目录变更不会改写在用模型，新模型须重新装配新池与保护包。每个进程默认最多完成 8192 个请求，并在达到 3600 秒年龄或 2048 MiB 峰值 RSS 阈值后回收，替代进程在空闲时预热；超时或取消仍先确认退出。窗口按长度分组跨片段合批，跨请求聚合为可配置能力，CPU 默认逐请求调度；所有成员仍占用有界准入容量，恢复映射保持请求内隔离。多槽时为短请求保留容量，单槽无法抢占长文本前向计算。契约见 [ADR 0010](docs/adr/0010-immutable-ner-snapshots-and-batching.md) 与 [NER 评测契约](docs/contracts/ner-evaluation.md)，真实样本和运行报告存放在仓库外。

SSE业务内容在协议终态与真实响应体EOF都验证后统一释放，此前只发送固定保活。原始及恢复后响应各有8MiB预算，工具参数恢复后每调用64KiB、全请求256KiB。该模式的首业务内容等待时间需要实际客户端联调；Claude 签名历史须通过供应商验证并携带域及版本绑定的网关 receipt。

---

## 核心安全与架构原则

* **明确处理边界**：已准入的内容字段执行检测与脱敏；未支持字段拒绝。检测故障默认报错，可由服务端显式配置故障透传。
* **请求级隔离映射**：占位符到原值的恢复表仅在单次请求内存使用。实体词典作为独立受管资产入库，不用于跨请求补回恢复表。
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
│    ├── 严格校验协议并提取可检测文本 (OpenAI / Claude)                         │
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
│    ├── 内存类型/角色序号映射表 (Mapping)                            │
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
| `apps/backend/src/infra` | 基础设施：系统配置、受控错误码（`SafetyCode`）、严格 JSON 解析、版本清单、可观测性、AES-GCM 信封加密、持久化 Spool 落盘、密钥销毁与出站 HTTP 传输 |
| `apps/backend/src/gateway` | 网关入口与编排：FastAPI 服务路由、端到端脱敏流水线（`pipeline`）、入口屏障与出口错误脱敏净化器 |
| `apps/backend/src/protocol` | 协议与准入：OpenAI Chat Completions 与 Claude Messages 严格协议模型、受信身份、准入预算与静态模板免检 |
| `apps/backend/src/policy` | 外发政策：受信外发分级政策契约与出站权限评估 |
| `apps/backend/src/detection` | 隐私检测：混合检测编排器、Presidio 正则识别器、企业词典匹配、本地 ONNX NER 推理及长文本分窗 |
| `apps/backend/src/masking` | 脱敏与映射：请求级类型/角色短占位符生成、正向敏感文本替换与反向响应原值还原 |
| `apps/backend/src/document` | 文件文字解析与脱敏：内存处理 DOCX、Excel、文字 PDF 和 UTF-8 文本，生成脱敏 Markdown |
| `apps/backend/src/audit` | 审计与质检：释放意图台账、审计存储容量水位、质量评价口径与外发留证门禁 |
| `apps/backend/src/knowledge` | 受控知识域：实体与关系模型、单管理员版本化治理、多来源授权交集、消费回执与失效 Tombstone |

---

## 快速上手与验证

仓库为单 Git 根 monorepo：后端 Python 项目位于 `apps/backend`（源码 `src/`、测试 `tests/`、脚本 `scripts/`、模型资产 `models/` 与启动器均在其中），Compose 部署文件位于 `deploy/compose.yaml`。除特别说明外，本章命令的工作目录均为 `apps/backend`；Compose 命令在仓库根执行。

### 环境要求
* Python 3.11 ～ 3.13
* 依赖管理工具：`uv`

### 1. 安装与同步依赖
~~~bash
git clone git@github.com:paulfrom/enterprise_gateway.git
cd enterprise_gateway/apps/backend
uv sync --frozen --no-editable --group dev --cache-dir .uv-cache
~~~

### 2. 运行自动化测试套件
完整测试复用开发服务使用的公共 PostgreSQL、同一数据库与已有 schema；不创建或删除数据库、schema、角色，不修改授权或 RLS，也不自动建表。通过 `GATEWAY_TEST_PG_CONFIG` 指定私有 JSON，或使用被 Git 忽略的 `apps/backend/.env.test`；配置包含 `schema`、`application_role` / `app_dsn`、`history_role` / `history_dsn`、`admin_role` / `admin_app_dsn`，分别使用基础设施提供的现有受限登录。库名和 schema 不固定，允许 `public`。测试入口只读核验现有表和权限；用合成租户/业务域隔离数据，退出不删除共享表或历史数据。配置或表缺失直接失败，不自动补建。完整建表 SQL、配置示例和使用方式见[公共 PostgreSQL 使用约定](docs/postgresql-infrastructure.md)。 单独PG回归执行 `bash scripts/check_pg.sh`，入口不执行DDL或授权。

~~~bash
# Linux 后端检查（从 apps/backend 执行）
bash scripts/check.sh

# 或直接使用 uv 执行全量测试
uv run --frozen --no-editable --group dev --cache-dir .uv-cache python -m unittest discover -s tests -t . -v
~~~

应用集成通过`gateway.app.create_app`装配完整`ProviderRouter`、`ByokAuthenticator`和服务端可信分类函数`classifier(raw_body: bytes) -> str`。分类必须来自受信业务系统或获准分类器，客户端自报头或正文不提供授权依据。流水线使用实际规则/词典/NER、固定供应商映射、真实磁盘水位、持久审计和加密 spool；缺可信分类时就绪与模型接口返回503。配置变化构造新装配，在途请求继续使用原路由快照。

`gateway.runtime.create_runtime_app`是独立多供应商 BYOK 的唯一装配工厂。调用者提供处理租户/域、来源关联密钥、KMS、词典、NER目录、状态目录、受信政策、水位政策及证据留存桶。`config/providers.json`仅包含服务端固定 URL、协议、模型白名单与超时，不接受供应商 Key、重复渠道/模型、未知字段或客户端选址。默认配置仅是可修改的路由样例，不证明对应模型仍供应或已经准入；Claude 已停用模型已移出默认配置，Messages 协议须使用另行核验的供应商配置。

网关入口和供应商上游均支持 HTTP/HTTPS，HTTPS 为可选配置。上游 URL 可使用域名、私网或公网 HTTP 地址，例如 `http://10.0.0.8:8000/v1/chat/completions`；仍须匹配配置的协议路径和模型白名单。两种传输都执行 BYOK、分类、检测、留证、固定出口和 DNS 地址集校验。选择 HTTPS 时验证证书链与主机名，失败即拒绝，不自动降级；HTTP 不提供传输加密。

客户端通过规范 `Authorization: Bearer ...` 或 `x-api-key` 携带凭据；允许两个头同时出现，但去掉 Bearer 前缀后的令牌必须相同且非空。同名鉴权头重复、令牌冲突或任一凭据格式错误均拒绝。外发仅生成渠道指定的一个鉴权头。网关转发当次客户端 Key，账单归供应商账户；不持有付费供应商 Key、不提供模型推理算力、不垫资、不换 Key/供应商重试。Key 的带密钥关联标识只标记未验证来源，不授予企业员工角色、知识所有权或阅读权限。内部 `TrustedIdentity` 和 `EnterpriseAuthenticator` 仅保留给受信审阅组件，不能作为 BYOK 入口的默认身份。

DeepSeek响应恢复支持普通 `content`、`reasoning_content`、`reasoning_details` 文本和可解析的工具参数中的已知映射令牌；未知字段、用量明细和 `logprobs` 保持原值。无法恢复的保留令牌仍报告恢复错误。

`audit.admin_reader.AdminReviewService` 提供单管理员直接审阅。后台构建器从可信释放意图与加密证据建立目录，管理员通过 `/api/admin/audit/records` 查询元数据，并读取指定记录。读取校验精确关联、摘要、AAD、会话、期限和密钥状态；访问尝试与结果可靠留痕失败时不释放明文。审计目录和知识治理使用独立资源，不能接收任意密文或文件路径。

### 3. 启动网关服务 (本地与 Docker)

启动前由部署方准备受控文件与以下显式设置。密钥为小写十六进制；每项密钥只允许环境值或对应 `_FILE` 文件二选一，文件可含末尾换行。密钥文件置于受限目录并排除版本控制；整个运行期保持主密钥与持久状态卷一致。

| 设置 | 用途 |
|---|---|
| `GATEWAY_PROCESSING_DOMAIN` / `GATEWAY_PROCESSING_TENANT` | 服务端受限处理范围，不能从供应商 Key 推导 |
| `GATEWAY_STATE_DIR` | 持久目录，包含 `keys/`、`intents/`、`evidence/`、`spool/` |
| `GATEWAY_KMS_MASTER_KEY` 或 `_FILE` | 恰好32字节，包封本地持久独立 KEK |
| `GATEWAY_SOURCE_CORRELATION_KEY` 或 `_FILE` | 至少32字节，仅未验证来源关联 |
| `GATEWAY_DICTIONARY_PG_DSN` 或 `_FILE` | 词典受限数据库连接；未配置时复用知识管理连接 |
| `GATEWAY_DICTIONARY_FILE` | 首次入库时的受控 JSON 种子；已有发布版本后不再读取 |
| `GATEWAY_POLICY_FILE` | 符合 `ClassificationPolicy` schema 的受信政策 JSON |
| `GATEWAY_NER_PACKAGE_DIR` | 已核验完整本地 ONNX 模型包 |
| `GATEWAY_NER_TIMEOUT_SECONDS` | 可选的 NER 单次检测时间预算（秒），代码默认 30，Compose 部署默认 120；大文本 CPU 推理需按硬件调整，仍受请求总超时约束 |
| `GATEWAY_NER_MAX_WORKERS` | 常驻 NER 执行槽数，默认 `1`，必须为正整数；各 HTTP 应用进程分别拥有自己的池 |
| `GATEWAY_NER_MAX_PENDING` | 等待任务上限，默认 `4`；`0` 仅使用可用槽，长文本仍遵守短文本保留容量，需排队则立即拒绝 |
| `GATEWAY_NER_MAX_TASKS_PER_WORKER` | 成功请求上限，默认 `8192`；各槽错峰回收，空闲时预热替代进程 |
| `GATEWAY_NER_INTRA_OP_THREADS` | 每会话 ORT 算子内线程数；未设置时按可见物理核心和 CPU 配额分摊到执行槽 |
| `GATEWAY_NER_MAX_AGE_SECONDS` | 工作进程年龄上限，默认 `3600` 秒 |
| `GATEWAY_NER_MAX_RSS_MIB` | 工作进程峰值 RSS 回收阈值，默认 `2048`；`0` 显式关闭此项；共享快照内存另计 |
| `GATEWAY_NER_WINDOW_LENGTH` / `GATEWAY_NER_STRIDE` | 默认 `384` / `318`，包含 CLS/SEP，内容重叠 64 token；改变须重新验收边界召回 |
| `GATEWAY_NER_SENTENCE_BOUNDARIES` | `1` 启用合法 token 边界上的句界切分，默认 `0` |
| `GATEWAY_NER_BATCH_TOKENS` | 单次前向的 padding token 总预算，默认 `4096`，须至少容纳一个窗口 |
| `GATEWAY_NER_BATCH_WAIT_MS` | 短请求合批聚合等待上限，默认 `0`，关闭主动等待；启用时按目标硬件评测 |
| `GATEWAY_NER_MAX_BATCH_JOBS` | 每批请求上限，默认 `1`，关闭跨请求合批；请求内窗口仍按长度分组合批 |
| `GATEWAY_NER_MAX_BATCH_CHARS` | 短请求分类及合批总字符上限，默认 `512` |
| `GATEWAY_EVIDENCE_BUCKET` | 受控原始请求证据留存桶 |
| `PROVIDERS_CONFIG` 或 `--config` | 路由文件，默认 `config/providers.json` |
| `GATEWAY_CLASSIFIER` 或 `--classifier` | 运维批准的同步 Python `module:callable`，接收请求 bytes 并返回政策分类；未配置保持拒绝 |
| `GATEWAY_QUICK_SCREEN_ENABLED` | 默认 `true`；`false` 恢复对全部可检测文本的完整检测 |
| `GATEWAY_QUICK_SCREEN_THRESHOLD` | 默认 `0.35`，范围 `(0,1]`；分数达到阈值进入完整检测，越低越保守 |
| `GATEWAY_QUICK_SCREEN_BUDGET_MS` | 默认 `2`，范围 `(0,10]`；整个请求共享的筛选预算，耗尽后转完整检测 |
| `GATEWAY_DETECTION_FAILURE_MODE` | 默认 `error`；`passthrough` 在请求检测故障时透传未脱敏文本，客户端无法通过请求切换 |
| `GATEWAY_SSL_CERTFILE` / `GATEWAY_SSL_KEYFILE` | 可选的原生 HTTPS PEM 证书与私钥；启用时必须成对提供，也可用同名命令行参数；未配置时使用 HTTP |

Compose 使用一个受控只读 `GATEWAY_OPERATOR_DIR`，其中放置 `dictionary.json`、`policy.json`、受信分类器模块和可选 TLS 文件。该目录加入容器 Python 模块路径；例如 `deployment_classifier.py` 的 `classify` 函数对应 `GATEWAY_CLASSIFIER=deployment_classifier:classify`。这是部署方受信代码，会执行 Python 导入；不得挂载用户上传文件或把合成测试分类器用于真实业务。密钥仍使用独立 Docker secrets。Compose 与启动脚本默认开通外部访问（绑定 `0.0.0.0`，网关端口 8080，前端端口 80）；若仅需限制本机环回访问，可显式指定 `GATEWAY_BIND_ADDRESS=127.0.0.1` 与 `FRONTEND_BIND_ADDRESS=127.0.0.1`。入口允许 HTTP；需要原生 HTTPS 时再配置证书对。

本机启动时，受信分类器须安装到运行环境，或将其受控目录加入 `PYTHONPATH`；仅设置模块名称不会创建分类逻辑。路径和证书使用本机实际文件，容器内使用 `/app/operator/...`。

`FileKmsProvider`是受控本地文件后端，使用随机独立 KEK、进程锁、认证包封和持久销毁墓碑；不等同企业 KMS，也不证明备份/快照已删除。首次使用必须显式初始化密钥，常规启动绝不补建丢失的密钥。有任何历史意图/证据/spool记录时，初始化命令仅验证既有键，缺键拒绝。应备份受控密钥状态与主密钥；不能通过重新初始化恢复丢键后的密文。

~~~bash
# 已设置上表所需环境后，首次显式初始化
python start_gateway.py --provision-keys

# 常规启动；缺可信服务端分类时健康200、就绪/模型接口503
python start_gateway.py --host 127.0.0.1 --port 8080

# 配齐受信模块及正式证书后，原生 HTTPS 示例
python start_gateway.py --host 127.0.0.1 --port 8443 --classifier deployment_classifier:classify --ssl-certfile <certificate.pem> --ssl-keyfile <private-key.pem>

# Compose 使用必填 _FILE 密钥路径与 GATEWAY_OPERATOR_DIR，另准备受限 PG 连接（仓库根执行）
docker compose -f deploy/compose.yaml config --quiet
docker compose -f deploy/compose.yaml build backend frontend
docker compose -f deploy/compose.yaml run --rm --no-deps backend python start_gateway.py --provision-keys
docker compose -f deploy/compose.yaml run --rm --no-deps backend python scripts/check_local_resources.py --role backend
docker compose -f deploy/compose.yaml run --rm --no-deps knowledge-worker python scripts/check_local_resources.py --role worker
docker compose -f deploy/compose.yaml up -d backend frontend knowledge-worker
~~~

启动器调用同一工厂；不创建示例词典、默认获准分类或长期企业身份。受信 Python 集成可调用 `start_gateway.build_app(classifier=approved_classifier)`，CLI/镜像可通过上述运维模块引用装配同一分类器。配置模块引用只解决装配，不提供业务外发批准；无分类器保持503，错误引用、异步/错误签名函数或无效 TLS 证书对安全退出。有效 BYOK、合法协议与可信分类结果已到达时，高敏/禁止外发或未知分类输入可先形成受限加密观察，再拒绝外发；秘密检测/协议/存储失败仍拒绝采集。就绪会检查路由完整版本、分类接入、存储/密钥和真实水位；通过技术就绪仍不代表生产准入。容器探针适配 HTTP/HTTPS，仅表示本机存活；选择 HTTPS 时客户端须校验证书链与服务域名。

独立 `start_knowledge_worker.py`读取相同状态卷、主密钥、处理域和租户，将受限 spool 幂等提交到现有 PostgreSQL 表。另外显式配置 `GATEWAY_KNOWLEDGE_PG_DSN` 或 `_FILE`，以及服务端 `GATEWAY_KNOWLEDGE_WORKER_SUBJECT`；连接角色须非表 owner、非超级用户、无 BYPASSRLS，现有 schema/RLS 必须先部署。worker 不初始化数据库、不创建密钥、不批准或发布知识；可用 `--once` 执行单次重放。Compose 的 worker 连接部署方既有 PG，镜像不内置生产数据库。当前观察沿用30天技术留存和 `standard-retention` 桶，具体真实留存政策仍需业务核准。

数据库初始化与 worker 启动共享最小权限检查：应用角色不能具有创建数据库/角色、复制能力、切换到特权角色或直接/间接成为 PostgreSQL `pg_*` 全局预定义角色的成员。登录用户、会话用户与当前 SQL 用户须一致，不接受管理连接降级成应用角色。worker 对全部资产表检查 forced RLS，且应用角色不能拥有表或成为表 owner 的成员。单次执行 `--once` 在提交失败或隔离异常时返回非零；成功提交或幂等跳过返回0，失败记录仍保留以便重放。

PostgreSQL 是已有公共基础设施。项目提供[完整建表 SQL](deploy/sql/gateway_tables.sql)，由部署方在指定的已有数据库与 schema 中手工执行，包含当前 v4 的22张表、约束、索引、触发器、受限函数及 RLS 定义。文件不创建数据库、schema、角色或扩展，也不授予数据库/schema权限。应用与测试不持有基础设施管理员连接。数据库、schema、账号及授权由基础设施管理方维护；各服务连接同一数据库，通过现有角色区分知识、历史和知识管理用途。

默认 SQL 使用已有 `public` schema 和已有知识管理角色 `gw_knowledge_admin`。需要使用其他现有名称时，可离线导出 SQL，再由部署方手工执行：

~~~bash
cd apps/backend
.venv/bin/python scripts/export_gateway_sql.py --schema <existing-schema> --admin-role <existing-admin-role> > /tmp/gateway-tables.sql
.venv/bin/python scripts/check_gateway_database.py --config <private-service-connections.json>
~~~

导出命令不连接数据库；完整SQL可手工重复执行，保留已有表、策略与数据。检查命令仅执行只读验证，不创建或修复对象。已有 v2 表集合只需手工执行[别名表增量 SQL](deploy/sql/entity_aliases_v3.sql)，不重建其他表。详细权限边界、SQL执行方式和配置见[公共 PostgreSQL 使用约定](docs/postgresql-infrastructure.md)；未来正文去重设计见[数据库设计审查](docs/database-design.md)。

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

## 管理员登录与请求历史网页

页面由 `apps/admin-web` 的 React 应用提供，后端提供受保护数据 API。本机开发使用 HTTP，Compose 与本地拉起脚本默认开通外部访问（默认绑定 `0.0.0.0`），管理入口默认发布为 80 端口（访问 `http://<主机IP>/login` 或本机 `http://127.0.0.1/login`），后端探针默认发布为 8080 端口；不发布 443。Vite 开发入口默认 `http://127.0.0.1:3000`，代理保留原始 Host（含端口），可用 `GATEWAY_ADMIN_PROXY_TARGET` 指定本机后端。

管理控制台仅供固定管理员账号使用。访问同源 `/login` 以 admin 登录（密码由部署方在初始化时设定），服务端校验后签发 HttpOnly 会话 Cookie；登录后进入 `/admin` 管理壳，`/admin/requests` 可查看当前租户/保护域内全部未过期请求的输入、脱敏外发、供应商回复、还原输出，不按用户或供应商 Key 分组。四阶段可用正文默认直接展示和复制，无遮挡开关；列表支持模型/协议/状态/错误码/时间窗筛选和游标分页，部分或未产生的阶段单独标记，网关拒绝正文不会标成成功模型回复。未登录访问管理页面会跳转登录页；退出或会话失效后页面清除正文并回到登录页。

登录后访问 `/admin/documents` 的“文件脱敏”页面，可上传最大 10 MiB 的 DOCX、Excel、文字型 PDF 或 UTF-8 文本，预览并下载脱敏 Markdown。处理复用本地规则、词典和 NER，不调用供应商；检测或解析失败拒绝整份文件，不保存原文件和原值映射。输出不保留原版式，旧版 DOC 须先转换，扫描 PDF 不支持；XLS 仅能读取缓存值。接口、支持范围与限额见[文件脱敏契约](docs/contracts/file-redaction.md)。

历史与知识使用同一 PostgreSQL schema、分别限定表权限；历史使用用途为 `request-history` 的加密密钥和访问留痕；访问审计绑定操作者 admin 及会话关联摘要，不记录正文、密码或会话令牌。完整四阶段可推断原值关系，须按原文敏感级别治理。供应商 Key 不作为查询凭据，不保存到历史；会话令牌只经 Cookie 携带，服务端仅存摘要，不进入浏览器持久存储。

部署须显式提供以下整组配置，缺项拒绝启动；未选择历史装配时不采集四阶段正文：

| 设置 | 内容 |
|---|---|
| `GATEWAY_HISTORY_PG_DSN` 或 `_FILE` | 统一 schema 内仅有历史表权限的受限应用连接，不是管理连接 |
| `GATEWAY_HISTORY_RETENTION_DAYS` | 明确的留存天数，范围1～36500，无默认值 |
| `GATEWAY_HISTORY_BUCKET` | 历史加密用途的受控留存桶 |

历史与知识使用同一已有数据库和 schema，按上述完整 SQL 手工部署；不再提供自动初始化数据库/schema的 CLI。历史服务使用基础设施提供的现有受限连接。管理员状态由 `scripts/prepare_admin_state.py` 一次性显式初始化（保存随机盐与 scrypt 派生值，不保存明文密码；已存在时拒绝覆盖），管理员状态目录独立于历史数据库，历史未启用时仍可登录管理控制台。

历史配置完成后，首次显式执行 `start_gateway.py --provision-keys` 初始化用途密钥，再正常启动。已有历史（包括过期但未删除的记录）而密钥丢失时拒绝补建。查询 API 是 `GET /api/admin/requests?limit=50&status=&cursor=` 和 `GET /api/admin/requests/{request_id}`，仅接受同源管理员会话 Cookie，管理写操作另需会话绑定的 `X-Admin-CSRF` 头。模型调用返回 `x-request-id`。筛选仅针对元数据，不索引正文。

启用历史后，持久化失败会停止模型外发或正文释放。流式保存实际供应商字节及网关输出片段，断连可显示部分记录；`completed`表示完整生成和留存，不能证明客户端已收到。过期记录不可查询，使用 `scripts/purge_request_history.py --config <private-purge.json>` 定期物理删除；配置字段及密钥输入见工具 `--help`。在线删除不证明备份和复制密钥已销毁。HTTP 不加密会话 Cookie 和正文，远端访问应依据数据敏感度选择受验证的HTTPS；生产数据库TLS、目录权限、备份/删除、性能和真实客户端/供应商仍须验证。

## 知识治理与审计管理 API

知识管理 API 已支持来源、候选、发布和观察的全状态查询，以及来源治理、候选直接发布/拒绝/修订、来源撤回和发布撤销。所有接口使用管理员会话；写请求需同源校验与 `X-Admin-CSRF`。发布校验候选版本、全部来源的当前治理版本、消费受众交集、用途及有效期限，返回真实发布标识；幂等重试不会产生重复发布或 Outbox 事件。

启用知识管理时配置 `GATEWAY_ADMIN_KNOWLEDGE_PG_DSN` 或 `_FILE`，只能设置其中一个。 使用基础设施已有图时设置 `GATEWAY_KNOWLEDGE_GRAPH_NAME`，与私有PG配置的 `graph_name` 一致；不创建图或schema。它指向 DDL v2 knowledge schema，`search_path` 必须绑定该 schema，数据库登录身份是预建的专用受限 `admin_role`。初始化使用的 `admin_dsn` 是 DDL 属主连接，不能作为网关管理应用连接。管理登录角色不得拥有或可切换到 schema、表、序列或函数的属主身份，也不得具有特权或全局预定义角色成员关系。每次管理事务绑定服务端租户/域和 `app.admin_context='true'`，并核对结构指纹；旧结构不会自动迁移或修复。

审计管理使用同一 FileKMS 和受控证据根，后台构建批量上限 200、间隔 5 秒。新证据的服务端默认保留策略为 30 天（`model-query-retention-30d-v1`），只为具有持久可信关联和完整生命周期元数据的证据建立目录。`GET /api/admin/audit/records` 返回元数据和目录积压，`GET /api/admin/audit/records/{record_id}` 返回获准单条正文，`GET /api/admin/audit/events` 返回访问事件；最终会话、期限或可靠留痕检查失败时不返回正文。

知识 PG 池最多 2 条连接，获取和 SQL 超时均为 5 秒；知识与审计各使用独立的 4 并发执行器，管理操作预算 5 秒。目录和访问事件各有 64 MiB 配额，扫描上限 20,000 条。知识连接缺失、权限不符或指纹不符仅拒绝知识管理能力；审计资源不可用仅拒绝审计能力。新增治理与目录能力不成为模型请求准入条件，既有加密留证和 Spool 门禁仍执行。

授权消费、导出和词典编译已在服务层实现；正常部署的消费执行器、导出/编译管理作业及完整治理网页尚待装配。发布知识不会自动改变在线词典、保护包或模型外发政策。字段、固定原因码与后续复用接口见 [管理控制台契约](docs/contracts/admin-console.md)。

## 生产部署与安全边界声明

1. **不可绕过性**：完整覆盖必须由企业网络/客户端管理约束模型出口，并在供应商支持时实施来源限制；客户端持有供应商 Key，单纯配置 Base URL 无法阻止其绕过网关直连。
2. **内存物理擦除限制**：原值映射在请求结束时由 Python 垃圾回收机制释放对象引用，在解释器层面不保证物理 RAM 位的硬件擦除。
3. **推断风险防范**：文本实体替换能够消除直接标识符泄露，但不能完全阻止模型基于上下文语境产生的反向间接推断，高敏绝密数据应直接配置为 `LOCAL_ONLY` 强阻断。
4. **知识数据库权限**：候选读取核验自身和全部来源权限，拒绝状态持久化。归一描述表不并集ACL；固定search_path、撤销PUBLIC执行权的受限管理函数需要专用管理owner，应用角色不得继承其BYPASSRLS权限。读取与来源撤回/到期通过行锁明确事务顺序。
5. **客观限制**：入口按已准入协议拒绝未知字段。没有真实供应商签名接受、实际WorkBuddy组合、企业IAM/KMS、生产网络与发布的通用通过声明。具体验签算法及信任材料仍须审查准入，语法守卫不能证明任意Python算法安全。

## Linux 本机检查与资源配置

仓库只有根 npm workspace 锁文件和 `apps/backend` Python 项目。`.node-version` 固定已验证的 Node 22 补丁版本，Python 3.11，冻结 uv 依赖；从根运行 `GATEWAY_HISTORY_PG_CONFIG=<受控PG测试配置> bash scripts/check.sh`。检查同时核对结构、wheel 与源码、Docker 运行依赖和锁文件；后端 OpenAPI 与前端生成类型分别检查漂移，构建前实际检查 app/node TypeScript 项目，并验证类型错误能阻断构建。npm 审计的 high/critical 问题返回非零退出码。

数据库复用本机已有 PostgreSQL 5433。原生进程使用 `127.0.0.1:5433`，Compose 提供 `host.docker.internal:host-gateway` 映射，容器 DSN 指向宿主5433。开发服务、worker、管理端及测试共用指定的已有数据库和 schema；当前关系模型包含22张表（含 `entity_aliases` 和4张脱敏词典表）。数据库、schema、角色和扩展由公共基础设施维护，项目只提供手工表DDL与只读检查，不创建替代PG服务。知识与历史分别使用现有受限连接，DDL属主连接不交给应用或测试。CI运行在能访问同一基础设施的 `enterprise-gateway` 自托管Linux runner，通过 `GATEWAY_PG_CONFIG_JSON` secret提供现有服务配置，不启动PostgreSQL容器。

`bash rebuild_and_run.sh` 使用已有本地启动配置（如存在）或标准 Compose 配置；标准部署可显式运行 `bash rebuild_and_run.sh --env-file <受控绝对配置路径>`。默认绑定 `0.0.0.0` 开通外部访问，先校验再构建/更新，不先停止全栈。支持 `--export [tar_path]` 导出本地构建镜像为归档文件，支持 `--export-only [tar_path]` 仅构建/导出，不依赖运行秘密或拉起容器。已有密钥和管理员状态直接复用；初始化工具只用于尚未初始化的资源。持久卷显式绑定 `enterprise_gateway_gateway-state` 与 `enterprise_gateway_gateway-admin-state`，镜像预建 `/app/state/admin` 并使用 UID 65532。前后端基础镜像均固定 digest；后端只打包已准备的 ONNX 制品。

浏览器回归执行 `GATEWAY_HISTORY_PG_CONFIG=<受控本机PG测试配置> npm run test:e2e --workspace apps/admin-web`。它启动真实后端和 Chrome，复用已有表、使用合成供应商和独立测试数据作用域，结束不删除数据库对象或历史数据。`CHROME_PATH` 可指定本机 Chrome；无本机 Chrome 时使用 Playwright 安装的 Chromium。全量检查可设置 `GATEWAY_CHECK_BROWSER=1`，同一私有 PG 文件也可通过 `GATEWAY_TEST_PG_CONFIG` 提供知识测试配置。构建后的 Nginx 浏览器流程运行 `GATEWAY_HISTORY_PG_CONFIG=<受控PG测试配置> python3 scripts/run_nginx_e2e.py`；代理故障检查运行 `python3 scripts/check_proxy.py`。TypeScript 拒绝 canary 运行 `python3 scripts/check_typecheck.py`。Docker 输入隔离检查为 `python3 scripts/check_docker_context.py`，仅构建合成 canary，不复制真实秘密。

当前 React 管理端提供登录、会话恢复、退出、请求历史筛选/分页/四阶段正文、文件脱敏预览和 Markdown 下载，以及本地脱敏词典查询、编辑、停用、删除和版本发布。其他既有管理 API 仍保留认证与授权，尚未实现的管理页面不算作已交付能力。

设置 `GATEWAY_CHECK_DOCKER=1` 可在聚合入口追加两端 context canary、镜像构建与实际内容/hash、代理错误及 Nginx 浏览器检查。独立镜像核验入口为 `python3 scripts/check_images.py`，需先在相同源码上构建本机 dist 和两端镜像。退出请求失败时，网页立即清除历史与正文并提示服务端注销未确认。

本地词典以 PostgreSQL 为权威来源，管理页为 `/admin/dictionary`。保存修改形成草稿；发布编译成功后用于新聊天请求和文件脱敏，在途请求保留原快照，NER 池继续复用。字段与发布边界见[词典契约](docs/contracts/redaction-dictionary.md)。已有 v3 表集合部署[词典增量 SQL](deploy/sql/redaction_dictionary_v4.sql)，由基础设施提供现有管理登录的四张新表 DML 权限。
