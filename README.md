# 企业级大模型隐私与知识网关 (Enterprise Privacy & Knowledge Gateway)

面向企业大模型应用的隐私保护与受控知识沉淀项目。目标架构位于企业内部受信网络与模型供应商之间，覆盖两个目标：

1. **外发分级与精确隐私脱敏**：
   * **分级拦截**：高敏与禁止外发数据强阻断在企业本地网络；获准内容经过多引擎检测与脱敏后安全外发。
   * **请求级精确伪名替换**：基于 HMAC 机制在请求内存中建立临时原值映射，在受支持文本字段内精确恢复已知令牌；不保证检测零漏检或模型语义正确。
   * **全链路安全防护**：涵盖上游错误正文丢弃、异常断链防泄露、AES-GCM 信封加密落盘重放（Spool）、以及 KEK 密钥轮转与销毁。
2. **企业受控知识资产沉淀**：
   * 输入默认可进入知识采集与分析；来源、知识访问权限、用途与有效期分别治理。代码包含有向关系抽取、审批、事务 Outbox、PostgreSQL 持久化与 RLS 组件，自动候选须验证后发布。

已支持严格 Chat Completions 与 Messages 子集的受保护 HTTP 非流式、SSE、工具与多轮往返，以及加密采集产物到独立 worker、PostgreSQL、审批、授权消费、词典和撤回/到期的本地闭环。技术验证使用合成上游与业务身份，不能代表实际客户端、供应商或生产基础设施准入；未装配默认服务保持503。

SSE业务内容在协议终态与真实响应体EOF都验证后统一释放，此前只发送固定保活。原始及恢复后响应各有8MiB预算，工具参数恢复后每调用64KiB、全请求256KiB。该模式的首业务内容等待时间需要实际客户端联调；历史thinking必须由已绑定验证器验签，网关receipt只证明本域完整版本绑定。

---

## 核心安全与架构原则

* **零原文直连**：彻底废除 Break-Glass 明文穿透旁路；任何检测能力缺失、策略未知或组件异常时严格阻断外发。
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
│    ├── 逐字段严格解析 (OpenAI / Claude)                         │
│    ├── 受信身份与保护域绑定 (identity / admission)               │
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

应用集成通过`gateway.app.create_app`装配完整`ProtectedPipeline`、服务端`enterprise_credentials`和至少32字节`hmac_key`。流水线需要实际规则/词典/NER、固定模型映射与出站绑定、审计/加密spool及完整版本；企业凭据逐请求验证，供应商凭据只由固定出站客户端生成。配置变化构造新装配，在途请求继续使用原route、协议、工具和验证器快照。

`gateway.runtime.create_runtime_app`提供单个固定 Custom Chat Completions 渠道的装配入口。调用者须明确提供可信身份、企业接入凭据、HMAC密钥、KMS、词典、NER模型目录、存储目录及分级和水位政策。服务端供应商文件只允许一个明确的 Custom 模型与 HTTPS `/v1/chat/completions`地址，装配时读取并固定；客户端仅持企业地址和企业凭据。能力标志不代表图片、任意协议或生产准入，缺少依赖时拒绝；`/readyz`仍为503。

DeepSeek响应支持普通`reasoning_content`文本的精确恢复、`system_fingerprint`、空`logprobs`和有限用量明细：`prompt_tokens_details.cached_tokens`及`completion_tokens_details.reasoning_tokens`。计费和结构元数据保持不变；未知明细、非空logprobs和无法恢复的令牌拒绝。普通推理文本不构成已验签历史状态，下一轮请求仍按请求契约准入。

`audit.record_review.RecordReviewService`提供受控单记录审阅：限时工单绑定请求者、租户、域及精确加密记录，由两名不同角色审批者批准，持久化一次性消费标记并审计后才解密交付。记录与租户的关联须由可信存储提供；模块没有公开HTTP或批量审阅接口。生产身份、KMS及审计卷政策由部署方接入。

### 3. 启动网关服务 (本地与 Docker)

~~~powershell
# 本地 Python 直接启动独立脱敏网关 (加载 config/providers.json，支持 BYOK 与多供应商路由)
python start_gateway.py --host 0.0.0.0 --port 8080

# 或使用 Docker Compose 服务端一键启动
docker compose up -d --build
~~~

### 4. 接口与 BYOK 使用说明

| 请求端点 | 协议类型 | 典型调用方式 |
|---|---|---|
| `GET /healthz` | 进程存活探针 | `curl http://127.0.0.1:8080/healthz` -> 返回 `200 OK` |
| `POST /v1/chat/completions` | OpenAI / DeepSeek 协议 | 携带客户端自备 Key：`-H "Authorization: Bearer sk-user-key"`，Body 指定 `"model": "deepseek-chat"` 或 `"gpt-4o"` |
| `POST /v1/messages` | Claude Messages 协议 | 携带自备 Key：`-H "x-api-key: sk-ant-user-key"`，Body 指定 `"model": "claude-3-5-sonnet-20241022"` |

* **费用与配额归属**：网关自身不垫资、不持有供应商 Key，请求外发时动态注入调用方自备的 API Key，费用由供应商直接扣减调用方的账户。
* **多供应商路由**：网关读取 `config/providers.json` 自动将清洗后的请求路由到对应供应商（DeepSeek、OpenAI、Claude 或本地私有 vLLM）。

---

## 生产部署与安全边界声明

1. **不可绕过性**：网关必须部署为客户端到大模型上游的唯一出口，且上游服务必须配置仅接受来自网关 IP/证书的请求。
2. **内存物理擦除限制**：原值映射在请求结束时由 Python 垃圾回收机制释放对象引用，在解释器层面不保证物理 RAM 位的硬件擦除。
3. **推断风险防范**：文本实体替换能够消除直接标识符泄露，但不能完全阻止模型基于上下文语境产生的反向间接推断，高敏绝密数据应直接配置为 `LOCAL_ONLY` 强阻断。
4. **知识数据库权限**：候选读取核验自身和全部来源权限，拒绝状态持久化。归一描述表不并集ACL；固定search_path、撤销PUBLIC执行权的受限管理函数需要专用管理owner，应用角色不得继承其BYPASSRLS权限。读取与来源撤回/到期通过行锁明确事务顺序。
5. **客观限制**：不支持任意协议或未知字段透传；没有真实供应商签名接受、实际WorkBuddy组合、企业IAM/KMS、生产网络与发布的通用通过声明。具体验签算法及信任材料仍须审查准入，语法守卫不能证明任意Python算法安全。
