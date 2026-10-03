# 企业隐私与知识网关

面向企业大模型使用的隐私保护与知识沉淀基础框架，具有两个目标：

- 按资料分级控制外发。高敏及不可外发内容只能在企业可信环境内处理；获准内容经过检测和脱敏后才可外发，并明确残余风险。
- 从获准业务材料中沉淀真实企业实体与关系，保留来源证据、原始权限、用途和有效期，自动生成候选，经验证后发布，为企业知识库持续优化提供数据。

仓库：[paulfrom/enterprise_gateway](https://github.com/paulfrom/enterprise_gateway)

**当前是可运行的本地基础框架，尚不是生产代理。两个模型接口固定返回503，没有上游HTTP客户端，没有真实供应商调用或真实知识采集。**

## 安全与知识边界

- 必需检测、审计或渠道能力缺失时拒绝请求，不提供原文直连或跳过保护的开关。
- 精确原值恢复映射仅存在于当前请求内存，不能从数据库、Redis或审计记录重建。
- 原值恢复与知识实体归一分离；别名归并不能改变恢复给用户的原始值。
- 企业实体、关系和来源属于受控知识资产，不是匿名统计；自动抽取或共现不能自行证明业务事实。
- 候选发布必须经过授权验证；来源权限、用途、到期和撤回约束需要传播到派生资产。
- 实体替换不能消除上下文推断，也不构成任意文本零泄漏保证。

架构决策见[请求内精确映射](docs/adr/0001-request-local-exact-mapping.md)、[证据约束的知识](docs/adr/0002-evidence-governed-knowledge.md)和[禁止无保护外发](docs/adr/0003-no-unprotected-egress.md)。

## 当前能力

- FastAPI服务：存活检查、就绪检查及安全拒绝入口；错误不包含请求正文、凭据或任意URL路径，请求校验失败不返回提交内容。
- 严格本地配置契约：拒绝未知字段和重复JSON key，不能通过配置开启生产能力。
- 分级外发政策契约：仅接受受信配置/上下文来源的政策输入，严格解析（未知字段、错误类型、重复JSON key、非标准JSON常量、过深嵌套均拒绝）；高敏、不可外发、未知或缺失分类拒绝外发资格，客户端自称获准不构成政策来源。
- 可信身份与保护域绑定契约：不可变受信身份上下文，强绑定租户、保护域、角色与原始ACL；严格拦截任意客户端伪造身份/域请求头，越权/跨域强阻断。
- 两协议候选请求契约：DeepSeek Chat Completions与Claude Messages的普通文本请求逐字段严格解析；每个支持字段及嵌套路径明确约束，未声明字段、错误类型、重复key、非法JSON整请求拒绝；工具、流式、图片/文件、思考块、身份元数据等未实现能力明确拒绝；所有消息文本均视为待检测业务内容，无角色免检。字段级处理规则见docs/contracts/。
- 精确静态内容免检契约：事前审批的静态模版精确内容与边界双重100%匹配免检；单字篡改、标点差异、动态变量混入及不可分离组合强制全量检测。
- 完整版本Manifest与请求版本生命周期固定：请求生命周期内绑定恒定包哈希；坏包原子拒载并回滚，在途请求与热更新安全隔离。
- 独立质量口径与划分审计契约：双维度测试集无交集审计，零秘密泄漏硬门禁一票否决，3/n单侧置信区间上界约束，未获准门槛显式声明。
- 网关入口综合验证与出口错误净化：综合验证屏障统一前置门禁；上游4xx/5xx错误正文、内部堆栈与凭据100%丢弃净化，保真透传状态码与Retry-After头。
- 请求内HMAC精确原文映射、碰撞拒绝、保留令牌字面量拒绝与生命周期清理。
- Span并集保护覆盖，秘密Span直接拒绝；数据分级及必需检测结果的前置契约。
- 纯内存知识候选：保留租户、保护域、来源版本、用途、ACL和期限；支持来源去重、不同角色双人审批、发布读取及到期/撤回tombstone。

领域组件用于合成验证。`authorize_egress`要求可信检测结果，但当前没有产生这些结果的检测器；HTTP入口不会通过该函数开放外发。

## 技术栈

| 用途 | 当前实现 |
|---|---|
| 语言与依赖 | Python 3.11～3.13、uv、锁定依赖及普通wheel安装 |
| HTTP服务 | FastAPI、Uvicorn |
| 数据契约 | Pydantic |
| 自动化验证 | 标准库unittest、HTTPX |
| 知识领域模型 | 纯内存对象与状态约束 |
| 容器定义 | Dockerfile、Compose；尚未构建或运行验证 |

## 安装与测试

准备Python和uv。推荐使用已验证的Python 3.11环境。

~~~powershell
git clone git@github.com:paulfrom/enterprise_gateway.git
cd enterprise_gateway
uv sync --frozen --no-editable --group dev --cache-dir .uv-cache
uv run --frozen --no-editable --group dev --cache-dir .uv-cache python -m unittest discover -s tests -v
~~~

Windows下，在首次安装已填充缓存后，可离线重建当前源码包并运行测试：

~~~powershell
.\scripts\check.ps1
~~~

普通wheel安装避免Python 3.11在中文路径下读取editable `.pth`的问题。修改源码后，应重新安装当前源码包再测试；Windows使用上述脚本，其他环境可执行：

~~~shell
uv sync --frozen --no-editable --group dev --reinstall-package enterprise-privacy-gateway --cache-dir .uv-cache
uv run --frozen --no-editable --group dev --cache-dir .uv-cache python -m unittest discover -s tests -v
~~~

## 本地运行

~~~shell
uv run --frozen --no-editable --cache-dir .uv-cache python -m uvicorn enterprise_gateway.app:app --host 127.0.0.1 --port 8080 --no-access-log
~~~

| 请求 | 当前响应 |
|---|---|
| `GET /healthz` | 200，进程存活 |
| `GET /readyz` | 503，尚不具备生产能力 |
| `POST /v1/chat/completions` | 503，请求未外发 |
| `POST /v1/messages` | 503，请求未外发 |

`config/local-review.json`是配置契约夹具。服务使用固定安全默认值，不能通过环境变量或配置注入上游。

## 模块结构

| 路径 | 内容 |
|---|---|
| `src/enterprise_gateway/app.py` | 本地HTTP服务与拒绝入口 |
| `src/enterprise_gateway/config.py` | 严格配置契约 |
| `src/enterprise_gateway/errors.py` | 受控错误类型与错误码注册表 |
| `src/enterprise_gateway/egress.py` | 数据分级与外发授权前置契约 |
| `src/enterprise_gateway/policy.py` | 受信来源的分级外发政策严格输入契约 |
| `src/enterprise_gateway/identity.py` | 可信身份与保护域/原始ACL绑定契约 |
| `src/enterprise_gateway/protocols.py` | 两协议普通文本请求的逐字段候选契约 |
| `src/enterprise_gateway/static_exemption.py` | 精确静态内容免检清单与边界评估契约 |
| `src/enterprise_gateway/manifest.py` | 包Manifest与请求版本生命周期固定 |
| `src/enterprise_gateway/quality_audit.py` | 独立质量口径、划分审计与零秘密泄漏契约 |
| `src/enterprise_gateway/ingress.py` | 入口综合验证屏障（整合政策、协议与免检） |
| `src/enterprise_gateway/error_sanitizer.py` | 上游错误脱敏与安全映射 |
| `src/enterprise_gateway/mapping.py` | 请求内精确映射与令牌生命周期 |
| `src/enterprise_gateway/spans.py` | Span并集保护与精确替换 |
| `src/enterprise_gateway/knowledge.py` | 纯内存知识模型与状态约束 |
| `tests/` | 组件、HTTP与合成知识流程测试 |
| `docs/adr/` | 架构决策及理由 |
| `docs/contracts/` | 政策与协议字段级契约说明 |
| `reports/` | 指定基线下的验证记录 |
| `Dockerfile`、`compose.yaml` | 本地容器定义 |
| `uv.lock`、`requirements-runtime.txt` | 依赖锁文件及含哈希的容器运行依赖 |

`tests/test_knowledge.py`中的`test_synthetic_approval_publish_read_and_withdraw_loop`覆盖合成流程：候选产生、安全与业务两人审批、发布、授权读取、来源撤回、tombstone以及撤回后拒绝读取。

## 当前限制

尚未实现真实规则/词典/NER检测、业务关系抽取、SSE/工具代理、供应商连接、KMS/AEAD持久审计、加密spool、PostgreSQL适配、IAM、下游发布及删除投递。

政策契约只验证受信输入的解析与分类映射，不实现企业身份认证，也不构成真实业务外发授权；合成分类表不是真实企业数据分类。协议契约是普通文本候选子集，不是完整供应商兼容声明：模型白名单为本地契约常量，工具调用、流式响应、多模态、思考块及历史状态准入均未实现；与真实渠道（接入层/网关组合）的兼容性尚未验证。

知识证据hash当前只是契约字段，不读取正文核验真实性；`TrustedActor`和`Source`需要由可信认证适配器构造。内存状态及tombstone不能证明持久发布或下游删除完成。权限变化需要撤回旧来源版本；关系有效时间与证据冲突尚无生产处理，当前模型仅验证否定、模态和来源期限。

映射退出时释放引用，不承诺Python内存物理擦除。HMAC稳定性会暴露同域同值关系，不能视为匿名化。精确匹配恢复器不能证明模型改写掉令牌语法后的业务含义正确。

容器尚未构建或运行验证，基础镜像tag尚未固定生产digest。实际渠道外发与真实知识采集需要分别具备完整的保护能力、真实环境验证及业务授权。
