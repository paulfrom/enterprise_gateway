# 批次任务卡：C-01 与 C-03（run-id: 20261003-0855-c01c03）

- 用户范围及来源：本轮用户请求"直接修复（评审第1组），并按照项目里程碑进入下一步开发"；对应任务ID：C-01、C-03，前置批次内修复不另造任务ID。
- 本批不包含：真实外发、真实IAM/身份适配（C-02）、检测器实现、SSE/工具/多模态能力、真实知识采集、生产部署。
- 基线：Git 无 commit（本地仓库 main 无提交；当前用户受 git safe.directory 限制无法读取状态，未改全局配置）。基线以真实文件哈希标识：baseline/source-manifest.txt（源码/测试/uv.lock/pyproject/已安装包/官方资料抽取件）。
- 基线复验：`powershell -File scripts/check.ps1`（离线重建 wheel + unittest），40 项全部通过，输出 baseline/check-run.txt。历史 38 项为旧记录，不作本批结果。
- 主Agent：本会话主Agent；reviewer：独立只读 subagent（验收阶段）。
- 设计输入哈希：source-manifest.txt 含 uv.lock/pyproject；设计文档为父目录 DESIGN.md V0.8、实施方案 02/03/08/09（未哈希，路径见父目录）。

## 批次内前置修复（主Agent直接落地，已复验）

1. knowledge.py 未知 candidate/publication/source ID 由 KeyError 收敛为 KnowledgeError（受控错误原则），新增 test_unknown_ids_raise_controlled_errors。
2. 错误码注册表：新增 errors.py（SafetyCode StrEnum + SafetyError），egress/mapping/spans 全部引用枚举成员。
3. core.py 拆分为 egress.py（外发政策）/ mapping.py（令牌映射）/ spans.py（Span并集与替换），无兼容导入层；test_core.py 相应拆为 test_egress/test_mapping/test_spans。09 交付卡中的文件路径据此调整。
4. app.py 注册 RequestValidationError 处理器：422 不回显提交内容（FastAPI 默认 detail 含 input，属敏感回显通道），新增 test_validation_error_does_not_echo_submitted_content（含 canary、extra 字段、截断 JSON）。

## C-01 分级外发政策契约

- 行为与输出：受信来源（配置/上下文对象，非客户端请求）输入严格解析为类型化政策；仅获准分类(APPROVED_EXTERNAL)到达检测资格判断；高敏/不可外发/未知/缺失分类、错误类型/枚举/未知字段/重复JSON key 一律拒绝；客户端自称获准不成为政策来源；拒绝时模拟出站计数为 0。
- 前置：F-01 → 本批 baseline/check-run.txt 复验通过；egress.py 既有 DataClassification/EgressPolicy/authorize_egress 语义沿用，不另造放行逻辑。
- 文件所有权（worker A 独占）：新增 src/enterprise_gateway/policy.py、tests/test_policy_contract.py、tests/fixtures/C-01/*、docs/contracts/egress-policy.md、evidence/20261003-0855-c01c03/C-01/*。只读：egress.py、errors.py、config.py。不修改 mapping/spans/knowledge/app。
- 设计依据：DESIGN.md §1/§3（未知分类拒绝、政策绑定保护域）；09 交付卡 §3 场景表。
- 交付物：严格政策 schema（Pydantic 风格可执行模型）、合成政策矩阵、正反例测试、C-01/result.json。
- 实际命令：`.venv/Scripts/python.exe -m unittest discover -s tests -p "test_policy_contract.py" -v` 及 scripts/check.ps1 全量回归。
- 正例：受信上下文中的获准类别+保护域 → 解析成功并明确到达检测资格判断（authorize_egress 可调用），不能只证明"没有抛错"。
- 反例：高敏/不可外发标签（保留独立标签，即使同映射 LOCAL_ONLY）、未知/缺失分类、空/错类型保护域、未知字段、错误枚举、重复 JSON key、客户端自称获准。
- 目标等级：L1；本次能证明合成政策契约行为；不能证明真实企业分类表/IAM/渠道准入。

## C-03 两协议字段契约

- 行为与输出：DeepSeek Chat Completions 与 Claude Messages 各自最小合法普通文本请求严格解析成功；每字段及嵌套路径明确检测/保真/拒绝；未知端点/顶层或嵌套字段、错误类型、重复 key、非法 JSON 整请求拒绝；图片/文件/工具/stream/signed thinking 等未实现能力明确拒绝；两协议载荷互换拒绝。
- 前置：F-01 复验通过；官方资料核读记录 baseline/official-sources.md（DeepSeek 页面全文摘要在任务卡记录、Claude 抽取件 baseline/anthropic-messages-api-extract.txt，均 2026-10-03 读取；两页面均无稳定协议版本号，以本地快照固定）。
- 文件所有权（worker B 独占）：新增 src/enterprise_gateway/protocols.py、tests/test_protocol_contracts.py、tests/fixtures/C-03/*、docs/contracts/protocol-field-policy.md、evidence/20261003-0855-c01c03/C-03/*。只读：其余全部源码。不新增依赖（沿用 Pydantic）。
- 设计依据：DESIGN.md §3（逐字段/未知拒绝/历史文本全处理/角色不免检）、§5；09 交付卡 §4 场景表。
- 交付物：两协议严格候选模型、字段处理表（含协议快照/JSON路径/类型约束/必填缺省/动作理由/正反测试对应）、官方来源记录、独立合法/拒绝夹具、C-03/result.json。
- 实际命令：`.venv/Scripts/python.exe -m unittest discover -s tests -p "test_protocol_contracts.py" -v` 及 scripts/check.ps1 全量回归。
- 正例：两协议各自最小合法纯文本请求（DeepSeek: model+messages[{role,content}]；Claude: model+max_tokens+messages[{role,content}]）解析成功，形成可供后续处理的字段结果。
- 反例：未知顶层/嵌套字段、错误类型、重复 JSON key、非法 JSON、system/历史消息按角色免检（不允许）、任意模型名穿透白名单、图片/工具/stream/thinking 块、协议互换载荷。
- 目标等级：L1；本次能证明候选契约解析/拒绝行为；不能证明真实 New API/WorkBuddy/供应商组合兼容（留 R 项）。

## 共享边界

- 两名 worker 均不写 app.py、config.py、errors.py、egress.py、mapping.py、spans.py、knowledge.py 及彼此独占文件；冲突先交主Agent。
- 共用错误类型：政策/协议解析失败使用 ValueError 子类（可新增专属错误类型于各自模块），不回显业务正文。
- workers 不是独自在代码库，不得回滚他人修改。
- 本批无真实出站；政策/契约测试中的下游观察必须是合成 spy 并注明。
