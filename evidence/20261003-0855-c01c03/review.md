# 批次评审记录（run-id: 20261003-0855-c01c03）

- 评审基线：baseline/source-manifest.txt（无 commit；源码/锁文件/已安装包/官方资料抽取件的真实 SHA-256）；设计输入 DESIGN.md V0.8、实施方案 02/03/08/09。
- 范围：批次前架构评审修复（共享文件）、C-01 政策契约、C-03 两协议契约。
- 评审者与独立性：批次前架构评审由主Agent执行（self_review，随用户"直接修复"指令落地）；C-01/C-03 实现评审由独立只读 reviewer subagent 执行（independent），主Agent逐项核实发现并安排修复、复验。

## 一、批次前架构评审发现（主Agent自评，已全部修复并复验）

| # | 位置 | 问题 | 影响 | 修复与复验 |
|---|---|---|---|---|
| A1 | knowledge.py approve/reject/publish/read_publication/withdraw_source | 未知 ID 抛原生 KeyError，穿透受控错误契约，repr 可能带内部 key 元组 | 调用方只能 500 兜底，错误类型不可控 | 收敛为 KnowledgeError（unknown candidate/publication/source）；新增 test_unknown_ids_raise_controlled_errors |
| A2 | core.py | SafetyError 错误码为散落字符串，测试 regex 硬编码，改名编译期不可发现 | 长期漂移风险 | 新增 errors.py（SafetyCode StrEnum），egress/mapping/spans 全部引用枚举 |
| A3 | core.py 244 行 | 外发政策/令牌映射/Span 三关注点混一文件，C-01/C-03 落地后会失控 | 结构风险 | 拆分为 egress.py/mapping.py/spans.py，无兼容导入层；测试相应拆分 |
| A4 | app.py | FastAPI 默认 RequestValidationError 响应 detail 含 input，未来端点接入后是正文回显通道 | 敏感回显隐患 | 注册不回显的 422 处理器；canary 测试 test_validation_error_does_not_echo_submitted_content（错误类型、extra 字段、截断 JSON 三路径） |

复验：scripts/check.ps1 离线重建 + unittest 40/40 通过（baseline/check-run.txt）。

## 二、P2 设计问题（记录，未修改领域规则，留设计/业务决策）

1. publish 不排除审批人兼任发布者；verification_ref 不查重（knowledge.py:318 附近）。属职责分离规则选择。
2. reject 硬编码 BUSINESS_REVIEWER，安全审批人无法拒绝候选（knowledge.py reject）。
3. 来源撤回仅精确到版本，无按 source_id 整体撤回；撤回授权要求 steward 仍在 source.acl 中（knowledge.py withdraw_source）。
4. KnowledgeLedger/MappingContext 并发语义未声明（接入 async 服务前需确定加锁或串行约束）。

以上涉及领域语义与业务规则，本批未代签；建议在 00 登记或在下一设计修订中裁决。

## 三、C-01/C-03 独立评审发现与处理（reviewer: independent）

### 已修复（修复后复跑，见各 result.json commands）

| # | 位置 | 问题 | 修复 |
|---|---|---|---|
| B1 | policy.py 异常链 | `raise ... from exc` 的 `__cause__` 持有含 input_value 的 ValidationError，traceback 可回显政策正文；egress-policy.md 声明不实 | except 块外抛新异常彻底断链；canary 测试断言 `__cause__`/`__context__` 为 None 且 format_exc 无 canary；文档按真实机制改写 |
| B2 | protocol-field-policy.md | "整数充浮点拒绝"声明与 pydantic v2 strict float 实际行为不符；`$.model` 行引用不存在的测试名 | 文档按实测行为改写并注明本地快照行为（新增测试固定）；测试名全部更正为真实名 |
| B3 | protocols.py 异常链 | `from None` 仅抑制显示，`__context__` 仍持有含 input 的 ValidationError | 同 B1 断链模式，canary 测试覆盖 |

### 已采纳的评审建议

| # | 问题 | 处理 |
|---|---|---|
| C1 | json 超深嵌套抛未受控 RecursionError（policy.py、protocols.py 同构） | 两模块均捕获归约为 PolicyError/ContractError，各加超深嵌套测试 |
| C2 | json.loads 默认接受 NaN/Infinity（非标准 JSON），当前被数值约束挡住但属未关的门 | 两模块均加 parse_constant 拒绝并加测试 |
| C3 | 部分边界行为正确但无单列测试（messages 空数组、缺 model、stop 超 16 序列、Claude content 空块数组） | C-03 全部补齐夹具/测试；C-01 侧对应边界已有合并覆盖，维持现状 |

### 已检查未发现问题（reviewer 结论，主Agent抽查复核一致）

未知/嵌套字段 forbid、重复 JSON key（任意层级）、非法 JSON/截断/非 UTF-8、白名单精确匹配、无角色免检路径、协议互换拒绝、正例真实性（eligibility spy 计数、解析结果字段断言）、证据真实性（artifact 哈希 12 项全中、fixtures-manifest 50/50、测试名引用无编造）。

## 四、最终复验（主Agent执行）

- `powershell -File scripts/check.ps1`（离线重建 wheel + unittest discover）：120/120 通过，exit 0（baseline/final-check-run.txt）。
- 真实 HTTP 烟测（uvicorn 仅绑 127.0.0.1，测后停止）：/healthz 200；/readyz 503；POST /v1/chat/completions 与 /v1/messages 携 canary 正文与凭据均 503 且无回显；未知路由 404 无回显（baseline/http-smoke.txt）。旧 reports/http-smoke.json 未充用。

## 五、未解决问题

- 第二节 P2 四项（领域规则决策，不阻塞 L1）。
- Docker 构建/运行仍未实测；真实渠道/IAM/检测器/持久审计按 WBS 后续任务。
- 官方协议页面无稳定版本号，C-03 契约以本地快照固定（baseline/official-sources.md）；真实 New API/WorkBuddy/供应商组合留 R 项。

## 六、验收结论

C-01、C-03 均满足 09 交付卡全部场景与 08 完成条件，达到 **L1**；评审硬条件（独立评审、阻塞修复复验）已满足。结论仅覆盖合成契约行为，不构成真实外发授权或生产准入。
