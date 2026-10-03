# 分级外发政策契约（C-01）

契约层：受信政策输入 → 严格解析 → 类型化政策对象 → 检测资格判断。本模块不做检测、不做网络出站；HTTP 模型入口保持 503（C-02 身份适配未实现，本契约不触碰 `app.py`）。

## 受信来源边界

- 政策来源只可以是受信配置/上下文对象：调用方以 Python `Mapping` 或受信 JSON 文本（`str`/`bytes`）显式交给 `load_policy`。
- 客户端请求体、请求头、自报"获准"永远不是政策来源。类型契约即边界：`load_policy` / `resolve_egress_policy` / `authorize_with_policy` 只接受上述类型，请求样对象传入即 `TypeError`（见 `test_request_shaped_object_is_not_a_policy_source`）。
- 头部自称 `approved_external`、伪造保护域无法进入政策：政策矩阵中的保护域随受信文档绑定，客户端没有任何字段可写入。
- 未来 C-02 身份适配实现后，由适配层从已认证内部通道提取身份元数据，再作为受信上下文显式传入；本模块不读取请求对象。

## Schema（可执行模型：`src/enterprise_gateway/policy.py`）

模型配置统一 `extra="forbid", frozen=True, strict=True`（同 `config.py` 风格）。枚举与数组字段单独放宽类型解析（`Field(strict=False)`），但取值仍受限：未知枚举值、非字符串 `category`/`scope` 仍拒绝；除这两处外不做任何字符串/布尔/数字宽松转换。

| 字段 | 路径 | 类型约束 | 必填 | 说明 |
|---|---|---|---|---|
| `version` | `$.version` | `str`（strict，拒绝 int/bool） | 是 | 政策文档版本标识 |
| `rules` | `$.rules` | 数组，元素为规则对象 | 是 | 合成分类矩阵 |
| `rules[].category` | `$.rules[*].category` | `str`，非空白 | 是 | 内容类别 ID |
| `rules[].label` | `$.rules[*].label` | 枚举 `secret`/`local_only`/`approved_external` | 是 | 业务分类标签 |
| `rules[].scope` | `$.rules[*].scope` | `str`，非空白 | 是 | 该类别绑定的保护域 |

解析规则：

- 未知字段（任意层级）拒绝；缺失必填拒绝；错误类型拒绝；未知枚举拒绝。
- 重复 JSON key（任意层级，`object_pairs_hook`）拒绝。
- 非标准 JSON 常量（`NaN`/`Infinity`/`-Infinity`，`parse_constant` 钩子）拒绝。
- 超深嵌套文档（解析器抛 `RecursionError`）归约为 `PolicyError` 拒绝，错误类型受控。
- 矩阵内 `category` 重复（歧义表）拒绝。
- 顶层不是 JSON 对象、JSON 非法：拒绝。
- 全部解析失败抛 `PolicyError(ValueError)`，公开消息为固定文案，不回显业务正文。异常链彻底断链：失败事实只在 `except` 块内记录，`PolicyError` 在异常处理之外抛出，`__cause__`/`__context__` 均为 `None`，`traceback.format_exc()` 不含 Pydantic `ValidationError`（其原始错误携带 `input_value`，经异常链会在 traceback 中回显提交内容）。
- 非 `str`/`bytes`/`Mapping` 来源（如请求对象）：`TypeError`。

## 合成分类矩阵

政策文档自带合成企业分类表（夹具 `tests/fixtures/C-01/matrix.json`）。标签到 `egress.DataClassification` 的映射唯一且复用 egress 语义，不另造分类枚举或放行逻辑：

| 业务标签 | 映射 | 解析 | 后续 |
|---|---|---|---|
| `approved_external` | `APPROVED_EXTERNAL` | 通过 | `resolve_egress_policy` 产出 `EgressPolicy(scope, APPROVED_EXTERNAL)`，可进入 `egress.authorize_egress` 检测资格判断 |
| `secret`（高敏） | `LOCAL_ONLY` | 通过 | `resolve_egress_policy` 抛 `PolicyError`，不到达检测资格判断 |
| `local_only`（不可外发） | `LOCAL_ONLY` | 通过 | 同上 |

`secret` 与 `local_only` 保留为独立测试标签（最终共同映射 `LOCAL_ONLY` 拒绝）；未知类别、缺失类别（空/`None`）同样在 resolve 层拒绝，不自动降级为获准。

## 正反例对应

| 场景 | 夹具 / 输入 | 测试 | 预期 |
|---|---|---|---|
| 受信获准类别+保护域 | `matrix.json`（`customer_faq`/`product_manual`） | `ClassificationMatrixTests.test_approved_category_reaches_eligibility_and_egress` | 解析成功；eligibility spy 被调用 1 次；模拟出站 1；`EgressPolicy` 分类为 `APPROVED_EXTERNAL`、scope 为矩阵绑定值 |
| 高敏 | `label-secret.json` | `test_secret_label_rejected_before_eligibility` | `PolicyError`；spy 0；出站 0 |
| 不可外发 | `label-local-only.json` | `test_local_only_label_rejected_before_eligibility` | `PolicyError`；spy 0；出站 0 |
| 未知类别 | `matrix.json` + `ghost_category` | `test_unknown_category_rejected` | `PolicyError`；spy 0；出站 0 |
| 缺失类别 | `""`/`"   "`/`None` | `test_missing_category_rejected` | `PolicyError`；spy 0；出站 0 |
| 未知枚举 | `unknown-label.json` | `test_rejecting_fixtures_raise_policy_error` | `PolicyError` |
| 缺失必填 | `missing-version.json` | 同上 | `PolicyError` |
| 错误类型保护域 | `wrong-type-scope.json`（int）+ bool/list 内联 | `test_rejecting_fixtures_raise_policy_error`、`test_no_string_or_bool_coercion` | `PolicyError` |
| 空保护域 | `empty-scope.json` | `test_rejecting_fixtures_raise_policy_error` | `PolicyError` |
| 未知字段 | `unknown-field.json`（含 canary） | `test_rejecting_fixtures_raise_policy_error`、`test_policy_error_does_not_echo_business_text` | `PolicyError`；canary 不回显，且 `__cause__`/`__context__`/`traceback.format_exc()` 均无 canary 与 ValidationError |
| 重复 JSON key | `duplicate-key.json` | `test_rejecting_fixtures_raise_policy_error` | `PolicyError` |
| 矩阵内重复类别 | `duplicate-category.json` | `test_rejecting_fixtures_raise_policy_error` | `PolicyError` |
| 非标准 JSON 常量 | 内联文本（`NaN`/`Infinity`/`-Infinity`） | `StrictParsingTests.test_nonstandard_json_constants_rejected` | `PolicyError`，异常链干净 |
| 超深嵌套文档 | 内联文本（1500 层） | `StrictParsingTests.test_excessively_nested_document_rejected` | `RecursionError` 归约为 `PolicyError`，异常链干净 |
| 客户端自称获准/伪造域 | `FakeClientRequest`（头+体均自称获准） | `TrustedSourceBoundaryTests.test_request_shaped_object_is_not_a_policy_source` | 三入口均 `TypeError`，无法构造政策 |
| 获准但检测缺失 | `matrix.json` + 缺一项 | `EgressCombinationTests.test_approved_with_missing_detector_still_blocked` | `SafetyError(DETECTION_INCOMPLETE)`；spy 1；出站 0 |
| 获准但检测失败/超时 | 同上替换状态 | `test_approved_with_failed_or_timed_out_detector_still_blocked` | `SafetyError(DETECTION_FAILED)`；spy 1；出站 0 |
| 获准但未知检测器 | 同上多一项 | `test_approved_with_unknown_detector_still_blocked` | `SafetyError(UNKNOWN_DETECTOR)`；spy 1；出站 0 |

测试中的 eligibility spy 与出站计数均为合成观察（spy 包装真实 `authorize_egress`），不是网络证据；本批无真实出站。

## 能力限制（L1）

- 合成政策矩阵不等于真实企业分类表授权；真实分类来源、IAM、渠道准入待后续 R 项。
- 本契约不产生真实外发许可；检测器仍未实现，获批仅是"具备进入检测的资格"。
- `load_policy` 的 `Mapping` 路径要求调用方代码受信；把客户端可控 dict 直接传入属于调用方越权，不在本模块防护范围内（类型边界只挡请求样对象）。
