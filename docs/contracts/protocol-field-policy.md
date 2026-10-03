# 两协议候选请求契约字段处理表（C-03）

日期：2026-10-03。本文档是 `src/enterprise_gateway/protocols.py` 可执行契约的字段级说明，两者一一对应；实现以代码为准。

## 1. 协议与候选快照标识

| 协议 | 候选快照标识 | 官方来源 | 读取日期 | 版本事实 |
|---|---|---|---|---|
| DeepSeek Chat Completions | `deepseek-chat-completions` | https://api-docs.deepseek.com/api/create-chat-completion | 2026-10-03 | 页面无稳定协议版本号；本地契约快照以摘录日期固定，不伪造官方版本 |
| Claude Messages | `claude-messages` | https://platform.claude.com/docs/en/api/messages | 2026-10-03 | 页面无稳定协议版本号（运行时 API 版本由 `anthropic-version` 请求头决定，属部署配置）；本地契约快照以摘录日期固定 |

官方资料核读记录：`evidence/20261003-0855-c01c03/baseline/official-sources.md`；Claude 页面完整抽取件：`evidence/20261003-0855-c01c03/baseline/anthropic-messages-api-extract.txt`。

候选支持子集：普通文本对话。两协议的模型白名单（`DEEPSEEK_MODEL_WHITELIST`、`CLAUDE_MODEL_WHITELIST`）是**本地契约常量**，仅用于固定候选快照与 fail-closed 边界，不构成官方型号兼容声明。

## 2. 动作词汇

- **检测**：业务文本字段，进入后续检测链（本批仅由契约层标记，检测器另批交付）；所有 role 的 content 同等对待，不存在按角色免检的结构。
- **保真**：结构/采样字段，过白名单或取值约束后原样保留。
- **拒绝**：整请求拒绝，抛 `ContractError`（ValueError 子类），错误消息不回显请求正文。

通用拒绝行为（两协议一致，均有测试）：

| 场景 | 行为 | 测试名（类前缀见各表） |
|---|---|---|
| 非法 JSON / 截断正文 | `ContractError(MALFORMED_JSON)` | `::test_malformed_json_rejected` |
| 任意层级重复 JSON key | `ContractError(DUPLICATE_JSON_KEY)`，解析期拒绝 | `::test_duplicate_top_level_key_rejected`、`::test_duplicate_nested_key_rejected` |
| 非标准 JSON 常量（NaN/Infinity） | `ContractError(MALFORMED_JSON)`（`parse_constant` 拒绝） | DeepSeek/Claude `::test_nonstandard_json_constant_rejected` |
| 超深嵌套 JSON（RecursionError） | 归约为 `ContractError(MALFORMED_JSON)`，错误类型受控 | DeepSeek `::test_deeply_nested_json_rejected_as_controlled_error` |
| 非 UTF-8 字节输入 | `ContractError(INVALID_UTF8)` | DeepSeek `::test_invalid_utf8_rejected` |
| 顶层非 JSON 对象 | `ContractError(CONTRACT_VIOLATION)` | DeepSeek `::test_non_object_top_level_rejected` |
| 未列入字段表字段（含未知字段） | 拒绝（Pydantic `extra="forbid"`），不剥离后放行 | 各拒绝行 |
| 类型不满足 strict 模式（如字符串充数值、字符串充布尔） | 拒绝，不做宽松转换 | `::test_non_string_model_rejected` 等 |
| JSON number 整数形式进入 float 字段（如 `temperature: 1`） | **接受**：pydantic v2 strict float 将 JSON number 统一处理，1 与 1.0 等价；这是依赖库的实际行为、属本地快照行为，已用测试固定 | DeepSeek `::test_temperature_integer_form_accepted` |
| 错误消息回显正文或异常链携带正文 | 不发生；ContractError 消息仅含协议标识与静态 reason，且 `__cause__`/`__context__` 均不引用含 input 的 ValidationError（异常彻底断链） | `::test_error_message_does_not_echo_business_text` |
| 两协议载荷互换/混用专属字段 | 按所选协议契约拒绝异协议字段 | `::test_claude_messages_payload_rejected`、`::test_deepseek_chat_payload_rejected` 及专属字段行 |

## 3. DeepSeek Chat Completions 字段表

测试类前缀：`DeepSeekChatCompletionTests`（文件 `tests/test_protocol_contracts.py`，夹具 `tests/fixtures/C-03/deepseek/`）。

### 3.1 支持字段

| JSON 路径 | 类型与约束 | 必填/缺省 | 动作与理由 | 正测试 | 反测试 |
|---|---|---|---|---|---|
| `$.model` | string，strict，值 ∈ `DEEPSEEK_MODEL_WHITELIST` | 必填 | 保真；模型名是渠道绑定结构字段，任意模型名不得穿透 | `::test_minimal_text_conversation_parses`、`::test_whitelisted_models_parse_and_unlisted_model_rejected`（白名单分支） | `::test_whitelisted_models_parse_and_unlisted_model_rejected`（未列模型分支）、`::test_non_string_model_rejected`、`::test_missing_model_rejected` |
| `$.messages` | object[]，长度 ≥ 1，元素严格模型 | 必填 | 容器；逐消息处理 | `::test_minimal_text_conversation_parses` | `::test_empty_messages_rejected`（空数组）、缺省/错类型由 `CONTRACT_VIOLATION` 拒绝（严格模型覆盖） |
| `$.messages[i].role` | enum：`system`/`user`/`assistant` | 必填 | 保真；角色是结构字段，`tool` 角色意味着工具链未准入 | `::test_minimal_text_conversation_parses` | `::test_tool_role_rejected` |
| `$.messages[i].content` | string，strict（块数组形式不接受） | 必填 | 检测；**所有 role（含 system、assistant 历史）的 content 都是待检测业务文本**，同一字段无角色豁免结构 | `::test_minimal_text_conversation_parses`、`::test_all_message_content_is_business_text_regardless_of_role` | `::test_block_content_form_rejected` |
| `$.temperature` | number(float, strict)，0 ≤ v ≤ 2；官方摘录标注默认 1、上限 2；JSON number 整数形式（如 `1`）按 pydantic v2 行为接受为浮点（本地快照行为） | 可选，缺省 null | 保真；采样参数，下界 0 为本地快照约束（官方摘录未列下界） | `::test_sampling_stop_and_response_format_options_parse`、`::test_temperature_integer_form_accepted` | `::test_temperature_above_official_cap_rejected` |
| `$.top_p` | number(float, strict)，0 < v ≤ 1；官方默认 1 | 可选，缺省 null | 保真；核糖采样参数 | `::test_sampling_stop_and_response_format_options_parse` | 越界/错类型由严格模型拒绝（合并覆盖） |
| `$.stop` | string 或 string[]，数组 ≤ 16 序列 | 可选，缺省 null | 保真；停止序列 | `::test_sampling_stop_and_response_format_options_parse` | `::test_stop_sequence_limit_rejected`（超 16 序列）、错类型由严格模型拒绝 |
| `$.response_format` | object，仅 `type` 键 | 可选，缺省 null | 保真；结构化输出声明 | `::test_sampling_stop_and_response_format_options_parse` | `::test_response_format_unknown_type_rejected`、`::test_response_format_unknown_nested_key_rejected` |
| `$.response_format.type` | enum：`text`/`json_object`，官方默认 text | 缺省 text | 保真 | `::test_sampling_stop_and_response_format_options_parse` | `::test_response_format_unknown_type_rejected` |

### 3.2 官方字段但本批拒绝（未选入候选子集）

| JSON 路径 | 官方语义（摘录） | 动作与理由 | 反测试 |
|---|---|---|---|
| `$.max_tokens` | integer，1..393216 | 拒绝；候选快照未选入，且作为 Claude 专属字段的互换载荷识别依据 | `::test_max_tokens_rejected_as_claude_specific_field`、`::test_claude_messages_payload_rejected` |
| `$.stream` / `$.stream_options` | 流式开关/选项 | 拒绝；SSE 能力未实现（DESIGN §5 另批交付），恒非流式 | `::test_stream_and_stream_options_rejected` |
| `$.tools` / `$.tool_choice` | 工具定义/选择 | 拒绝；工具链未准入（DESIGN §5） | `::test_tools_and_tool_choice_rejected` |
| `$.thinking` / `$.reasoning_effort` / `$.messages[i].reasoning_content` | 思考配置/历史签名思考 | 拒绝；signed/opaque thinking 无来源证明（DESIGN §3），C-07 前不准入 | `::test_thinking_and_reasoning_fields_rejected` |
| `$.logprobs` / `$.top_logprobs` | 对数概率 | 拒绝；能力未选入 | `::test_logprobs_rejected` |
| `$.user_id` | 终端用户标识 | 拒绝；身份元数据走受信通道（C-02），不接受客户端自报 | `::test_user_id_rejected` |
| `$.frequency_penalty` / `$.presence_penalty` | 官方已标注 deprecated | 拒绝；官方声明不再生效 | `::test_deprecated_penalty_rejected` |
| `$.messages[i].name` | 消息级可选名 | 拒绝；候选子集不接纳消息级元数据 | `::test_unknown_message_field_rejected` |
| 其他未列顶层/嵌套字段 | — | 拒绝；fail-closed，不静默透传 | `::test_unknown_top_level_field_rejected`、`::test_non_object_top_level_rejected`、`::test_malformed_json_rejected`、`::test_duplicate_top_level_key_rejected`、`::test_duplicate_nested_key_rejected`、`::test_nonstandard_json_constant_rejected`、`::test_deeply_nested_json_rejected_as_controlled_error`、`::test_empty_messages_rejected`、`::test_missing_model_rejected`、`::test_stop_sequence_limit_rejected` |

## 4. Claude Messages 字段表

测试类前缀：`ClaudeMessagesTests`（夹具 `tests/fixtures/C-03/claude/`）。

### 4.1 支持字段

| JSON 路径 | 类型与约束 | 必填/缺省 | 动作与理由 | 正测试 | 反测试 |
|---|---|---|---|---|---|
| `$.model` | string，strict，值 ∈ `CLAUDE_MODEL_WHITELIST` | 必填 | 保真；同 DeepSeek | `::test_minimal_text_conversation_parses`、`::test_whitelisted_models_parse_and_unlisted_model_rejected`（白名单分支） | `::test_whitelisted_models_parse_and_unlisted_model_rejected`（未列模型分支）、`::test_missing_model_rejected` |
| `$.max_tokens` | integer，strict，≥ 1（官方必填；thinking budget 上限语义未选入） | 必填 | 保真；输出预算结构字段 | `::test_minimal_text_conversation_parses` | `::test_missing_max_tokens_rejected`、`::test_zero_max_tokens_rejected` |
| `$.messages` | object[]，长度 ≥ 1 | 必填 | 容器 | `::test_minimal_text_conversation_parses` | `::test_empty_messages_rejected`（空数组）、缺省/错类型由严格模型拒绝 |
| `$.messages[i].role` | enum：`user`/`assistant` | 必填 | 保真；Claude 无 system 角色 | `::test_minimal_text_conversation_parses` | `::test_system_role_rejected` |
| `$.messages[i].content` | string，strict；或仅含 text 块的数组（≥1 块） | 必填 | 检测；**所有 role 的 content/块文本都是待检测业务文本**，string 与块数组形式同等对待 | `::test_minimal_text_conversation_parses`、`::test_all_message_content_is_business_text_regardless_of_role`、`::test_text_block_array_and_sampling_options_parse` | 块数组中异型块见 4.2；`::test_empty_content_block_array_rejected`（空块数组） |
| `$.messages[i].content[j].type` | enum：仅 `text` | 块内必填 | 保真；块型判别 | `::test_text_block_array_and_sampling_options_parse` | `::test_image_block_rejected`、`::test_document_block_rejected`、`::test_tool_use_and_tool_result_blocks_rejected` |
| `$.messages[i].content[j].text` | string，strict | 块内必填 | 检测；块文本即业务文本 | `::test_text_block_array_and_sampling_options_parse` | `::test_text_block_extra_field_rejected`（含块级未知字段） |
| `$.system` | string，strict | 可选，缺省 null | 检测；仅纯文本形式，块数组形式不选入 | `::test_text_block_array_and_sampling_options_parse` | `::test_system_as_block_array_rejected` |
| `$.stop_sequences` | string[] | 可选，缺省 null | 保真；停止序列（官方摘录未列数量上限，按类型约束） | `::test_text_block_array_and_sampling_options_parse` | 错类型由严格模型拒绝（合并覆盖） |
| `$.temperature` | number(float, strict)，0 ≤ v ≤ 1 | 可选，缺省 null | 保真；官方摘录未列范围，上下界为本地快照约束并记录于此 | `::test_text_block_array_and_sampling_options_parse` | 越界/错类型由严格模型拒绝（合并覆盖） |
| `$.top_p` | number(float, strict)，0 < v ≤ 1 | 可选，缺省 null | 保真；同上 | `::test_text_block_array_and_sampling_options_parse` | 同上 |
| `$.top_k` | integer，strict | 可选，缺省 null | 保真；官方摘录未列范围，按类型约束 | `::test_text_block_array_and_sampling_options_parse` | 错类型由严格模型拒绝（合并覆盖） |

### 4.2 官方字段/块但本批拒绝（未选入候选子集）

| JSON 路径 | 官方语义（摘录/抽取件） | 动作与理由 | 反测试 |
|---|---|---|---|
| `$.stream` | 流式开关 | 拒绝；SSE 未实现 | `::test_stream_rejected` |
| `$.tools` / `$.tool_choice` | 工具/工具选择 | 拒绝；工具链未准入 | `::test_tools_and_tool_choice_rejected` |
| `$.metadata`（含 `user_id`） | 请求级元数据/用户标识 | 拒绝；身份元数据走受信通道，不接受客户端自报 | `::test_metadata_rejected` |
| `$.thinking`（含 `budget_tokens`） | 扩展思考配置 | 拒绝；budget ≥1024 且占用 max_tokens，准入证据另批 | `::test_thinking_config_rejected` |
| `$.messages[i].content[j]` type=`image` | base64 图片 | 拒绝；多模态未准入 | `::test_image_block_rejected` |
| type=`document` | base64 PDF | 拒绝；同上 | `::test_document_block_rejected` |
| type=`tool_use`/`tool_result` | 工具调用/结果块 | 拒绝；工具链未准入 | `::test_tool_use_and_tool_result_blocks_rejected` |
| type=`thinking`/`redacted_thinking`/`server_tool_use`/`web_search_tool_result`/`bash_code_execution*` | 思考/签名/服务端工具/搜索/代码执行块 | 拒绝；同上两类理由 | 由 `extra="forbid"` 与 type 枚举拒绝（同类块测试覆盖机制：`::test_tool_use_and_tool_result_blocks_rejected` 等） |
| `$.messages[i].content[j].cache_control` / `.citations` | 块级提示缓存/引用字段（抽取件行 1599） | 拒绝；官方可选块字段未选入 | `::test_text_block_extra_field_rejected` |
| `$.response_format` | —（DeepSeek 专属） | 拒绝；异协议字段互换载荷识别 | `::test_response_format_rejected_as_deepseek_specific_field`、`::test_deepseek_chat_payload_rejected` |
| 其他未列顶层/嵌套字段 | — | 拒绝；fail-closed | `::test_missing_max_tokens_rejected`、`::test_malformed_json_rejected`、`::test_duplicate_top_level_key_rejected`、`::test_duplicate_nested_key_rejected`、`::test_nonstandard_json_constant_rejected`、`::test_empty_messages_rejected`、`::test_missing_model_rejected`、`::test_empty_content_block_array_rejected` |

## 5. 能力边界

- 本契约是**候选快照**：证明两协议选定子集的严格解析/拒绝行为（L1），不等于真实 New API/WorkBuddy/供应商组合兼容（留 R 项）。
- 模型白名单是契约常量，不等于官方型号清单或兼容承诺；新增型号须走渠道准入评审。
- 静态免检边界（精确内容+指纹匹配）是 C-04 事项；本契约中所有 content 一律是待检测业务文本。
- HTTP 入口仍恒拒绝（503），本批无网络出站；解析函数仅从内存文本/字节输入工作。
