# DeepSeek Chat Completions 官方资料摘录（主Agent核读记录）

- URL: https://api-docs.deepseek.com/api/create-chat-completion
- 读取日期: 2026-10-03
- 版本标识: 页面未提供稳定协议版本号；本地契约快照以本摘录日期固定，不伪造官方版本。
- 页面列出的当前模型 ID: `deepseek-flash`, `deepseek-v4-pro`（候选契约采用配置化模型白名单，不硬编码页面型号）。

## 请求字段摘录（与候选契约相关）

- `messages`: object[]，必填，>=1；oneOf system/user/assistant/tool 消息。system 消息含 `content`(string, 必填)、`role`="system"、`name`(可选)。
- `model`: string，必填。
- `thinking`: object，可空；`type`: "enabled"|"disabled"，默认 enabled。
- `reasoning_effort`: string；none/low/high/max（minimal→low，medium/xhigh→high 映射）。
- `max_tokens`: integer，可空，1..393216。
- `response_format`: object，可空；`type`: "text"|"json_object"，默认 text。
- `stop`: string | string[]，可空，最多 16 个序列。
- `stream`: boolean，可空。
- `stream_options`: object，可空；`include_usage` boolean；必须配合 stream:true。
- `temperature`: number，可空，<=2，默认 1。
- `top_p`: number，可空，(0,1]，默认 1。
- `tools`: object[]，可空；type="function"；function.name 必填（[a-zA-Z0-9_-]，<=128）、description、parameters(JSON Schema)、strict(默认 false)。
- `tool_choice`: string("none"|"auto"|"required") | object（命名工具）。
- `logprobs`: boolean，可空；`top_logprobs`: integer 0..20。
- `user_id`: string，可空，[a-zA-Z0-9-_]，<=512；官方明确不要放用户隐私信息。
- `frequency_penalty` / `presence_penalty`: 官方标注 deprecated，不再生效。
- 历史 assistant 消息可含 `reasoning_content`（签名/不透明思考内容，准入证据见 C-07，本批不准入）。

# Claude Messages 官方资料摘录（主Agent核读记录）

- URL: https://platform.claude.com/docs/en/api/messages
- 读取日期: 2026-10-03
- 版本标识: 页面未提供稳定协议版本号（运行时 API 版本由 `anthropic-version` 请求头决定，属部署配置，不伪造具体值）；本地契约快照以摘录日期固定。
- 完整抽取件: baseline/anthropic-messages-api-extract.txt（哈希见 source-manifest.txt）。

## 请求字段摘录（与候选契约相关）

- 端点: POST /v1/messages。
- 顶层请求参数（官方 API 参考）: `model`(string, 必填)、`messages`(array, 必填)、`max_tokens`(integer, 必填)、`system`(string 或 block array, 可选)、`stop_sequences`(string[], 可选)、`stream`(boolean, 可选)、`temperature`(number, 可选)、`top_p`(number, 可选)、`top_k`(integer, 可选)、`tools`(array, 可选)、`tool_choice`(object, 可选)、`metadata`(object, 含 user_id)、`thinking`(object, 含 type/budget_tokens)。
- 消息结构: `role`("user"|"assistant")，content 为 string 或 content block 数组；block 类型含 text / image(base64) / document(base64 PDF) / tool_use / tool_result / thinking / redacted_thinking / server_tool_use / web_search_tool_result / bash_code_execution* 等。
- thinking: "Requires a minimum budget of 1,024 tokens and counts towards your max_tokens limit"（抽取件行 2278）。
- 图片/文档/工具/搜索/代码执行类 block 在类型目录中有定义，但本批候选契约不支持（标记不准入）。
