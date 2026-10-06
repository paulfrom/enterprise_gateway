# DeepSeek Chat Completions 响应有限合同

依据：[DeepSeek 官方 Chat Completions API](https://api-docs.deepseek.com/api/create-chat-completion/)。2026-10-06取得官方站点搜索索引内容；直接打开页面超时。采用已确认字段的有限集合，不声明支持官方全部能力。

非流式和 SSE 使用以下明确分类；未知键或类型拒绝，不删除后继续转发。

| 字段 | 接受类型与处理 |
|---|---|
| `message.reasoning_content` / `delta.reasoning_content` | 可省略或为 `string/null`；普通文本按请求映射恢复，未知或损坏令牌拒绝 |
| `system_fingerprint` | 可省略或为 `string/null`；保留字段和值；含恢复令牌的结构字段拒绝 |
| `choices[].logprobs` | 可省略或仅为 `null`；任何对象、数组或字符串均拒绝 |
| `usage.prompt_tokens`、`completion_tokens`、`total_tokens` | usage对象存在时，三个值必须为非负严格整数 |
| `usage.prompt_cache_hit_tokens`、`prompt_cache_miss_tokens` | 可省略；存在时为非负严格整数 |
| `usage.prompt_tokens_details` | 可省略；存在时仅接受对象及必需的非负整数 `cached_tokens` |
| `usage.completion_tokens_details` | 可省略；存在时仅接受对象及必需的非负整数 `reasoning_tokens` |
| SSE `choices[].delta.role` | 可省略或为 `assistant/null`；官方终态示例的null原样保留，不改变消息身份 |

所有计数拒绝负值、bool、浮点数、字符串；details对象拒绝额外键、空对象或null。非流式与SSE共享同一严格usage类型。计数、null、未出现字段和结构元数据按解析后的实际字段存在性保留；不以默认null补齐供应商未发送的字段。非流式完整验证后返回，SSE在协议终态与真实EOF都验证后释放，坏尾部撤销全部待交付业务帧。

DeepSeek普通思考文本不是签名或不透明状态，响应恢复不签发历史重发证明；Claude签名thinking继续按既有验签/receipt合同处理。请求侧未声明的 `reasoning_content` 仍严格拒绝；本合同不扩展图片、未知结束原因、logprobs、历史输入或任意供应商扩展。

对应检查：`tests/masking/test_deepseek_response_contract.py`、`tests/protocol/test_deepseek_stream_contract.py`，以及既有restorer、stream-events回归。
