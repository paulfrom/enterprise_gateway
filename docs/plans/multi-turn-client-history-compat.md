# 多轮对话客户端历史回传兼容改造方案

> 状态：已实施（待评审） | 触发事件：2026-10-15 `01a13cfccbfb7a44be01b93842805b76` 400 拦截
> 范围：`/v1/chat/completions`（DeepSeek Chat Completions 路径）多轮历史解析与外发
> 目标：在不破坏“分类先于替换、无未脱敏外发”门禁的前提下，消除客户端回传历史元数据导致的误拦截。

## 1. 报错定位（证据链）

### 1.1 运行环境

- 容器：`enterprise_gateway-backend-1`（`0.0.0.0:8080 -> 8080`）。
- 入口日志（`docker logs`）中 `x-request-id: 01a13cfccbfb7a44be01b93842805b76`、
  `x-conversation-id: 279eb8a1-5cb2-4458-8eb8-dfa83b9a5869`，时间 `2026-10-15 00:36:02`，
  `POST /v1/chat/completions`，`content-length: 156156`。

### 1.2 请求历史库（可解码证据）

`request_records` 中同一会话相邻的 4 次调用：

| 时间(UTC) | history `request_id` | 字节 | 状态 | error_code | 说明 |
|---|---|---|---|---|---|
| 00:34:02 | `3360ac4a-…` | 2376 | completed | – | 轮 1，无文档 |
| 00:34:08 | `a09f8e97-…` | 137578 | completed | – | 轮 1，携带 doc |
| 00:35:49 | `c88b2ecc-…` | 145451 | **blocked** | **PROTOCOL_VIOLATION** | 轮 2（首次提交） |
| 00:36:02 | `85ea1fcd-…` | 148126 | **blocked** | **PROTOCOL_VIOLATION** | 轮 2（重试，即上报请求） |

解码后报文结构（`85ea1fcd` / `c88b2ecc` 一致）：

```
messages[0].role = system     keys: role, content
messages[1].role = user       keys: role, content, startsNewUserRequest, agent, conversationRequestId
messages[2].role = assistant  keys: role, content, conversationRequestId, messageId, stepSeq,
                                    model, requestModelId, requestModelName, traceId,
                                    rawUsage, usage, reasoning, reasoning_content
messages[3].role = user       keys: role, content, startsNewUserRequest, agent, conversationRequestId
```

- assistant 文本块：`{"type":"text","text":…,"annotations":[]}`；
- assistant 还携带 `reasoning_content`（约 3KB 明文思考）与同源别名 `reasoning`；
- 轮 1（`a09f8e97`，带 doc）只有 `system + user`，因此成功；轮 2 客户端把上一轮 assistant 消息原样回传，才触发拦截。

### 1.3 代码级根因

失败发生在严格解析阶段，而非脱敏阶段：

1. `apps/backend/src/protocol/protocols.py`
   - `DeepSeekTextBlock`（extra=forbid）不接受 `annotations`；
   - `DeepSeekMessage`（extra=forbid）不接受 `messageId / stepSeq / model / requestModelId /
     requestModelName / traceId / rawUsage / usage / reasoning`；
2. `protocols._parse()` 把 Pydantic `ValidationError` 统一转成 `CONTRACT_VIOLATION`；
3. `gateway/ingress.py` 再统一包装为 `PROTOCOL_VIOLATION`：

复现验证（当前代码 + 计划中的轮 2 报文形状）输出的 Pydantic 错误定位：

```text
messages[2].content[0].annotations   extra_forbidden
messages[2].messageId                extra_forbidden
messages[2].stepSeq                  extra_forbidden
messages[2].model                    extra_forbidden
messages[2].requestModelId           extra_forbidden
messages[2].requestModelName         extra_forbidden
messages[2].traceId                  extra_forbidden
messages[2].rawUsage                 extra_forbidden
messages[2].usage                    extra_forbidden
messages[2].reasoning                extra_forbidden
```

（`reasoning_content` 已被模型接纳，但随后被第 4 步的入口显式拒绝。）

```python
# gateway/ingress.py（当前）
if any(m.get('reasoning_content') is not None for m in payload['messages']):
    raise SafetyError(SafetyCode.PROTOCOL_VIOLATION, 'unverified history')
```

4. `gateway/app.py::_render_safety_error` 对 `PROTOCOL_VIOLATION` 返回 400 与固定文案，
   因此客户端只看到“请求已根据安全规则拦截”，拿不到具体码。

结论：**两个独立原因叠加**——(a) 客户端回传的 assistant 消息级与块级账本字段触发 `extra=forbid`；
(b) `reasoning_content` 被入口显式拒绝。只修 (a) 仍会因 (b) 返回 400。

### 1.4 安全侧事实

- 响应恢复阶段（`masking/restorer.py`）会把 `content` 与 `reasoning_content` 中的占位符
  还原为**明文**再返回客户端；客户端因此持有明文思考文本。
- 外发报文取自 `redacted_request.model_dump(exclude_unset=True)`（`gateway/pipeline.py`），
  当前 `reasoning_content` 不在检测范围内；若仅“放行”而不丢弃，将破坏
  ADR-0003「无未脱敏外发」。

## 2. 改造原则

1. 未知/未建模字段继续 fail-closed，不做“删除后继续转发”的通用容错。
2. 仅对**已知客户端账本字段**做显式接纳，并保证其**永不外发、永不进入检测片段**。
3. 历史 assistant 的 `content` 继续每轮重检测（多轮重脱敏不变）。
4. 不引入“历史重发证明/receipt”新机制；思考文本按上游约定回传语义处理。
5. 错误码对外仍收敛为固定文案，但内部可诊断（结构化、无正文日志）。

## 3. 推荐方案 A：显式接纳 + 非外发（exclude）

核心：把客户端账本字段建模为 **可解析但不可序列化** 的字段（`Field(exclude=True)`），
从源头保证它们不会出现在证据、知识、外发报文中。

### 3.1 `apps/backend/src/protocol/protocols.py`

```python
class DeepSeekTextBlock(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    type: Literal["text"]
    text: str
    # 客户端块级账本：接纳以兼容，绝不外发。
    annotations: list[Any] | None = Field(default=None, exclude=True)


class DeepSeekMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    role: Literal["system", "user", "assistant", "tool"]
    content: ...
    tool_calls: ...
    tool_call_id: str | None = None

    # 客户端回传的思考文本：接纳但永不外发、永不参与检测。
    reasoning_content: str | None = Field(default=None, exclude=True)
    reasoning: str | None = Field(default=None, exclude=True)

    # 客户端消息级账本：接纳但永不外发。
    startsNewUserRequest: bool | None = Field(default=None, exclude=True)
    agent: str | None = Field(default=None, exclude=True)
    conversationRequestId: str | None = Field(default=None, exclude=True)
    messageId: str | None = Field(default=None, exclude=True)
    stepSeq: int | None = Field(default=None, exclude=True)
    model: str | None = Field(default=None, exclude=True)
    requestModelId: str | None = Field(default=None, exclude=True)
    requestModelName: str | None = Field(default=None, exclude=True)
    traceId: str | None = Field(default=None, exclude=True)
    rawUsage: dict[str, Any] | None = Field(default=None, exclude=True)
    usage: dict[str, Any] | None = Field(default=None, exclude=True)
```

要点：
- 保留 `_valid_role_content`，`reasoning_content` 仅允许 assistant（类型/角色仍校验）；
- `exclude=True` 使 `model_dump(exclude_unset=True / exclude_none=True)` 均不产出这些字段，
  从而 `replace_request()` 重建的 `redacted_request` 与最终外发报文都不含它们；
- 已存在的 `startsNewUserRequest / agent / conversationRequestId` 由“透传”改为“丢弃”，
  属行为变更，需在联调环境确认聚合上游不依赖（见 §6）。

### 3.2 `apps/backend/src/gateway/ingress.py`

- 删除 `reasoning_content` 显式拒绝块，替换为契约注释：思考文本与消息账本由协议层
  `exclude` 保证不外发，历史 assistant 的 `content` 仍进入重检测；
- 可选防御：对 `payload['messages']` 断言不含 `reasoning_content/reasoning` 等字段
  （与 `exclude` 形成双重保险，作为断言而非信任）。

### 3.3 契约与文档

- `docs/contracts/deepseek-chat-response.md` 末段改为：
  - 响应侧不变：`reasoning_content` 为普通文本，按映射恢复，未知 token 拒绝；
  - 请求侧新增：客户端回传的 assistant 思考文本（`reasoning_content`/`reasoning`）与
    块级/消息级账本字段（`annotations`、`messageId`、`stepSeq`、`model`、
    `requestModelId`、`requestModelName`、`traceId`、`rawUsage`、`usage` 等）**接纳但丢弃**，
    不参与检测、不进入外发与留证处理阶段；
  - 明确其余未知键仍 fail-closed。

### 3.4 测试改造

| 文件 | 变更 |
|---|---|
| `tests/gateway/test_ingress_validator.py` | 将 `test_unproven_reasoning_history_is_rejected` 改为：真实客户端 assistant 回传（含 `reasoning_content`、`reasoning`、`annotations`、全部账本字段）解析成功，`model_dump()` 不含上述字段，fragments 仅覆盖 `content` 文本 |
| `tests/integration/test_protocol_lifecycle.py` | `test_unproven_history_and_upstream_errors_have_zero_plaintext_release` 的 DeepSeek 分支：`reasoning_content` 用例改为“放行且外发报文零思考字段、零明文”，`compression` 等未知键仍 400 且零外发 |
| `tests/gateway/test_online_remediation.py` / `tests/integration/test_protocol_matrix.py` | 增加端到端：把密钥/占位符放入 `reasoning_content` 与 `annotations`，断言上游收到的 payload 不含这些字段与原值，`content` 已被脱敏 |
| `tests/protocol/` 新增 | 对 `DeepSeekMessage`/`DeepSeekTextBlock` 的接纳与 `exclude` 序列化做单元锁定 |

### 3.5 可诊断性（建议同批）

在 `gateway/app.py` 的 `except SafetyError` 分支增加**仅含错误码、无正文**的日志：

```python
logging.getLogger(__name__).warning('REQUEST_BLOCKED code=%s', exc.code.value)
```

这样后续同类问题可直接从容器日志定位到 `PROTOCOL_VIOLATION`，无需解密历史库。

## 4. 方案 B（备选）：重检测并脱敏后回传思考文本

若联调确认聚合上游**必须**收到历史 `reasoning_content`，则：

- 将 assistant 的 `reasoning_content`/`reasoning` 纳入检测片段（roles、路径与 `content` 同级）；
- 外发时使用脱敏后思考文本；
- 需要同步扩展 `BusinessTextFragment` 路径、`replace_request` 可编辑叶子白名单、流式契约与文档。

代价与风险：思考文本体量可能很大、纳入检测会影响 NER 预算与延迟；且与 DeepSeek 官方
“下一轮不应回传 reasoning_content”的约定冲突。**仅在 A 无法满足上游时采用。**

## 5. 不建议方案

- 全局 `extra="ignore"`：会静默吞掉任意未知字段，破坏严格契约与零泄露门禁。
- 在中间件对原始 JSON 做通用“删字段后透传”：同样绕过契约枚举，难以审计。
- 为客户端账本字段签发 receipt/证明：本场景无需信任该历史，属于过度设计。

## 6. 验收标准

1. 回放 `85ea1fcd-…` / `c88b2ecc-…` 两份请求体（脱敏 fixture）：
   - 入口不再 400；
   - 上游 payload 不含 `reasoning_content`、`reasoning`、`annotations`、`messageId`、
     `stepSeq`、`model`、`requestModelId`、`requestModelName`、`traceId`、`rawUsage`、`usage`
     及 `startsNewUserRequest/agent/conversationRequestId`；
   - 上游 payload 中历史 `content` 已按当前映射重脱敏。
2. 对抗用例：上述被丢弃字段中植入密钥/占位符/已恢复明文，断言不进入外发与“redacted”留证阶段。
3. 未知字段（如 `compression`、`redacted_thinking`）仍 400 且零外发，回归不退化。
4. Claude Messages 路径与既有 `thinking` 验签/receipt 行为不变。
5. `docs/contracts/deepseek-chat-response.md` 与测试同步更新，全部测试通过。

## 7. 变更清单

| 文件 | 类型 |
|---|---|
| `apps/backend/src/protocol/protocols.py` | 模型字段接纳 + `exclude`（已实施） |
| `apps/backend/src/gateway/ingress.py` | 移除思考历史拒绝、更新契约注释（已实施） |
| `apps/backend/src/gateway/app.py` | 新增仅含错误码的 `REQUEST_BLOCKED` 结构化日志（已实施） |
| `docs/contracts/deepseek-chat-response.md` | 请求侧契约修订（已实施） |
| `tests/gateway/test_ingress_validator.py` | 用例改写：接纳 + 序列化排除 + 未知键仍拒绝（已实施） |
| `tests/integration/test_protocol_lifecycle.py` | DeepSeek 分支改写：放行且上游零账本字段（已实施） |
| `tests/gateway/test_online_remediation.py` | 新增端到端防泄露用例（已实施） |
| `tests/protocol/test_deepseek_client_history.py` | 新增序列化契约锁定用例（已实施） |
| `tests/protocol/test_protocol_contracts.py` | 既有 reasoning 历史用例改为断言不外发（已实施） |
