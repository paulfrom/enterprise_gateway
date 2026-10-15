# 历史消息检测结果缓存：评估与实施方案

> 状态：待评审 | 目标：把多轮对话中「每轮对全量历史重跑规则/词典/NER」的 O(n²) 检测成本降为 O(n)，
> 且不引入明文留存、不改变 fail-closed 语义。仅解决**效率**，不解决跨轮 token 编号稳定性。

## 1. 背景与成本

多轮路径（`gateway/app.py` → `gateway/pipeline.py::ProtectedPipeline.process_request` → `detection/detection_orchestrator.py::detect_many`）：

1. 每轮客户端回传完整历史（明文，网关已还原）；
2. `IngressValidator` 为每条 user/assistant `content` 与 tool 结果生成 `BusinessTextFragment`；
3. `pipeline` 先做快速风险筛选（`QuickRiskScreen.assess_many`），命中片段再进入
   `detect_many`：规则路（`recognizers`）→ 词典路（`analyze_dictionary`）→
   NER 路（隔离 worker 内 ONNX 推理）→ `resolve_spans` 合并。

第 k 轮要对前 k-1 轮的全部消息再跑一遍 NER，整段会话累计约 O(n²)。NER 是其中最贵的部分
（隔离进程、切窗、前向）。历史消息内容在轮与轮之间通常**逐字不变**，因此存在可复用的确定性结果。

现有确定性事实（缓存可行的前提）：规则/词典/ONNX 推理对同一文本与同一装配是确定性的；
`DetectionOutcome` 已经携带 `dictionary_version`、`recognizer_names`、`ner.model_sha256` 等
可追溯元数据，且 `ResolvedSpan` 只含偏移/类型/优先级/来源，不含正文。

## 2. 目标与非目标

**目标**
- 同一 `(文本, 检测装配指纹)` 的片段只跑一次完整检测，后续请求直接复用其 `DetectionOutcome`。
- 缓存条目**不含任何业务正文**；键为带密钥摘要，缓存仅驻留网关进程内存。
- 保持现有 fail-closed 前置校验（检测三路未装配仍拒绝）。

**非目标**
- 不解决跨轮 token 编号/角色前缀漂移（那是「会话级别名账本」的议题）。
- 不缓存失败、超时、`passthrough`、秘密（P0）阻断等结果。
- 不引入 Redis/PostgreSQL 等共享或持久缓存（与 ADR 0001「共享映射扩大暴露面」的取向一致；
  `start_gateway.py` 使用单进程 `uvicorn.run`，进程内缓存即可覆盖全部在途请求）。

## 3. 缓存单元与键

**单元**：单个 `BusinessTextFragment` 的完整 `DetectionOutcome`（`spans` + 溯源元数据）。

**键**：
```
key = HMAC-SHA256(k_cache, detection_fingerprint || 0x00 || fragment_text_utf8)
```
- `k_cache`：装配时用 `secrets.token_bytes(32)` 生成的**进程内临时随机密钥**（不落盘、不经运维配置、
  重启即失效）。用它做 HMAC 只是避免缓存键成为「已知明文猜测验证器」；无需持久化，也不参与任何协议。
- `detection_fingerprint`：绑定检测语义的装配快照，取 `ProtectedPipeline._component_payloads()`
  中的 `rules`、`dictionary`、`ner` 三块（`rules` 已含 `modules('detection')` 全量源码哈希、
  快速筛选配置、各识别器定义/政策/regex flags；`dictionary` 含域、版本与全部词条；
  `ner` 含模型文件哈希、窗口/步长/超时、worker 模式与批处理参数）。
  `detection_fingerprint = sha256(payloads['rules'] + payloads['dictionary'] + payloads['ner'])`。
- 不把 `quick_screen` 结果放入键：检测结果与是否经过筛选无关；筛选仍在 pipeline 中照常执行。
- 使用 **HMAC** 而非裸 `sha256`：即使缓存内存被转储或误入诊断，也不能作为「已知明文猜测验证器」。
  密钥为进程内临时随机值，重启即失效。
- 域隔离：`dictionary` 指纹已含 `domain`；键空间天然按装配/域分离。

**命中条件**：文本逐字节相同且检测装配指纹相同。客户端若改写/压缩历史 → 自然 miss，不误用。

## 4. 集成点（最小改动）

把缓存放在编排器内部，而不是 pipeline，以保证所有前置校验与调用语义不变：

```python
def detect_many(self, texts, *, deadline_at=None, cancel=None, metrics=None):
    # 1. 既有前置校验原样保留：recognizers/dictionary/ner 缺失 → DETECTION_INCOMPLETE；
    #    timeout<=0 / cancel → INFERENCE_TIMEOUT。
    # 2. 逐文本查缓存；命中直接复用 DetectionOutcome，未命中收集为 miss 列表。
    # 3. 只对 miss 文本执行原 _detect_uncached（现 detect_many 主体，含 NER 合批）。
    # 4. 成功结果回填缓存；按原始顺序合并返回。
```

- `NerWorkerPool` 合批只作用于 miss 集合；每条结果与是否命中无关（确定性），输出顺序严格保持。
- `metrics` 增加 `cache_hits/cache_misses`，其余计时口径不变。
- pipeline 在装配完成时调用一次 `self.detector.configure_cache(cache, detection_fingerprint)`；
  该指纹随流水线一次性快照绑定（与 `version_handle` 同源），发布切换后旧条目不再命中并被 LRU/TTL 淘汰。

## 5. 语义与安全不变量

| 不变量 | 处理 |
|---|---|
| 只缓存成功完整结果 | 异常、超时、`DETECTION_FAILED/INCOMPLETE`、`INFERENCE_TIMEOUT`、`SECRET_DETECTED` 一律不入缓存，下次仍真实执行 |
| 检测资源未装配仍拒绝 | 前置校验在查缓存之前执行，与现状一致 |
| 秘密 P0 阻断不被绕过 | `SECRET_DETECTED` 在 `resolve_spans` 内抛出，无从产生可缓存结果；装配变更→指纹变更→miss |
| 命中不接触 NER worker | 全命中请求不调用 worker；**开放决策**：是否要求 worker 存活（见 §9） |
| 偏移有效性 | 键含文本摘要，仅同文本命中，偏移必然对应同一文本 |
| 无正文留存 | 条目仅含 `ResolvedSpan`（偏移/类型/优先级/来源）与溯源元数据；键为带密钥摘要 |
| 线程安全 | `process_request` 经 `asyncio.to_thread` 并发执行，缓存需加锁（见 §6） |
| 留证/知识一致 | pipeline 只消费 `outcome.spans`，命中返回同跨度 → `_collect_observations`/`replace_request` 结果不变 |

## 6. 缓存实现

新增 `apps/backend/src/detection/detection_cache.py`：

- 结构：`OrderedDict[key, DetectionOutcome]` + `threading.Lock`（命中时 `move_to_end`）。
- 边界（可由运维配置，均有默认值并校验为正整数）：
  - `GATEWAY_DETECTION_CACHE_ENTRIES`（默认如 4096）；
  - `GATEWAY_DETECTION_CACHE_TTL_SECONDS`（默认如 900）；
  - `GATEWAY_DETECTION_CACHE_MAX_SPANS`（默认如 65536，按累计跨度数近似内存上限）。
- 淘汰：超条目/超跨度/超时 LRU 淘汰；`clear()` 支持装配切换时主动清空。
- 关闭开关：`GATEWAY_DETECTION_CACHE`（`off`/`on`，默认先 `off`，灰度验证后再改默认）。
- 不记录正文；日志只允许 `DETECTION_CACHE stats hits=.. misses=.. evicted=.. entries=..`。

## 7. 失效与版本绑定

- 词典/模型发布 → 构建新装配 → 新 `detection_fingerprint` → 旧条目永不再命中，随 TTL/LRU 退出；
  可在装配替换时显式 `clear()` 以即时释放内存。
- 进行中请求持有自己的流水线快照，与 `version_handle` 语义一致，不受发布影响。
- 进程重启缓存自然清空，无恢复语义，符合「不持久、不共享」。

## 8. 观测与度量（先量后开）

- 指标：`cache_hits/misses`、命中率、条目数、淘汰数、近似省下的 NER 片段数/字符数。
- 基准：合成 N 轮（如 20 轮）递增历史，记录每轮检测耗时与总耗时，对比缓存开关；预期累计从
  O(n²) 降为 O(n)（每轮只对新消息做 NER）。真实样本与报告存仓库外。
- 安全回归：确认缓存键/条目中不含任何正文片段（内省测试）。

## 9. 开放决策（评审时定）

1. **全命中请求是否要求 NER worker 存活**：建议「三路已配置」为必需（现状），但不要求 worker 存活
   （缓存返回的是同装配下的既验证结果）。若坚持「资源不可用即拒绝」，可加一次极廉价的执行器存活探测，
   但会抵消部分收益。
2. **是否同时缓存快速筛选结论**：筛选本身廉价，建议不缓存（保持 pipeline 结构最小改动）。
3. **缓存归属**：放在编排器实例上（每装配一份）；共享编排器的部署下，键含指纹仍安全。
4. **条目上限与 TTL 取值**：需用真实会话长度分布标定。

## 10. 测试计划

| 类型 | 用例 |
|---|---|
| 确定性 | 同文本缓存冷/热两次，`spans` 与溯源逐项相等 |
| 命中合并 | 多文本混合命中/未命中，输出顺序与内容与全冷一致 |
| 失效 | 更换词典版本/识别器/模型指纹后必 miss 且结果为新配置 |
| 失败不入缓存 | 注入规则/词典/NER 故障与超时，断言下次仍真实执行（不返回旧结果） |
| 秘密阻断 | 含 P0 秘密文本始终抛 `SECRET_DETECTED`，不产生缓存 |
| 无明文 | 内省缓存条目与键，断言不含正文子串 |
| 边界/线程 | 并发命中、条目/TTL/跨度淘汰 |
| 多轮集成 | N 轮递增历史：历史片段首轮 miss 后续 hit，NER 调用片段数只随新增消息增长 |
| 回归 | 现有 `tests/detection`、`tests/gateway`、`tests/integration` 全绿 |

## 11. 变更清单（预估）

| 文件 | 类型 |
|---|---|
| `apps/backend/src/detection/detection_cache.py` | 新增：有界、线程安全、带密钥键缓存 |
| `apps/backend/src/detection/detection_orchestrator.py` | 改：`configure_cache` + `detect_many` 分区命中/未命中 + 度量 |
| `apps/backend/src/gateway/pipeline.py` | 改：由装配快照派生 `detection_fingerprint` 并绑定缓存 |
| `apps/backend/src/gateway/runtime.py`、`start_gateway.py` | 改：读取运维开关/边界并装配 |
| `apps/backend/src/infra/config.py`（或入口校验） | 改：缓存相关配置校验 |
| `apps/backend/tests/detection/test_detection_cache.py` | 新增：单元与对抗用例 |
| `apps/backend/tests/integration/`（多轮） | 改/新增：缓存命中与耗时行为 |
| `docs/adr/0012-*.md` | 新增：检测结果缓存决策（编号待定） |

## 12. 验收标准

1. 缓存 `off` 与 `on` 在全部既有测试下结果逐字节一致（除性能与新增指标）。
2. 合成 20 轮会话：`on` 时每轮 NER 片段数只与新增消息相关，累计耗时显著低于 `off`（给出实测比值）。
3. 缓存条目、键、日志中不出现任何业务正文；失败/P0/超时结果不入缓存。
4. 检测资源缺失仍 `DETECTION_INCOMPLETE`；装配指纹变化必定 miss。
5. 缓存默认关闭；灰度指标与基准达标后再默认开启。

## 13. 分期落地

1. **M1 度量**：先加 `cache_hits/misses` 与耗时埋点，跑合成长会话基准，确认收益幅度与内存占用。
2. **M2 实现**：`detection_cache` + 编排器分区 + 装配指纹绑定 + 单测。
3. **M3 灰度**：默认 `off` 上线，观察命中率/延迟/内存；达标后默认 `on`。
4. **M4（可选）**：与「会话级稳定别名账本」合并评估——缓存保证同文本同跨度，账本保证跨轮同 token。
