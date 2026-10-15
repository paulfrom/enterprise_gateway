# 进程内检测结果缓存

## 决策

多轮对话每轮回传完整历史，现有保护路径会对全部历史消息重跑规则、词典与 NER，整段会话累计约 O(n²)。历史片段在轮与轮之间通常逐字不变，规则/词典/ONNX 推理对同一文本与同一装配是确定性的，且 `DetectionOutcome` 只含偏移/类型/优先级/来源与词典/NER 溯源，因此可按「单个 `BusinessTextFragment` 的完整 `DetectionOutcome`」复用检测结果。

缓存放在检测编排器内部而非流水线，保证准入、筛选、替换与审计语义完全不改：编排器先做既有 fail-closed 前置校验（三路未装配仍 `DETECTION_INCOMPLETE`，超时/取消仍 `INFERENCE_TIMEOUT`），逐文本查缓存，命中直接复用，只对未命中集合执行规则→词典→NER 合批，成功后整体回填，最后按原始顺序合并。输出顺序与内容与全冷执行逐项一致。

缓存只驻留网关进程内存。`start_gateway.py` 使用单进程 `uvicorn.run`，进程内缓存即可覆盖全部在途请求；不引入 Redis/PostgreSQL 等共享或持久缓存，与 ADR-0001「共享映射扩大暴露面」的取向一致。进程重启缓存自然清空，无恢复语义。

## 键、边界与安全

键为 `HMAC-SHA256(k_cache, 域 || detection_fingerprint || 0x00 || text_utf8)`。`k_cache` 是装配时用 `secrets.token_bytes(32)` 生成的进程内临时随机密钥：不落盘、不经运维配置、重启即失效；使用 HMAC 而非裸摘要，避免缓存键成为「已知明文猜测验证器」。`detection_fingerprint = sha256(payloads['rules'] + payloads['dictionary'] + payloads['ner'])`，其中规则块含全部检测源码哈希、快速筛选配置与各识别器定义/政策/regex flags，词典块含域、版本与全部词条，NER 块含模型文件哈希、窗口/步长/超时、worker 模式与批处理参数。

缓存条目只含 `DetectionOutcome` 与插入时刻，不含任何业务文本；日志、指标与诊断不得输出正文。键摘要满足：文本逐字节相同且检测装配指纹相同才命中；客户端改写/压缩历史自然 miss。

上限为条目数（默认 4096）、累计跨度数（默认 65536）与 TTL（默认 900 秒），超限按 LRU 淘汰，支持装配切换时主动 `clear()`。单条跨度即超过跨度上限的结果不缓存，避免单条顶掉全部。全部访问在锁内完成，因为 `process_request` 经线程并发执行。

只缓存成功完整结果：异常、超时、`DETECTION_FAILED`/`DETECTION_INCOMPLETE`/`INFERENCE_TIMEOUT`、`SECRET_DETECTED` 以及 passthrough 失败一律不入缓存。P0 秘密在合并阶段抛出，无从产生可缓存结果；装配变更导致指纹变更即 miss。全命中请求不调用 NER worker；本决策不要求 worker 存活，因为返回的是同装配下已完整校验的结果。

## 失效、观测与灰度

词典/模型发布构造新装配、产生新指纹，旧条目永不再命中并随 TTL/LRU 退出；进行中请求持有自己的流水线快照，与 `RequestVersionHandle` 语义一致，不受发布影响。共享同一编排器的部署下，键含指纹仍安全。

指标包含 `cache_hits`/`cache_misses`、条目数、跨度数、淘汰数与近似的可省片段/字符/跨度，以及既有分阶段耗时；日志只允许 `DETECTION_CACHE_STATS hits=.. misses=.. evicted=.. entries=..` 这类不含正文的静态格式。

默认 `GATEWAY_DETECTION_CACHE=off`，配 `GATEWAY_DETECTION_CACHE_ENTRIES`/`GATEWAY_DETECTION_CACHE_MAX_SPANS`/`GATEWAY_DETECTION_CACHE_TTL_SECONDS`，非法值在入口受控拒绝。先以 M1 影子度量（只统计 `(文本, 指纹)` 重复度、不返回缓存结果）在合成长会话上量出命中率与可省工作量与内存条目，确认收益后再以本决策的 M2 真实缓存灰度，达标后再改默认值。

## 验收

缓存 `off` 与 `on` 在全部既有测试下结果逐字节一致；合成 20 轮递增历史在 `on` 时每轮 NER 片段数只与新增消息相关（实测 20 次调用，对照全冷 210 次片段）；缓存键、条目、日志不含任何业务正文；失败/秘密/超时结果不入缓存；检测资源缺失仍 `DETECTION_INCOMPLETE`；装配指纹变化必定 miss。跨轮 token 编号/角色前缀稳定性不在本决策范围，属「会话级别名账本」议题。
