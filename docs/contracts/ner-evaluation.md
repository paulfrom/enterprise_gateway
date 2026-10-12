# NER 业务评测与分阶段性能基线

## 样本格式

默认合成样本为 `apps/backend/tests/detection/fixtures/ner/business-samples.json`。真实样本使用同一格式，存放在仓库外，并将 `synthetic_only` 设为 `false`。根字段为：

- `schema_version`：整数 1。
- `synthetic_only`：布尔值。
- `span_convention`：固定 `unicode-codepoint-half-open`。
- `dictionary_entries`：`{text, entity_type}` 条目数组；在评测中编译为独立词典。
- `samples`：请求数组，每个请求含唯一 `id`、`scenario`、`tags`、非空 `fragments` 与布尔 `expect_secret_block`。

每个片段为 `{text, entities}`，实体为 `{type, start, end}`；跨度不得截断实体或遗漏片段内其他需要保护的实体。场景使用固定分类 `customer_service`、`contract`、`finance`、`human_resources`、`rule_format`、`secret`、`low_risk`。NER 金标类型为 PER/ORG/LOC；规则类型为 PHONE_NUMBER、CN_ID_NUMBER、CN_USCC、MONEY_AMOUNT、ACCOUNT_NUMBER、CONTRACT_NUMBER、SECRET。重复实体每次出现都独立标注。

## 执行

以下命令在 `apps/backend` 执行；输出目录由操作员选择，必须位于仓库外。

```bash
PYTHONPATH=src .venv/bin/python scripts/ner/benchmark_business.py \
  --output /tmp/enterprise-gateway-ner-baseline.json \
  --modes both --screening both --concurrency 1 \
  --workers 1 --pending 4 --repeats 3 --ort-threads 4
```

`oneshot` 每次任务重新创建进程和模型运行环境，`persistent` 复用进程与会话。两种模式必须采用相同的 ORT 线程数；上述命令使用四个线程，工具默认一个线程，`--ort-threads auto` 使用 ONNX 默认线程配置。ORT 线程数、执行槽和 HTTP 应用进程数应联合调优。

通过 `--concurrency 1,2,4` 比较负载，`--workers` 与 `--pending` 独立控制推理资源。超过容量的任务会真实报告 `INFERENCE_QUEUE_FULL`，不能把拒绝请求的速率解释为成功吞吐量。`--recycle` 控制常驻工作进程任务上限。`--window-length` 和 `--stride` 用于后续窗口几何实验，默认仍为 128 和 32；调整后必须重新检查实体覆盖。

通过 `--dataset /private/path/business-samples.json` 与 `--package /local/model-package` 指定本机资源。无需网络、Torch 或供应商访问。报告记录数据集与模型 manifest SHA-256、Python/ORT/tokenizer 版本、CPU 型号和可见核心数，方便在相同环境重跑。

## 指标与观测边界

NER 精确指标与完整检测精确指标分开报告，词典或规则覆盖不能掩盖 NER 漏检。保护覆盖统计正常请求的敏感实体完整覆盖率和 code point 覆盖率；秘密请求单独统计整请求阻断。检测失败的正常请求没有部分成功预测，记作未覆盖，并另外记录错误码。筛选开启和关闭分别运行；带金标片段被筛选跳过的数量显式报告。

阶段包括冷启动中的包校验、tokenizer/Session 创建，以及工作负载中的排队/启动、包校验、分词切窗、批次准备、ONNX 执行、解码、规则、词典与跨度合并。`request_latency_ms` 为离线检测总耗时，不包含 HTTP 准入、流水线组件全量指纹扫描、映射、审计加密、持久化、网络外发或响应恢复，不能宣称为网关端到端延迟。启动与初始化阶段、工作任务与内部阶段是包含关系，不能相加得到总耗时。

独立冷启动探针使用空文本，但执行完整模型初始化和制品门禁；后续常驻任务使用已加载会话，单次进程任务仍逐次冷启动。每组结束后关闭所有资源。成功检测和被正确分类的秘密阻断与错误请求分别统计；峰值 RSS 为进程内累计高水位，不是增量内存或整个池的总内存。

报告中的精确率、召回率、F1 与覆盖率在无对应分母时为 `null`。默认退出码 0 只表示运行未出现非预期失败、重复预测稳定、秘密阻断符合金标且两种执行方式预测相同；不是业务质量合格证明。可添加 `--min-coverage 0.99` 设置显式敏感实体覆盖验收阈值；阈值仅为命令示例，由实际业务需求决定。

每完成一组，工具在输出文件旁写入 `.partial.json` 聚合报告，并标记 `status: running`；全部完成后写入正式报告并移除该文件。中断运行先关闭推理资源，返回退出码 130，保留已完成组的聚合报告。

退出码 1 表示完成评测并写出报告，但功能/确定性/显式覆盖门禁不通过；退出码 2 表示样本或模型契约无法完成评测。报告不携带正文、原始预测和错误消息。

## 后续实验顺序

1. 固定样本、窗口和线程配置，建立单次进程与常驻会话基线。
2. 独立评估快速筛选误跳过与阈值，补充真实业务样本。
3. 联合调整执行槽、ORT 线程数和并发，检查排队与尾延迟。
4. 再试请求内跨片段窗口合批、窗口步长和量化；每次实验重新跑质量与性能对照。

运行结果和执行过程记录放在仓库外，不作为 README 的阶段性事项或提交进仓库。
