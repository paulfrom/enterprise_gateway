# 数据库设计审查与下一版存储契约

本文区分已实现结构与下一版设计。统一 namespace 已实现；正文去重、下述新约束和图后端导出协议是待实施设计，不能视为当前能力。

## 当前结构与判断

知识模块有16张表（含v3的实体别名表），请求历史有2张表，脱敏词典有4张表；共22张表部署到公共基础设施提供的已有数据库与schema。知识采用 source/version、entity、claim、evidence、candidate、publication 和关联表；治理、Outbox、消费回执和消费者资产单独建表。历史以 request 和 request/stage 拆分，正文使用带绑定信息的信封密文。

这具备关系型建模基础，但不能宣布整个模型符合严格第三范式或 BCNF。“表分得多”和“使用 UUID”都不能证明范式；必须逐表列出候选键、函数依赖和更新语义。建议保留这些逻辑实体，在同一 schema 内组织。

| 发现 | 当前依据 | 下一版要求 |
| --- | --- | --- |
| 核心关系已经拆分 | entity/claim/evidence/candidate 及 candidate_evidence_links，含复合租户/域外键 | 保留关系事实与证据多对多关系；避免改成一个无约束 JSON 大表 |
| 部分跨表关系未由数据库完整约束 | candidate.derived_from 没有 FK；governance source/version 未 FK 到 source；publication.admin_action_id 未 FK 到 action；若干 UUID 外键没有携带 tenant/domain | 对每条关系增加作用域内复合唯一键和 FK；迁移前查孤儿及跨域引用；测试直接 SQL 不能绕过应用检查 |
| 同一 publication 同时保存 candidate_id 和 claim_id | claim 可以由 candidate 推导，存在重复事实；candidate_version 没有独立的不可变版本行 | 引入 candidate_versions，publication 只引用精确候选版本，或使用复合 FK 约束二者一致。发布快照需要明确不可变语义 |
| ACL、purpose 多处复制 | 多张表独立保存安全标签，来源、事实、候选和发布存在不同有效权限 | 将其定义为明确的权限快照或有效权限，记录派生规则；不能为“规范化”直接删除，导致撤回或授权语义变化 |
| 集合与结构数据 | ACL TEXT[]、candidate_ids UUID[]、consumer_audiences TEXT[]、lineage/payload JSONB | ACL 作为整体集合有工程合理性；需要 FK、独立查询或逐成员生命周期的集合应建关联表，特别是 observation_candidates；JSONB 保存版本化外部信封，不承担核心 FK |
| 值域与版本约束不完整 | 部分 state/type/event 等 TEXT 未 CHECK；部分版本和治理有效期未做正值/顺序检查 | 给有限枚举、版本正值和有效期加 CHECK，先验证既有数据；不能依赖 Python 枚举挡住直接 SQL |
| 删除和索引设计需要补齐 | 历史 FK 级联删除，知识多个关系没有完整归档/删除顺序；不是所有 FK 都有适合查询的索引 | 定义 source 保留期、证据清理、发布撤回、消费回执归档的顺序；依据 EXPLAIN/真实负载确定 FK 和域/时间索引 |

主键、复合租户/域 FK 和 CHECK 的语义按 [PostgreSQL 约束文档](https://www.postgresql.org/docs/17/ddl-constraints.html)执行；RLS 不替代引用完整性。下一版先建立完整的关系不变量，再讨论为性能进行受控冗余。

## 大模型交互中的重复文本

`request_stage_contents` 按 `(request_id, stage)` 保存 input、redacted、upstream、restored 四种正文。`PostgresHistoryStore._encrypt` 用请求/阶段/状态/媒体类型绑定 AAD，每次随机 DEK/nonce。即使正文相同，密文也不同；当前没有内容去重。四阶段部分正文可能相同，连续对话又会把旧消息带入后续请求，因此重复存储是实际设计缺口。

如果每轮加入等长消息，且每轮重发全部历史，原始请求中历史文本的累计存储可按 `1+2+...+n` 增长，即 O(n²)。这是按该交互模式推导的增长趋势，不是实测压缩率，也不意味着所有协议与四阶段总存储都严格等于该公式。PostgreSQL 对 BYTEA 的压缩不能可靠消除随机密文中的重复明文。

知识模块已有 source/version、entity、claim、evidence 的唯一约束以及 observation 事件去重，但事件重放幂等与文本内容去重不同。`encrypted_observation` 仍保存序列化证据片段；来源身份、范围、版本或事件变化时，相同文本可以重复保存。相同文本也不能被算作多份独立证据。

### 建议模型

继续在同一 schema 中增加以下关系，取代“每个阶段一份完整密文”的唯一存储方式：

| 表 | 内容及关键约束 |
| --- | --- |
| content_blobs | blob_id、tenant/domain、权限范围标识、purpose、bucket、密钥/格式版本、作用域 HMAC、明文长度、encrypted_payload；scope/key_version/HMAC 唯一 |
| request_stage_manifests | request_id/stage、state/media_type、格式版本、加密且认证的有序片段清单；请求/阶段唯一，并与 request 作用域一致 |
| request_stage_blob_refs | request/stage/ordinal/blob_id、作用域；复合 FK 保证请求与 blob 属于同一范围，支持保留期清理和完整性核对 |
| message_occurrences | 可选语义索引：request/stage、消息顺序、role、工具关联、content blob 引用；客户端 conversation ID 仅是非可信关联信息 |
| observation_blob_refs | observation 与证据片段的有序关系，携带范围；避免 UUID 数组承担引用关系 |

去重在加密前完成；blob 继续使用随机加密，禁止使用确定性加密或把裸明文 SHA256 作为可枚举数据库查询键。使用独立派生的作用域 HMAC 密钥；作用域至少覆盖 tenant、domain、purpose、ACL/授权范围、bucket 和密钥版本，禁止跨租户或跨授权范围合并。HMAC 相同后由可信写入路径核对长度及解密后的精确字节，才复用 blob；不合并语义相近文本。作用域内相等性元数据是额外泄露面，需要纳入访问契约。

blob 的 AAD 绑定自身不可变身份、范围和格式；阶段 manifest 的 AAD 绑定 request、stage、状态、媒体类型和格式，并认证顺序、长度和 blob 引用，防止把另一个请求的片段替换进来。不能把现有“绑定 request/stage 的密文”直接挪到共享 blob 表。

第一阶段可以对精确相同的完整阶段正文去重，但这不能解决不同完整请求中反复出现的旧消息。第二阶段需要对原始字节进行分片或记录带原始间隔的消息片段，以清单逐字节重建正文。不能简单 JSON 解析再序列化，否则键顺序、空白、Unicode 转义、工具块与 SSE 字节都会改变。semantic message 索引用于查询，不替代审计要求的原始字节恢复。

请求阶段、manifest 和引用应在一个事务内写入；缺任何 blob、认证失败、越界或格式未知均拒绝读取。purge 删除到期引用，在锁保护下仅回收没有任何有效引用的 blob；不要仅依赖容易漂移的整数 ref_count。共享 blob 的到期不能简单采用最早引用的期限；采用仍有效引用的最长保留期限，并遵守该范围的硬性删除要求。撤回、密钥轮换和密码擦除必须覆盖历史与知识的不同用途，不能因共享内容延长授权。

验证必须包含：跨租户及不同 ACL 不去重、多轮重复消息仅新增新片段、JSON/SSE 逐字节恢复、并发重复写入、purge 与新增引用竞态、引用篡改失败、部分响应、密钥轮换以及旧格式读取。节省率用合成多轮语料统计明文字节、密文字节、唯一 blob 数与存储开销；不承诺固定比例。

## 知识图谱后续迁移

当前 entity、claim 和 evidence 提供了节点、边与证据的关系结构；worker 使用稳定 UUID5 派生部分身份；发布有版本、谱系、Outbox、回执及撤回机制。这些是迁移基础，但当前没有图数据库适配器、可恢复导出协议或一致性校验工具，不能宣称已经支持无损迁移。

优先将 PostgreSQL 保留为治理与事务事实源，把图后端作为可以重建的查询投影。先明确迁移目的：只增加图查询能力，还是替换权威持久层。后者必须重新实现原子治理、幂等、撤回和安全访问，不能把 RLS 假设带入图后端。

建议的导出契约：

- 节点和边保留既有 UUID，标注 tenant/domain 与导出格式版本；不能用实体显示名称作为跨后端主键。实体别名、重命名、合并与拆分需要显式 identity/alias 模型，当前按 name 派生的 UUID5 不能代替生命周期定义。
- claim 保留 predicate、polarity、modality；证据保留 source/version、摘要、精确字符位置及与候选/发布的关联，不能只导出三元组而丢失证据。
- publication 保留精确 candidate_version、治理版本、有效期、用途和消费受众；withdrawn、tombstone、过期状态必须随迁移传播。
- 首次导出采用一致性快照并记录增量水位。现有 Outbox 的随机 UUID 和可重复时间戳不足以单独充当提交顺序水位；下一版必须提供提交一致的变更序列或经过验证的 CDC 位点，所有需要投影的变化都要有版本化事件。
- 增量消费以 event_id 幂等，以对象版本拒绝旧事件覆盖新状态；处理并发快照/增量、重复、乱序、宕机重放及删除。目标提交成功后才推进消费回执，提供全量重建路径。
- 对目标后端重新实现查询前的 tenant/domain、用途、受众、有效期及撤回授权。图查询结果不能绕过 PostgreSQL 中的实时授权核对。
- 迁移验收核对每个范围的节点/边/证据数、版本与谱系摘要、孤儿关系、撤回和过期结果、访问拒绝结果；完成演练后才切换读流量。

PostgreSQL 逻辑复制不会自动复制 DDL 和 sequence 状态，异构图投影更需要独立的格式和版本管理，参考[逻辑复制限制](https://www.postgresql.org/docs/17/logical-replication-restrictions.html)。数据库跨实例恢复还必须保留角色、策略、函数/trigger 固定 search_path 和外部密钥；单纯导出行或图边不能保证原有安全语义。

## 实施顺序

1. 复用公共PostgreSQL中的同一已有数据库和schema；提供完整手工表DDL，服务和测试仅检查现有对象，不创建数据库/schema/角色或修改基础设施权限。
2. 建立版本化迁移机制与完整性审计，补作用域 FK、候选不可变版本、值域及生命周期约束；禁止靠重建 schema 替代业务升级。
3. 增加作用域内容 blob 与 manifest，兼容读取旧信封，以小批次回填、逐字节校验和可回滚写入切换完成去重。
4. 定义图导出 v1、增量水位和适配器，用治理/撤回/重放测试验证查询投影。

正文去重和图迁移必须各自更新结构版本、契约、指纹与迁移测试。它们改变存储和安全语义，应分别实现，不能在 namespace 合并时顺便改变历史正文和知识事实。
