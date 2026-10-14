# 本地脱敏词典契约

## 数据与版本

管理页面为 `/admin/dictionary`。词条包含 UUID `entry_id`、精确 `text`、`entity_type`、`enabled` 和更新时间。文本非空、最多 512 code point，禁止占位符命名空间；类型匹配 `[A-Z][A-Z0-9_]{0,31}`。每个 tenant/domain 内文本唯一，最多 20000 个词条；全称和简称可分别登记，不做原值归一化。

`revision` 每次草稿写入递增，`published_revision` 指向已发布修订。所有写入必须包含 `expected_revision`，不匹配返回 409，不自动覆盖或重试。发布仅使用启用词条，至少一个；词典哈希绑定 dictionary_id、发布版本、处理域和完整条目。版本的检测标识为 `db-<revision>`。

保存、停用、删除不会改变已发布快照。删除只移除草稿词条，先前发布快照继续留存。发布编译和新装配失败时事务回滚，旧版本仍有效；成功后用于新的聊天和文件请求，在途请求使用原对象。重启读取数据库已有版本；种子文件只用于初次入库。

## API

所有接口使用既有管理员 Cookie 和服务端 scope；POST 同时要求同源 Origin 与 X-Admin-CSRF。

| 方法与路径 | 内容 |
| --- | --- |
| GET `/api/admin/dictionary` | 词条分页及草稿/发布状态 |
| GET `/api/admin/dictionary/versions` | 最近 50 个发布版本的数量、时间、发布人和摘要，不交付旧版原值列表 |
| POST `/api/admin/dictionary/entries` | 新增草稿词条 |
| POST `/api/admin/dictionary/entries/{entry_id}` | 修改精确文本、类型和启用状态 |
| POST `/api/admin/dictionary/entries/{entry_id}/delete` | 从草稿删除词条 |
| POST `/api/admin/dictionary/publish` | 发布期望修订 |

查询只接受唯一的 query（最多 512 字符）、entity_type、enabled（true/false）、offset（0～20000）、limit（1～100）。排序按原文 C collation 及 UUID；修改后应刷新分页。

新增与修改正文为 `{expected_revision, text, entity_type, enabled}`，enabled 默认 true。删除与发布只接受 `{expected_revision}`。JSON 正文最多 8192 字节、10 秒；未知字段、重复键、非标准常量、编码/类型错误均拒绝。鉴权和 CSRF 先于正文读取，正文读取后及结果交付前再次校验会话。返回使用 no-store；浏览器离开页面后不留存查询缓存，退出清除会话和管理数据。

错误不包含词条、连接详情、SQL或解析诊断：401/403 为认证、同源、CSRF 或 scope 拒绝，404 为词条不存在，409 为修订/文本冲突，422 为输入、数量超限或空发布，503 为数据库或发布装配不可用。

## 存储与运行

`redaction_dictionary_state` 保存活动指针和草稿修订；`redaction_dictionary_entries` 保存草稿条目；`redaction_dictionary_versions` 保存不可修改的发布条目；`redaction_dictionary_changes` 保存修订、动作、条目 ID 和管理员元数据，不复制词条正文。

四表采用复合作用域约束、forced RLS 和管理登录检查；版本表由固定 search_path 的 invoker 触发器拒绝更新和删除。启动检查表、DML 权限、策略及触发器，缺资源拒绝。运行时数据库失败不回退文件或跳过检测；聊天故障透传配置不能绕过词典版本读取。

通过 GATEWAY_DICTIONARY_PG_DSN 或对应 _FILE 提供受限连接；未设置时复用 GATEWAY_ADMIN_KNOWLEDGE_PG_DSN。GATEWAY_DICTIONARY_FILE 是可选初始种子。使用已有数据库/schema，执行 `deploy/sql/redaction_dictionary_v4.sql` 或导出 `--dictionary-only` 增量；管理登录的四表权限由基础设施提供。
