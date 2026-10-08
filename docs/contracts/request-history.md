# 请求历史与四阶段查询契约

当前网关展示全部请求历史，不按用户或供应商 Key 分组。查询使用服务端配置的独立访问 Key；该凭据仅授予本装配租户/保护域内请求历史的读取，不代表企业身份或知识权限。供应商 Key 仍只用于当次模型调用，不持久保存。

## 记录与读取

固定阶段为 `input`、`redacted`、`upstream`、`restored`，分别表示入站正文、实际外发正文、实际收到的供应商响应、网关生成并准备发出的还原正文。正文带 media_type（application/json 或 text/event-stream）、阶段状态 complete/partial；不存在的阶段展示为 not_produced。整体状态 processing/completed/blocked/failed/partial，不声称客户端已经收全。

`restored`也保留网关实际生成的拒绝或错误响应，其整体状态和错误码明确表明该正文不是成功的模型回复。`blocked`表示保护链拒绝，不能据此断言从未调用上游；是否已经外发由redacted/upstream阶段及具体错误反映。`failed`表示上游或内部故障。截断UTF-8在网页中使用替代字符呈现，密文内仍保存准确字节。已提交completed后若绝对截止时间届满，HTTP可无正文504/流可结束；仍只证明正文完整准备和留存，没有交付确认，不再生成未留证错误正文。

请求使用服务端 UUID，不用明文正文哈希或供应商 Key 作为查询标识。元数据只有 ID、租户/域、协议、模型、创建/到期时间、状态和白名单错误码；正文不进入标题、普通日志或搜索索引。

采集从唯一合法BYOK凭据、完整可解析正文、已准入模型/端点校验通过后开始；此后政策拒绝也有记录。认证失败、畸形/超限正文和未知模型在此之前拒绝，不持久采集为请求历史。因此“全部”指本服务固定域内所有已采集记录，不保证记录每次HTTP访问。

四阶段记录是独立受控资产，不属于知识观察/候选，不开放原审计工单、知识审批或发布接口。不保存 MappingContext；但完整对照正文可能推断出原值关系，全部正文按原文等价敏感数据加密和授权读取。

## 组件接口（共同实现依据）

模块为 `request_history`。`HistoryUnavailable` 与 `HistoryNotFound` 使用固定错误信息，不能附带正文、Key、DSN或上游错误原文。

`PostgresHistoryStore(connection_uri, kms, *, tenant_id, domain, retention_days, bucket, audit_directory, max_stage_bytes=16777216)` 要求显式正整数留存天数、已初始化的 request-history 用途 KEK、专用 schema 和普通受限应用连接。

- `check_ready()`：实际校验受限角色、独立历史表的 forced RLS/不可达 owner、作用域与 KMS。失败拒绝，不能创建缺失结构或补建旧 Key。
- `begin(*, protocol, model, raw_body: bytes) -> HistoryRecorder`：生成 request_id，事务保存 processing 元数据及 input 加密正文。
- `list_requests(*, limit=50, cursor=None, query='', status=None) -> dict`：返回 `{items: [...], next_cursor: str|null}`，只搜索模型/协议/请求ID等元数据；排除过期记录。
- `get_request(request_id) -> dict`：返回单请求元数据和四阶段 `{stage, state, media_type, body}`（body为UTF-8文本，未产生时null）。核对密文绑定，授权读取留痕可靠完成后再次校验期限再释放正文。
- `audit_access(*, operation, request_id=None, outcome)`：仅持久保存静态操作/结果、随机审计ID、请求ID、时间、固定作用域；不写查询文本和 Key。
- `purge_expired() -> int`：限定本装配域，事务删除过期历史及正文；不触碰知识表。提交前审计仅记attempted，返回值证明提交成功；失败不据attempted推断删除已发生。在线物理删除不等于全部备份密码学销毁。

`HistoryRecorder` 有 `.request_id`、`.write(stage, body: bytes, *, media_type='application/json', state='complete', append=False)`、`.write_many(updates)`、`.finish(status, error_code=None)`。updates为字典列表，每项含stage/body及上述选项。Recorder累计大小有界，append累计真实字节；write_many原子保存各阶段快照。写失败不得静默继续。finish不得把未产生阶段补造成空的成功文本；重复终态不能改写已完成记录。

在线调用在外发前同步保存 input/redacted，非流式在还原前保存 upstream，返回前保存 restored并完成状态。流式记录实际接收字节与实际生成的SSE输出；必须在输出帧释放前可靠保存对应快照，断连/错误保存部分内容并保留真实终态。进程崩溃遗留processing记录只证明结果未知。供应商认证头绝不进入历史正文或元数据。

## HTTP及网页

`GET /history` 返回独立静态网页；资产在同源 `/history/assets/`。`GET /api/requests` 接受 limit/cursor/q/status；`GET /api/requests/{request_id}` 读取详情。两类查询只接受单个 `Authorization: Bearer <网关查询Key>`，拒绝缺失、重复或错误Key，不把供应商Key自动升级为查询授权。不做账号系统、浏览器持久凭据、URL凭据或无认证全文接口。

API正文和页面使用 no-store，设置同源CSP、nosniff、frame-ancestors none等响应边界。错误固定净化；数据库/KMS/访问审计失败拒绝释放正文。网页只使用textContent及文本节点呈现模型输出，不解释模型HTML；支持真实空列表、错误、过期、部分/未知阶段。默认遮挡输入与还原文本，明确遮挡不是访问控制。模型调用返回服务端 `x-request-id`，便于定位该次记录。

## 部署与验证边界

历史采用独立 PostgreSQL schema，新namespace事务初始化，拒绝旧布局与权限绕过；沿用现有psycopg/受限角色校验/信封加密，不修改知识worker的13表契约。留存期与访问Key必须明确配置；没有业务期限不启用真实正文采集。合成测试可使用明确的测试期限，不代表生产留存政策。启动CLI可显式选择历史装配，历史装配缺少任何必需设置/资源即拒绝，不进行数据库迁移、旧实现fallback或原文绕行。
