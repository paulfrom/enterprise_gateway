# 公共 PostgreSQL 使用约定

PostgreSQL 是已有公共基础设施。开发阶段的 HTTP 服务、知识 worker、知识管理、请求历史及测试复用同一已有数据库和 schema；库名与 schema 由部署环境指定，允许使用 `public`。不安装新 PostgreSQL，不自动创建数据库、schema、扩展或账号，不自动修改授权。

## 手工表部署

`deploy/sql/gateway_tables.sql` 是完整的 v4 建表文件，包含知识的16张表、请求历史的2张表和脱敏词典的4张表，以及约束、索引、触发器、受限函数与 RLS 策略。默认目标是已有 `public`，知识管理登录为已有 `gw_knowledge_admin`。SQL不创建数据库、schema、角色或扩展，不授予数据库/schema权限，不删除现有表或数据。

使用其他现有名称时，先离线导出完整SQL：

```bash
cd apps/backend
.venv/bin/python scripts/export_gateway_sql.py \
  --schema <existing-schema> --admin-role <existing-knowledge-admin-role> \
  > /tmp/gateway-tables.sql
```

该命令只生成文本，不连接 PostgreSQL。由部署方通过已授权的表部署连接在已有数据库执行文件，例如 `psql -X -v ON_ERROR_STOP=1 -d '<existing-connection>' -f /tmp/gateway-tables.sql`。应用、测试、CI均不执行建表文件。完整SQL可以在当前同版本表集合上重复执行，补齐缺失对象而不删除既有表或策略；不兼容的既有结构仍需经过审核的增量表SQL，不能靠删schema升级。

已有v2关系表升级到v3时使用 `deploy/sql/entity_aliases_v3.sql`，只增加实体别名表、索引约束及其RLS策略，其他表和行不变。离线导出命令支持 `--aliases-only` 指定增量SQL。此文件使用相同的默认schema和管理登录。

账号与授权由基础设施管理方预先维护。知识worker、历史和知识管理使用现有独立受限登录，均指向同一数据库/schema；不接受超级用户、CREATEDB、CREATEROLE、BYPASSRLS、复制能力或可达的特权角色，也不能具有数据库CREATE权限（该权限允许新建schema）。知识登录仅访问知识表，历史登录仅访问历史表；schema USAGE、具体表DML及受限函数EXECUTE由基础设施提供，项目不自动授予。禁止把基础设施管理员连接放进服务或测试配置。

建表SQL保留两项SECURITY DEFINER函数的PUBLIC执行权限撤销，这是新建项目函数的访问定义，不改变数据库、schema或角色权限。其受控属主需要满足既有forced-RLS函数契约，由基础设施安排，应用登录不能获得该属主身份。

## 现有连接配置和检查

私有JSON字段参考 `deploy/database.example.json`，包括 `schema`、`application_role` / `app_dsn`、`history_role` / `history_dsn`、`admin_role` / `admin_app_dsn`。示例中的库名、角色和密码必须替换为基础设施实际提供的值。配置保存在仓库外或Git忽略且权限为0600的文件中，不提供DDL管理员连接字段。

```bash
cd apps/backend
.venv/bin/python scripts/check_gateway_database.py --config /private/service-connections.json
```

检查使用只读事务，验证三种登录指向同一数据库/schema，以及已有表、forced RLS、结构指纹和用途授权。缺配置、缺表或权限不匹配时报告失败；不补建、不修复、不清空。结构指纹只覆盖项目表及项目函数，已有schema中的无关基础设施对象不影响启动。

## 测试与历史复测

`GATEWAY_TEST_PG_CONFIG` 和 `GATEWAY_HISTORY_PG_CONFIG` 使用上述同一配置。测试先只读核验既有对象，再以合成租户/业务域运行普通DML；不要求空schema，不改授权、属主或RLS，不进行建表故障注入，不在退出时删除表、schema或角色。测试数据使用独立合成作用域，不按整表清理业务数据。

在仓库根目录执行 `bash scripts/check_pg.sh` 可单独运行PG相关回归；默认读取 `apps/backend/.env.test`，也可以通过 `GATEWAY_TEST_PG_CONFIG` 指定私有文件。入口先只读核验，再运行存储、治理、历史、图投影和实际HTTP链路测试，不执行部署或授权SQL。

历史复测保留原始样本和预期结果；如果使用已留存的加密请求，还需提供对应密钥和配置版本。测试夹具中的临时文件及合成密钥仍按夹具生命周期处理，不应把它们当作长期回放档案。保留期清理由业务自身的作用域策略执行，不能用测试退出清理替代。

CI使用能访问公共基础设施的 `enterprise-gateway` 自托管Linux runner。`GATEWAY_PG_CONFIG_JSON` secret提供同一现有服务配置，CI只写临时连接文件并运行检查和测试；不启动PostgreSQL服务容器、不建库、建schema或创建角色。浏览器回归也复用现有表。

## 可选图投影

AGE扩展、已有图及Entity/Claim标签由公共基础设施预置，与关系事实源位于同一数据库。复用已存在的图时，在私有JSON中设置 `graph_name`；服务启动使用 `GATEWAY_KNOWLEDGE_GRAPH_NAME` 指定同一个现有图名。未配置时沿用按数据库/schema派生的默认名称，缺图时明确失败，不自动创建。应用和测试只验证已有图资源，不运行扩展安装、图schema创建、标签创建、图删除或授权。图重建必须提供tenant/domain，只更新这一范围内的投影行。未提供AGE资源时，关系表DDL与普通服务无需创建替代图资源；图功能检查明确失败。

## 脱敏词典 v4 增量

已有 v3 表集合执行 `deploy/sql/redaction_dictionary_v4.sql`，或通过导出器的 `--dictionary-only` 生成相同增量。新增草稿状态、词条、不可变发布版本和变更元数据四表，以及 forced RLS 和版本不可修改触发器；不重建其他表。由基础设施给现有管理登录提供这四张表的 SELECT/INSERT/UPDATE/DELETE 权限，应用角色不能成为表或函数属主。

网关启动首次从受控 JSON 导入当前作用域的词典，之后以数据库发布版本为准；管理端编辑和发布只执行普通 DML。数据库检查核验管理登录的词典权限、RLS 及不可变触发器。测试使用独立合成作用域，不部署或清空表。字段和在线生效边界见[词典契约](contracts/redaction-dictionary.md)。
