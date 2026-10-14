# ADR 0008：公共 PostgreSQL、统一表集合与手工表部署

状态：已接受。

## 决策

PostgreSQL作为公用基础设施存在。开发阶段所有服务及测试复用同一已有数据库和schema；环境决定库名和schema，允许 `public`，不要求专用测试库或 `gw_test_gateway`。知识、实体别名及请求历史的18张关系表共同部署，分别使用基础设施提供的现有知识worker、历史和知识管理登录，以表级授权和forced RLS隔离用途。

项目提供完整手工建表SQL及增量表SQL。项目代码、服务启动、测试和CI不自动创建数据库、schema、角色、扩展或图schema，不修改基础设施授权。移除自动初始化和迁移CLI、运行时建表方法，以及修改授权、表属主、关闭RLS、篡改结构或故意制造建表失败的测试。

## 实现约束

- `deploy/sql/gateway_tables.sql` 提供当前v3全部关系对象；`scripts/export_gateway_sql.py` 可离线替换已有schema/管理登录名，生成完整DDL，不连接PG、不执行SQL。
- `deploy/sql/entity_aliases_v3.sql` 提供已有v2表集合的增量表DDL，不重建其他表或删除既有行。部署方在已有授权范围内手工执行；账号、schema和数据库权限由基础设施管理。
- 服务、测试和CI只持有既有受限应用连接，不能创建数据库/角色，也不能具有允许新建schema的数据库CREATE权限。DDL函数的受控属主身份不交给应用。
- `gateway.database.verify_database` / `scripts/check_gateway_database.py` 使用只读事务检查三种用途登录指向同一既有数据库/schema，验证现有表、forced RLS、结构指纹及用途授权；缺资源即失败，不自动修复。
- 结构指纹仅覆盖项目表和项目函数；公共schema中的无关对象不构成项目结构漂移。项目表上的未知结构变化仍被拒绝。
- 测试使用合成租户和业务域进行普通数据操作；不要求全新schema，不自动删除既有数据，不在退出时删除表、schema或角色。保留数据的复测需要相应代码、样本、配置和密钥版本。
- AGE扩展、图和标签是基础设施预置资源；图检查只读。重建必须提供明确tenant/domain，仅更新对应投影行，禁止删除整个共享图。
- CI复用能访问公共PG的Linux runner和现有服务连接secret；不启动替代PostgreSQL服务或执行数据库/角色/表初始化。

## 影响

部署不需要新的PostgreSQL实例、测试数据库或测试schema；服务与复测使用同一已部署表集合。项目维护表级技术契约和完整SQL，基础设施维护数据库/schema/账号/授权。结构升级需要显式审核并手工执行增量表SQL，不能以重建schema代替升级。

本决策替代ADR 0005、ADR 0006、ADR 0007中将用途隔离等同于独立schema的部分；现有用途授权、独立密钥和forced RLS要求继续成立。具体使用方式见[公共PostgreSQL使用约定](../postgresql-infrastructure.md)。
