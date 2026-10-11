# ADR 0008：统一数据库命名空间与测试入口

状态：已接受。

## 决策

复用本机 PostgreSQL 5433 实例，新建专用 `enterprise_gateway` 数据库作为本地及 CI 数据库测试目标。常规测试只使用固定的 `gw_test_gateway` schema；知识与请求历史的 17 张表共同初始化，不再每个进程为两种用途分别创建随机 schema。

数据库测试是独立环境，不把业务表作为故障注入目标。它们会修改 RLS、表属主和结构，不能与正在服务的业务共享表。业务部署内部同样采用一个 schema（建议 `gateway`），分别使用知识 worker、历史和知识管理角色，以表级授权与 forced RLS 隔离用途。schema 数量不承担权限隔离职责。既有业务数据的数据库迁移是显式操作，不随测试配置切换自动执行。

## 实现约束

- `gateway.database.prepare_database` / `scripts/prepare_gateway_database.py` 在一个事务内创建知识和历史表、策略、受限函数与授权，拒绝已有 namespace；所有应用角色必须预先创建、分别登录、无属主可达路径。
- 知识角色及知识管理角色不获得历史表权限，历史角色不获得知识表和受限函数权限。授权列出具体表，禁止共享 namespace 中的全表授权。
- 知识 v2 指纹明确排除两张历史表及其元数据，保留其他未知对象的漂移检查。知识表契约本身不变，因此 v2 指纹值不变。历史每次取连接验证自身表、forced RLS、属主和跨用途权限；允许同 namespace 中已知知识表。
- 测试配置必须指向 `enterprise_gateway`，固定 namespace 必须为 `gw_test_gateway`。会话级 advisory lock 防止两个常规测试进程并发修改同一表集合；碰到已有 namespace 或锁冲突即失败，禁止自动清空可能含数据的 namespace。
- 测试退出清理本进程创建的固定 namespace 和角色。初始化器及指纹稳定性等结构测试可以创建短暂 namespace，必须注册清理或使用 `finally`；这类对象不是部署结构，也不能在 `postgres` 中创建。
- 强制终止无法保证退出清理。残留处理必须核实数据库、namespace、表清单和属主并显式清理；清理错误写 stderr，禁止静默假报完成。
- CI 的 PostgreSQL 服务通过 `POSTGRES_DB=enterprise_gateway` 创建同名库，管理连接和应用连接均指向该库。

## 影响

部署只需维护一个 namespace 和一组表；应用仍使用不同权限的连接。备份与后续迁移必须一起携带角色授权、函数及其固定 `search_path`、触发器、forced RLS、密钥资源及版本契约，不能只复制表。

本决策替代 ADR 0005、ADR 0007 和历史契约中将用途隔离等同于独立 schema 的部分；独立角色、密钥用途和受限访问要求继续成立。独立初始化旧 CLI 保留用于其契约测试与单模块部署，新部署优先使用统一初始化入口。

参考：[PostgreSQL schema 与 search_path](https://www.postgresql.org/docs/17/ddl-schemas.html)、[权限](https://www.postgresql.org/docs/17/ddl-priv.html)。
