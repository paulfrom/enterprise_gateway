# 可信身份与保护域/原始 ACL 绑定契约（C-02）

版本：1.0.0（2026-10-03，固定契约）

## 1. 契约目标与安全边界

本契约用于实现企业身份（`TrustedIdentity`）对保护域（Protection Domain）、租户（Tenant ID）、角色（Roles）、授权用途（Purposes）及原始来源访问控制列表（Source ACL）的强类型绑定。

### 安全铁律

1. **禁止客户端请求头注入**：
   网关绝不信任来自 HTTP 客户端直接提供的身份或权限相关请求头（如 `X-User-Id`、`X-Tenant-Id`、`X-Domain`、`X-Roles`、`X-Original-ACL` 等）。包含上述请求头的请求一律作为违规请求强制阻断拒绝（`UNTRUSTED_HEADER_REJECTED`）。
2. **信任源于受信适配器**：
   可信身份对象仅能由内部受信任认证层（例如经过 mTLS 验证的客户端证书、内部微服务签发的内部票据等）构造并传递给网关。
3. **跨域与越权强阻断**：
   跨租户、跨域访问直接触发 `SCOPE_MISMATCH`；未在数据源原始 ACL 范围内的操作直接触发 `ACCESS_DENIED`；超出目的范围触发 `UNAUTHORIZED_PURPOSE`；缺少角色触发 `MISSING_REQUIRED_ROLE`。
4. **零凭据正文泄漏**：
   所有鉴权与身份校验失败产生的异常均属于受控异常，不输出用户正文、认证凭据或内部网络拓扑信息。

## 2. 字段规范与约束

| 字段名 | 类型 | 约束 | 来源 |
|---|---|---|---|
| `subject_id` | `str` | 非空字符串，表示主体唯一标识 | 受信认证适配器 |
| `tenant_id` | `str` | 非空字符串，表示租户隔离边界 | 受信认证适配器 |
| `domain` | `str` | 非空字符串，表示保护域 | 受信认证适配器 |
| `roles` | `frozenset[str]` | 非空不可变字符串集合 | 受信认证适配器 |
| `purposes` | `frozenset[str]` | 非空不可变字符串集合，表示授权用途 | 受信认证适配器 |
| `source_acl` | `frozenset[str]` | 非空不可变字符串集合，表示原始数据访问权限 | 受信认证适配器 |
| `auth_source` | `str` | 非空字符串，如 `mTLS`、`internal_token` | 受信认证适配器 |
| `authenticated_at` | `datetime` | 带有时区的时间戳 | 受信认证适配器 |
| `expires_at` | `datetime` | 带有时区的时间戳，必须大于 `authenticated_at` | 受信认证适配器 |

## 3. 场景覆盖与正反例

1. **正例**：合法受信任身份访问本域资源，且在 ACL 范围内且目的相符 -> 校验通过。
2. **反例：伪造 Header 篡改域**：请求头包含 `x-domain: secret-domain` -> 抛出 `IdentityError(UNTRUSTED_HEADER_REJECTED)`。
3. **反例：伪造 Header 篡改 ACL**：请求头包含 `x-original-acl: admin` -> 抛出 `IdentityError(UNTRUSTED_HEADER_REJECTED)`。
4. **反例：跨租户/跨域访问**：身份域为 `finance`，试图操作 `hr` 域数据 -> 抛出 `IdentityError(SCOPE_MISMATCH)`。
5. **反例：越权访问数据源**：身份 `user-1` 不在数据的 `source_acl={"user-2", "user-3"}` 中 -> 抛出 `IdentityError(ACCESS_DENIED)`。
6. **反例：未授权目的**：授权目的为 `customer_support`，操作要求目的为 `marketing_analysis` -> 抛出 `IdentityError(UNAUTHORIZED_PURPOSE)`。
7. **反例：凭据过期与未来时间戳**：凭据已过 `expires_at` 或 `authenticated_at` 在未来 -> 抛出对应过期/非法受控错误。
