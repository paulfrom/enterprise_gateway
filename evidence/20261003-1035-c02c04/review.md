# 批次评审报告（run-id: 20261003-1035-c02c04）

- 评审基线：`baseline/source-manifest.txt` 与 `baseline/check-run.txt`（120项历史单元测试全部通过）。
- 评审范围：C-02（可信身份与保护域/原始ACL绑定）与 C-04（精确静态内容免检边界）。
- 评审模式：`independent`（独立审阅核对与断言复核）。

## 一、代码实现与设计核对

### 1. C-02 可信身份与保护域/原始 ACL 契约
- **文件**：[`identity.py`](file:///d:/project/skills/脱敏网关/enterprise_gateway/src/enterprise_gateway/identity.py)
- **核对结果**：
  1. **禁止客户端请求头注入**：全面封禁 `FORBIDDEN_CLIENT_IDENTITY_HEADERS`，大小写不敏感匹配；任意伪造请求头立即触发受控阻断（`UNTRUSTED_HEADER_REJECTED`）。
  2. **强类型不可变上下文**：`TrustedIdentity` 采用 `frozen=True, slots=True`，严格校验 `subject_id`、`tenant_id`、`domain`、`auth_source`、`roles`、`purposes`、`source_acl` 及带有时区的生命周期时间戳。
  3. **领域桥接**：提供 `to_trusted_actor()` 方法，将可信身份直接转换为知识领域所需的 `TrustedActor` 模型，消除领域概念分裂。
  4. **越权强阻断**：跨域（`SCOPE_MISMATCH`）、越权（`ACCESS_DENIED`）、未授权用途（`UNAUTHORIZED_PURPOSE`）、缺少角色（`MISSING_REQUIRED_ROLE`）均具备显式受控断言。
  5. **Canary 防泄漏**：Canary 验证证明异常信息及调用栈绝不包含伪造的凭据内容。

### 2. C-04 精确静态内容免检边界契约
- **文件**：[`static_exemption.py`](file:///d:/project/skills/脱敏网关/enterprise_gateway/src/enterprise_gateway/static_exemption.py)
- **核对结果**：
  1. **清单防篡改与完整性**：注册表严格校验模版文本与声明的 SHA-256 摘要；防范 JSON 重复键及非标准 JSON 常量。
  2. **精确内容与边界双重匹配**：`text == template.text` 确保 100% 逐字符一致。
  3. **细微变动强阻断**：改单字、标点变动、增减空格立即失效，判定为 `NOT_EXEMPT`。
  4. **动态变量与组合逃逸防范**：动态插值或与用户提问拼接的不可分离组合，整体判定为 `NOT_EXEMPT`，必须调用检测器 Spy。
  5. **检测器 Spy 行为可证伪**：正例命中免检时，检测器调用计数为 0；非免检时，检测器调用计数为 1。

## 二、评审发现与解决记录

| # | 位置 | 发现问题 | 影响 | 处理方式 | 复验结果 |
|---|---|---|---|---|---|
| 1 | `static_exemption.py:121` | 解析 JSON 时发生 `ExemptionError` 被通配 `Exception` 捕获重包装为 `REGISTRY_PARSE_FAILED`，导致重复 Key 错误类型偏离 | 错误码不精准 | 在异常捕获前显式透传 `except ExemptionError: raise` | 修复并通过 `test_registry_duplicate_json_keys_rejected` |

## 三、验收结论

C-02 与 C-04 均达到 **L1** 验收标准，全部正反例断言通过，全量回归套件无衰退。
HTTP 模型端点保持 503 拒绝，无真实外部请求外发，无凭据/正文泄漏风险。
