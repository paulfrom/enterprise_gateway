# 统一受控异常注册表与零泄漏断链

在网关多层处理架构中，如果错误码分散且各模块使用平行异常范式，极易发生异常链（`__cause__` / `__context__`）意外捕获并回显请求明文或凭据正文（例如 Pydantic ValidationError 或 JSONDecodeError 默认内嵌输入值），导致敏感信息泄露。

系统建立全工程统一的受控异常机制：
1. **单一注册表**：所有受控失败统一使用 `errors.SafetyCode` 注册表与 `errors.SafetyError(code, detail)`。
2. **零泄漏静态诊断**：`detail` 仅允许包含静态诊断描述（如特定字段名、协议名、组件标识），严禁携带业务提交的任何正文、凭据或原文片段。
3. **断链隔离**：共享严格 JSON 解析收敛至 `strict_json.parse_strict_json`，失败时捕获异常并在外部重新抛出 `SafetyError`，保证任何 `SafetyError` 的 `__cause__` 与 `__context__` 均为 `None`，杜绝堆栈回溯泄露。
