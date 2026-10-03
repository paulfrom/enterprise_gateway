# 批次交接（run-id: 20261003-0855-c01c03）

日期：2026-10-03。用户请求：直接修复架构评审第 1 组问题，并按里程碑进入下一步开发（C-01/C-03）。

## 本批实际完成

| 项 | 结果 | 证据 |
|---|---|---|
| 批次前修复（KeyError 收敛、SafetyCode 注册表、core 拆分 egress/mapping/spans、422 不回显处理器） | 完成 | review.md 第一节；baseline/check-run.txt |
| C-01 分级外发政策契约 | **L1 通过**（独立评审 + 修正后复验） | C-01/result.json（22 断言全 pass） |
| C-03 两协议逐字段候选契约 | **L1 通过**（独立评审 + 修正后复验） | C-03/result.json（59 断言全 pass） |
| 全量回归 | 120/120（离线重建 wheel） | baseline/final-check-run.txt |
| HTTP 烟测（回环、canary、测后即停） | 通过 | baseline/http-smoke.txt |

## 产物索引

- 实现：src/enterprise_gateway/policy.py、protocols.py、errors.py、egress.py、mapping.py、spans.py（core.py 已删除，无兼容层）；app.py 增加 422 处理器；knowledge.py 未知 ID 受控错误。
- 契约文档：docs/contracts/egress-policy.md、docs/contracts/protocol-field-policy.md。
- 夹具：tests/fixtures/C-01/（11）、tests/fixtures/C-03/（47）。
- 测试：test_policy_contract.py（21）、test_protocol_contracts.py（59）、test_egress/test_mapping/test_spans（拆自 test_core）、test_app/test_knowledge（各新增 1 反例）。
- 官方来源记录：baseline/official-sources.md（DeepSeek/Claude 页面 2026-10-03 读取，均无稳定协议版本号，本地快照固定）。

## 复现命令（代码目录）

```powershell
.\scripts\check.ps1   # 离线重建 wheel + 全量 unittest
```

HTTP 烟测步骤见 baseline/http-smoke.txt 头部命令记录模式（uvicorn 绑 127.0.0.1，canary 正文/凭据，测后 kill）。

## Git 与环境状态

- 本地仓库 main 仍无 commit；当前用户受 git safe.directory 限制无法读取仓库状态（未改全局配置）。基线身份以 source-manifest.txt 真实哈希标识。
- Windows、Python 3.11.9、uv 离线缓存 .uv-cache；Docker 未实测。

## 未发生

真实供应商外发、真实知识采集、真实 IAM 接入、持久审计、生产部署均未发生；HTTP 模型入口保持 503；政策/契约测试中的出站与资格判断均为合成 spy。

## 未测与阻塞

- P2 领域规则四项待设计/业务决策（review.md 第二节）。
- 协议契约是候选子集：工具/SSE/多模态/signed thinking/历史状态不准入；静态免检（C-04）未实现，所有 content 均待检测。
- 模型白名单是本地契约常量，不是官方型号兼容声明。

## 下一批已满足的前置与建议

- C-02（前置 C-01）、C-06（前置 C-01）、C-04（前置 C-03）现已解锁；C-05 需 C-01+C-03 均已通过，亦解锁。
- P-07/P-13（前置 C-03）可按 07 第 4 节提前并行。
- 建议下一批：C-02 + C-04（身份绑定与静态免检是后续纵切的关键依赖），或按用户指定。
- 注意：C-02 涉及可信身份语义，开工前应在任务卡明确身份适配边界，不得从客户端头取信任。
