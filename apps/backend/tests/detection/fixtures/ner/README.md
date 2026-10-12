# NER 夹具说明

本目录夹具全部为合成数据，不含真实人名、机构名或任何真实业务内容。

- `synth-long-text.txt`：由 `aa bb cc dd ee ff gg hh` 模式重复构成的纯 ASCII
  字母文本，仅用于驱动多窗口切分路径的真实加载管线测试；字母序列不指向
  任何真实实体。
- `business-samples.json`：业务脱敏质量与性能评测语料，包含 40 个合成请求、
  50 个文本片段，覆盖客服、合同、财务、人事、规则格式、秘密阻断和低风险
  正常文本。其中 5 个请求包含多个片段，9 个请求为纯负例；5 个长文本长度
  分别为 2048、4096、8192、3072、2048 个 Unicode code point。

业务语料固定为 `schema_version=1`、`synthetic_only=true`。`fragments` 表示同一
请求中的独立文本片段，金标的 `start`/`end` 是各片段原文内的 Unicode code
point 半开区间 `[start,end)`，与 Python 字符串切片一致；无需对 emoji、组合
字符或换行做归一化。NER 金标使用 `PER`、`ORG`、`LOC`；规则金标使用当前
默认识别器的 `PHONE_NUMBER`、`CN_ID_NUMBER`、`CN_USCC`、`MONEY_AMOUNT`、
`ACCOUNT_NUMBER`、`CONTRACT_NUMBER`、`SECRET`。秘密样本的
`expect_secret_block=true` 表示整个请求必须阻断，包括同请求的其他片段。

人名、企业名与地点名均为虚构标签，词典条目只用于完整检测链路评测。NER
单独评测应直接对原文推理，单独统计 `PER`、`ORG`、`LOC`，避免词典命中掩盖
模型漏检。号码按格式人工构造，不来自真实客户或员工；身份证地址码使用
不可分配的 `9901xx` 合成前缀，统一社会信用代码使用 `9199` 合成前缀。账号
不绑定任何银行账户；API key、密码和 PEM 内容仅为无效的合成字符串，PEM
块体编码的是任意文本，并非可用私钥。

长文本在内容 token 126 附近及后续 `126 + 32n` 边界布局实体，并保留末尾
实体。已按本机 `bert4ner-base-chinese-onnx/tokenizer.json` 的 offsets 校准
跨界样本；窗口参数为 `window_length=128`（内容容量 126）、`stride=32`。
更换 tokenizer 或窗口参数后应重新确认这些边界。每一处重复人名、机构名、
地点名和规则实体都完整标注，填充段仅使用普通流程描述；emoji 与组合字符
样本用于检查偏移坐标。

`tests/detection/test_business_samples.py` 校验结构、片段范围、唯一标识、全部
虚构实体出现位置、当前规则的精确命中、纯负例及阻断预期。本机模型存在时
也校验真实 token 窗口跨界与末尾实体。该语料适合建立确定性回归和分阶段
性能基线；合成语料不能代表生产业务分布，真实业务评测数据应保存在仓库外。
