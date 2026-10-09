"""中文规则识别器：秘密（D-01）、手机号（D-02）、身份证号（D-03）、
统一社会信用代码（D-04）、金额（D-05）、账号（D-13）、合同编号（D-14）。

编排与校验分离：每个识别器是 presidio ``PatternRecognizer`` 子类，
正则只做候选提取（含边界断言），确定性校验函数负责通过性判定。
识别结果转换为 ``spans.Span``（原文 Python code point 半开偏移 [start,end)）。

本模块不做归一化、不做语义判断，只输出候选跨度。

政策快照声明：以下语境词表与格式常量（``SECRET_*`` / ``MONEY_*`` /
``ACCOUNT_*`` / ``CONTRACT_*``）是本地合成政策快照，仅用于合成场景
验收，不代表任何真实业务授权。政策以不可变数据类（``SecretPolicy`` /
``MoneyPolicy`` / ``AccountPolicy`` / ``ContractPolicy``）在识别器
构造时注入，默认值取模块级政策常量。

规则定义（全部合成场景适用，语义类判断一律不做）：

- 秘密 ``SECRET``（跨度 priority=0；整请求阻断由 ``spans.merge_spans``
  的 P0 语义承载，本模块只输出 Span、不抛 ``SECRET_DETECTED``）：
  - API Key：政策前缀（默认 ``sk-``/``ak-``）+ 纯字母数字主体
    （默认 ≥16 位，前缀/字符集/最小长度全部参数化）；两侧字母数字
    边界（嵌入更长串不命中）；公开文档占位标记（example/xxxx/your/...
    参数化词表，大小写不敏感）不命中。
  - PEM 私钥块：``-----BEGIN <算法名> PRIVATE KEY-----`` 起、
    ``-----END <算法名> PRIVATE KEY-----`` 止的整块（跨度覆盖整块；
    算法名可缺省，但首尾算法名必须一致）；块体必须非空、只含
    base64 字符集与空白、不含占位标记。
  - 密码上下文：政策语境词（默认 ``password``/``密码``/``口令``）+
    分隔符（``:``/``：``/``=``，允许前后空白）后的非空值；值不得含
    空白、引号与常见分隔标点；公开占位示例不命中。只承诺政策定义
    上下文，不承诺识别任意密码；语境词按子串锚定（``mypassword=x``
    同样命中，与 D-02 手机号字母粘连同一取舍）。
  - 三类形态共用一个实体与一个识别器；``validate_result`` 按命中
    形状分发校验（BEGIN 块→PEM；策略前缀开头且主体符合字符集→
    API Key；其余→密码值）。
- 手机号 ``PHONE_NUMBER``：``1[3-9]`` 开头共 11 位（前三位组后接两个
  4 位组）；接受连续写法与 3-4-4 分隔写法（两个分隔位各自可选一个
  半角空格或连字符，允许混合）；
  数字边界：前后紧邻字符不得为数字（嵌入更长数字串不命中）；紧邻字母
  仍命中（明确的取舍，字母粘连不改变号码本身已完整出现的事实）。
- 身份证号 ``CN_ID_NUMBER``：18 位；GB 11643 加权校验位（权重
  7,9,10,5,8,4,2,1,6,3,7,9,10,5,8,4,2，前 17 位加权和模 11 后按
  ``10X98765432`` 映射，校验字符只接受大写 ``X``）；
  出生日期（第 7-14 位）合法性：年 ∈ [1900, 当年]、月 01-12、日按
  公历当月天数（含闰年，由 calendar.monthrange 给出），且日期不晚于
  当日（"当日"由识别器 ``today`` 配置决定，默认 ``datetime.date.today()``）。
  不校验地址码是否真实分配、不校验顺序码语义；年下界 1900 是明确的
  取舍（身份证号制度远晚于该年，1900 以前视为荒谬值）。
- 统一社会信用代码 ``CN_USCC``：18 位；GB 32100 字符集
  ``0-9`` 与大写字母去掉 ``I/O/Z/S/V``；加权校验位（权重
  1,3,9,27,19,26,16,17,20,29,25,13,8,24,10,30,28，前 17 位加权和模 31，
  校验字符 = 字符集第 ``(31 - 和 % 31) % 31`` 位）；小写字母不命中。
- 金额 ``MONEY_AMOUNT``：命中必须携带政策符号/单位/语境之一——
  货币符号（¥/$/€）紧邻数字（符号可在数字前或后，跨度覆盖符号与
  数字）；货币单位邻近数字：多字单位（人民币/美元/万元/...）可在
  数字前或后，单字"元"只在数字后（避免"公元2026年"误报）；
  款项语境词（合同金额/总价款/违约金/...，参数化词表）后经显式
  分隔符（冒号或空白）的裸数字（带符号/单位的金额由符号/单位分支
  承载；裸数字尾侧不得紧跟 年/月/日/字母/连字符，年份与日期类不
  命中）。年份（2026年）、章节号（第3.2节）、编号、无政策上下文的
  普通数字不因是数字而命中。
- 账号 ``ACCOUNT_NUMBER``：政策账号语境词（银行账号/收款账号/
  付款账号/账号/账户/卡号/户名，参数化词表）邻近（允许空白/冒号
  分隔）的纯数字串，长度在政策区间（默认 8-30 位，参数化）；
  尾侧数字边界（嵌入更长数字串不命中）；无语境的普通编号不自动
  当账号。
- 合同编号 ``CONTRACT_NUMBER``：政策合同语境词（合同编号/协议编号/
  合同号/协议号，参数化词表）邻近的
  ``大写字母{2,4}-数字{4}-数字{3,6}``（各段长度均参数化）；
  两侧字母/数字/连字符边界（嵌入更长代码串不命中）；无语境相似
  代码、格式不符（小写、段长越界）不命中。

跨度覆盖口径：API Key 与 PEM 块跨度覆盖整块文本；密码值、金额
表达式、账号、合同编号的跨度只覆盖值/表达式本身，不含语境词——
这些识别器的语境词放在 lookbehind 中（presidio 引擎使用 ``regex``
模块编译模式，支持变长 lookbehind）。``validate_result`` 只收到
命中文本、看不到位置，语境邻近性由候选正则的 lookbehind 保证，
这是 presidio 契约的明确边界。

身份证与统一代码边界：两侧紧邻字符不得为数字或大写字母
（不嵌入更长数字/字母串）；手机号边界：两侧紧邻字符不得为数字。

受控失败：非 ``str`` 文本 → ``INVALID_TEXT``；识别器非法配置
（空名称、非法实体名、空模式、非法置信分、非法 ``today``、非法
政策配置对象/词表/边界值）与非 ``EntityRecognizer`` 编排输入 →
``INVALID_RECOGNIZER``。
"""

from __future__ import annotations

import calendar
import re
from dataclasses import dataclass
from datetime import date
from typing import Iterable

from presidio_analyzer import EntityRecognizer, Pattern, PatternRecognizer

from infra.errors import SafetyCode, SafetyError
from detection.spans import Span

__all__ = [
    "ACCOUNT_NUMBER",
    "CN_ID_NUMBER",
    "CN_USCC",
    "CONTRACT_NUMBER",
    "MONEY_AMOUNT",
    "PHONE_NUMBER",
    "SECRET",
    "AccountNumberRecognizer",
    "AccountPolicy",
    "CnIdNumberRecognizer",
    "CnPhoneRecognizer",
    "CnUsccRecognizer",
    "ContractNumberRecognizer",
    "ContractPolicy",
    "MoneyAmountRecognizer",
    "MoneyPolicy",
    "SecretPolicy",
    "SecretRecognizer",
    "account_number_valid",
    "analyze_text",
    "api_key_secret_valid",
    "contract_number_valid",
    "default_recognizers",
    "id_birth_date_valid",
    "id_check_digit_valid",
    "money_amount_valid",
    "password_value_valid",
    "pem_private_key_valid",
    "phone_candidate_valid",
    "uscc_valid",
]

PHONE_NUMBER = "PHONE_NUMBER"
CN_ID_NUMBER = "CN_ID_NUMBER"
CN_USCC = "CN_USCC"
SECRET = "SECRET"
MONEY_AMOUNT = "MONEY_AMOUNT"
ACCOUNT_NUMBER = "ACCOUNT_NUMBER"
CONTRACT_NUMBER = "CONTRACT_NUMBER"

# 候选跨度优先级：候选不携带秘密语义，用最低档（spans 默认档）。
SPAN_PRIORITY = 3

_ENTITY_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,31}\Z")

# 候选提取正则（只负责"像不像 + 边界"，通过性判定全部在校验函数）。
_PHONE_CANDIDATE = re.compile(r"(?<!\d)1[3-9]\d[ -]?\d{4}[ -]?\d{4}(?!\d)")
_ID_CANDIDATE = re.compile(r"(?<![0-9A-Za-z])\d{17}[\dX](?![0-9A-Za-z])")
_USCC_CANDIDATE = re.compile(r"(?<![0-9A-Za-z])[0-9A-Z]{18}(?![0-9A-Za-z])")

_PHONE_STRICT = re.compile(r"1[3-9]\d{9}\Z")
_ID_STRICT = re.compile(r"\d{17}[\dX]\Z")
_USCC_STRICT = re.compile(r"[0-9A-Z]{18}\Z")
_PHONE_SEPARATORS = re.compile(r"[ -]")

_ID_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_ID_CHECK_CHARS = "10X98765432"
_ID_MIN_YEAR = 1900

_USCC_CHARSET = "0123456789ABCDEFGHJKLMNPQRTUWXY"
_USCC_WEIGHTS = (1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28)
_USCC_INDEX = {char: index for index, char in enumerate(_USCC_CHARSET)}

# ---- 政策常量（全部为本地合成政策快照，非真实业务授权） ----

# D-01 秘密政策。
SECRET_API_KEY_PREFIXES = ("sk-", "ak-")
SECRET_API_KEY_MIN_BODY_LENGTH = 16
SECRET_API_KEY_BODY_CHARS = tuple(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)
SECRET_PASSWORD_CONTEXTS = ("password", "密码", "口令")
SECRET_PASSWORD_SEPARATORS = ":：="
# 密码值 stop 字符集：空白、引号与常见分隔标点不得进入密码值。
_SECRET_PASSWORD_VALUE_CLASS = r"[^\s\"'<>,，。；;、()（）\[\]【】{}|]"
SECRET_PLACEHOLDER_MARKERS = (
    "example",
    "xxxx",
    "your",
    "placeholder",
    "test",
    "demo",
    "sample",
)

# D-05 金额政策。
MONEY_SYMBOLS = ("¥", "$", "€")
MONEY_UNITS = ("人民币", "美元", "欧元", "日元", "港元", "万元", "亿元", "千元", "元")
MONEY_CONTEXTS = (
    "合同金额",
    "总价款",
    "违约金",
    "定金",
    "预付款",
    "进度款",
    "质保金",
    "货款",
    "价款",
    "租金",
    "金额",
)

# D-13 账号政策。
ACCOUNT_CONTEXTS = ("银行账号", "收款账号", "付款账号", "账号", "账户", "卡号", "户名")
ACCOUNT_MIN_DIGITS = 8
ACCOUNT_MAX_DIGITS = 30

# D-14 合同编号政策。
CONTRACT_CONTEXTS = ("合同编号", "协议编号", "合同号", "协议号")
CONTRACT_PREFIX_MIN_LETTERS = 2
CONTRACT_PREFIX_MAX_LETTERS = 4
CONTRACT_YEAR_MIN_DIGITS = 4
CONTRACT_YEAR_MAX_DIGITS = 4
CONTRACT_SEQ_MIN_DIGITS = 3
CONTRACT_SEQ_MAX_DIGITS = 6


def _check_vocab(field: str, value: object) -> tuple[str, ...]:
    """政策词表守卫：非空字符串元组/列表，归一为 tuple。"""
    if isinstance(value, str) or not isinstance(value, (tuple, list)):
        raise SafetyError(SafetyCode.INVALID_RECOGNIZER, field)
    items = tuple(value)
    if not items or any(not isinstance(item, str) or not item for item in items):
        raise SafetyError(SafetyCode.INVALID_RECOGNIZER, field)
    return items


def _check_int(field: str, value: object, low: int, high: int) -> int:
    """政策整数边界守卫：拒绝 bool 与越界值。"""
    if type(value) is not int or not low <= value <= high:
        raise SafetyError(SafetyCode.INVALID_RECOGNIZER, field)
    return value


def _check_policy(policy: object, kind: type, field: str = "policy") -> object:
    if not isinstance(policy, kind):
        raise SafetyError(SafetyCode.INVALID_RECOGNIZER, field)
    return policy


@dataclass(frozen=True)
class SecretPolicy:
    """D-01 秘密识别政策（本地合成快照，非真实业务授权）。"""

    api_key_prefixes: tuple[str, ...] = SECRET_API_KEY_PREFIXES
    api_key_min_body_length: int = SECRET_API_KEY_MIN_BODY_LENGTH
    api_key_body_chars: tuple[str, ...] = SECRET_API_KEY_BODY_CHARS
    password_contexts: tuple[str, ...] = SECRET_PASSWORD_CONTEXTS
    password_separators: tuple[str, ...] = tuple(SECRET_PASSWORD_SEPARATORS)
    placeholder_markers: tuple[str, ...] = SECRET_PLACEHOLDER_MARKERS

    def __post_init__(self) -> None:
        object.__setattr__(self, "api_key_prefixes", _check_vocab("api_key_prefixes", self.api_key_prefixes))
        object.__setattr__(
            self,
            "api_key_min_body_length",
            _check_int("api_key_min_body_length", self.api_key_min_body_length, 1, 128),
        )
        chars = _check_vocab("api_key_body_chars", self.api_key_body_chars)
        if any(len(char) != 1 for char in chars):
            raise SafetyError(SafetyCode.INVALID_RECOGNIZER, "api_key_body_chars")
        object.__setattr__(self, "api_key_body_chars", chars)
        object.__setattr__(self, "password_contexts", _check_vocab("password_contexts", self.password_contexts))
        separators = _check_vocab("password_separators", self.password_separators)
        if any(len(separator) != 1 for separator in separators):
            raise SafetyError(SafetyCode.INVALID_RECOGNIZER, "password_separators")
        object.__setattr__(self, "password_separators", separators)
        markers = _check_vocab("placeholder_markers", self.placeholder_markers)
        object.__setattr__(self, "placeholder_markers", tuple(marker.lower() for marker in markers))


@dataclass(frozen=True)
class MoneyPolicy:
    """D-05 金额识别政策（本地合成快照，非真实业务授权）。

    单字单位不允许出现在数字前（只在数字后），避免"公元2026年"类
    误报；多字单位前后均可。
    """

    symbols: tuple[str, ...] = MONEY_SYMBOLS
    units: tuple[str, ...] = MONEY_UNITS
    contexts: tuple[str, ...] = MONEY_CONTEXTS

    def __post_init__(self) -> None:
        symbols = _check_vocab("symbols", self.symbols)
        if any(len(symbol) != 1 for symbol in symbols):
            raise SafetyError(SafetyCode.INVALID_RECOGNIZER, "symbols")
        object.__setattr__(self, "symbols", symbols)
        object.__setattr__(self, "units", _check_vocab("units", self.units))
        object.__setattr__(self, "contexts", _check_vocab("contexts", self.contexts))

    @property
    def prefix_units(self) -> tuple[str, ...]:
        """允许出现在数字前的单位（多字单位）。"""
        return tuple(unit for unit in self.units if len(unit) > 1)


@dataclass(frozen=True)
class AccountPolicy:
    """D-13 账号识别政策（本地合成快照，非真实业务授权）。"""

    contexts: tuple[str, ...] = ACCOUNT_CONTEXTS
    min_digits: int = ACCOUNT_MIN_DIGITS
    max_digits: int = ACCOUNT_MAX_DIGITS

    def __post_init__(self) -> None:
        object.__setattr__(self, "contexts", _check_vocab("contexts", self.contexts))
        min_digits = _check_int("min_digits", self.min_digits, 1, 64)
        max_digits = _check_int("max_digits", self.max_digits, 1, 64)
        if min_digits > max_digits:
            raise SafetyError(SafetyCode.INVALID_RECOGNIZER, "min_digits")
        object.__setattr__(self, "min_digits", min_digits)
        object.__setattr__(self, "max_digits", max_digits)


@dataclass(frozen=True)
class ContractPolicy:
    """D-14 合同编号识别政策（本地合成快照，非真实业务授权）。"""

    contexts: tuple[str, ...] = CONTRACT_CONTEXTS
    prefix_min_letters: int = CONTRACT_PREFIX_MIN_LETTERS
    prefix_max_letters: int = CONTRACT_PREFIX_MAX_LETTERS
    year_min_digits: int = CONTRACT_YEAR_MIN_DIGITS
    year_max_digits: int = CONTRACT_YEAR_MAX_DIGITS
    seq_min_digits: int = CONTRACT_SEQ_MIN_DIGITS
    seq_max_digits: int = CONTRACT_SEQ_MAX_DIGITS

    def __post_init__(self) -> None:
        object.__setattr__(self, "contexts", _check_vocab("contexts", self.contexts))
        prefix_min = _check_int("prefix_min_letters", self.prefix_min_letters, 1, 16)
        prefix_max = _check_int("prefix_max_letters", self.prefix_max_letters, 1, 16)
        year_min = _check_int("year_min_digits", self.year_min_digits, 1, 16)
        year_max = _check_int("year_max_digits", self.year_max_digits, 1, 16)
        seq_min = _check_int("seq_min_digits", self.seq_min_digits, 1, 16)
        seq_max = _check_int("seq_max_digits", self.seq_max_digits, 1, 16)
        if prefix_min > prefix_max or year_min > year_max or seq_min > seq_max:
            raise SafetyError(SafetyCode.INVALID_RECOGNIZER, "bounds")
        object.__setattr__(self, "prefix_min_letters", prefix_min)
        object.__setattr__(self, "prefix_max_letters", prefix_max)
        object.__setattr__(self, "year_min_digits", year_min)
        object.__setattr__(self, "year_max_digits", year_max)
        object.__setattr__(self, "seq_min_digits", seq_min)
        object.__setattr__(self, "seq_max_digits", seq_max)


def _alternation(items: Iterable[str]) -> str:
    """词表转正则 alternation：去重、长词优先（避免前缀词截断）。"""
    unique = sorted(set(items), key=lambda item: (-len(item), item))
    return "|".join(re.escape(item) for item in unique)


def _char_class(chars: Iterable[str]) -> str:
    """单字符集合转正则字符类。"""
    return "[" + "".join(re.escape(char) for char in dict.fromkeys(chars)) + "]"


def phone_candidate_valid(candidate: str) -> bool:
    """手机号确定性校验：去分隔符后必须是 1[3-9] 开头的 11 位数字。"""
    digits = _PHONE_SEPARATORS.sub("", candidate)
    return _PHONE_STRICT.fullmatch(digits) is not None


def id_check_digit_valid(number: str) -> bool:
    """GB 11643 加权校验位验证。"""
    if len(number) != 18 or _ID_STRICT.fullmatch(number) is None:
        return False
    total = sum(int(digit) * weight for digit, weight in zip(number[:17], _ID_WEIGHTS))
    return _ID_CHECK_CHARS[total % 11] == number[17]


def id_birth_date_valid(number: str, today: date) -> bool:
    """出生日期合法性：年 [1900, 当年]、月 01-12、日按公历、不晚于当日。"""
    if len(number) != 18 or _ID_STRICT.fullmatch(number) is None:
        return False
    try:
        year = int(number[6:10])
        month = int(number[10:12])
        day = int(number[12:14])
    except ValueError:
        return False
    if not (_ID_MIN_YEAR <= year <= today.year):
        return False
    if not (1 <= month <= 12):
        return False
    if not (1 <= day <= calendar.monthrange(year, month)[1]):
        return False
    return date(year, month, day) <= today


def uscc_valid(code: str) -> bool:
    """GB 32100 字符集与加权校验位验证。"""
    if len(code) != 18 or _USCC_STRICT.fullmatch(code) is None:
        return False
    if any(char not in _USCC_INDEX for char in code):
        return False
    total = sum(_USCC_INDEX[char] * weight for char, weight in zip(code[:17], _USCC_WEIGHTS))
    return _USCC_CHARSET[(31 - total % 31) % 31] == code[17]


# ---- D-01/D-05/D-13/D-14 候选正则构建 ----
#
# 语境词一律放 lookbehind（presidio 引擎用 regex 模块编译模式，支持变长
# lookbehind），因此密码值/金额/账号/合同编号的命中跨度只覆盖值本身，
# 不含语境词。validate_result 只收到命中文本、看不到位置，语境邻近性由
# 候选正则保证。

# PEM 私钥块候选：整块提取（(?s) 使 . 跨行）；首尾算法名一致性与块体
# 字符集由 pem_private_key_valid 判定。
_PEM_PRIVATE_KEY_CANDIDATE = (
    r"(?s)(?<!-)-----BEGIN ([A-Z0-9]+ )?PRIVATE KEY-----"
    r".*?-----END ([A-Z0-9]+ )?PRIVATE KEY-----(?!-)"
)
_PEM_PRIVATE_KEY_STRICT = re.compile(
    r"-----BEGIN ([A-Z0-9]+ )?PRIVATE KEY-----\r?\n"
    r"(.*?)-----END ([A-Z0-9]+ )?PRIVATE KEY-----",
    re.DOTALL,
)
_PEM_BODY_ALLOWED = re.compile(r"[A-Za-z0-9+/=\s]*")
_PASSWORD_VALUE_STRICT = re.compile(_SECRET_PASSWORD_VALUE_CLASS + r"+")


def _group(items: Iterable[str]) -> str:
    """词表转非捕获组；空词表退化为永不匹配分支 (?!)。"""
    body = _alternation(items)
    return f"(?:{body})" if body else "(?!)"


def _api_key_candidate(policy: SecretPolicy) -> str:
    """API Key 候选：政策前缀 + 纯字符集主体（≥ 政策最小长度），两侧字母数字边界。"""
    prefixes = _group(policy.api_key_prefixes)
    body = _char_class(policy.api_key_body_chars)
    minimum = policy.api_key_min_body_length
    return rf"(?<![A-Za-z0-9]){prefixes}{body}{{{minimum},}}(?![A-Za-z0-9])"


def _password_candidate(policy: SecretPolicy) -> str:
    """密码值候选：语境词 + 分隔符（:：=，允许前后空白与成对引号）后的非空值。

    引号（JSON 形态 ``"password":"..."``）由 lookbehind 消费，命中跨度
    只覆盖引号内的值本身。
    """
    contexts = _group(policy.password_contexts)
    separators = _group(policy.password_separators)
    return rf"(?<={contexts}[\"']?\s*{separators}\s*[\"']?){_SECRET_PASSWORD_VALUE_CLASS}+"


def _money_candidate(policy: MoneyPolicy) -> str:
    """金额候选：符号/单位/语境分支的有序 alternation（先长后短靠分支顺序消解重叠）。"""
    symbol_class = _char_class(policy.symbols)
    units = _group(policy.units)
    prefix_units = _group(policy.prefix_units)
    contexts = _group(policy.contexts)
    number = r"\d+(?:,\d{3})*(?:\.\d+)?"
    branches = (
        rf"{symbol_class}\s*{number}(?:\s*{units})?",  # 符号前（可带后置单位）
        rf"{number}\s*{symbol_class}",  # 符号后
        rf"{prefix_units}\s*{number}(?:\s*{units})?",  # 多字单位前
        rf"{number}\s*{units}",  # 单位后（含单字"元"）
        # 语境词 + 显式分隔符（冒号或空白）后的裸数字；尾侧紧跟
        # 年/月/日/字母/连字符/数字点号的按年份与编号类拒绝。
        rf"(?<={contexts}(?:\s*[:：]\s*|\s+)){number}(?![-\d.,A-Za-z年月日])",
    )
    return rf"(?<![\d.,])(?:{'|'.join(branches)})(?![\d.,])"


def _money_strict_pattern(policy: MoneyPolicy) -> str:
    """金额命中形状复核：可选（符号|多字单位）+ 数字 + 可选符号/单位。"""
    symbol_class = _char_class(policy.symbols)
    units = _group(policy.units)
    prefix_units = _group(policy.prefix_units)
    number = r"\d+(?:,\d{3})*(?:\.\d+)?"
    return rf"(?:{symbol_class}\s*|{prefix_units}\s*)?{number}(?:\s*{symbol_class})?(?:\s*{units})?"


def _account_candidate(policy: AccountPolicy) -> str:
    """账号候选：语境词邻近（允许空白/冒号分隔）的政策长度数字串。"""
    contexts = _group(policy.contexts)
    return rf"(?<={contexts}\s*[:：]?\s*)\d{{{policy.min_digits},{policy.max_digits}}}(?!\d)"


def _contract_candidate(policy: ContractPolicy) -> str:
    """合同编号候选：语境词邻近的政策格式代码。"""
    contexts = _group(policy.contexts)
    code = (
        rf"[A-Z]{{{policy.prefix_min_letters},{policy.prefix_max_letters}}}"
        rf"-\d{{{policy.year_min_digits},{policy.year_max_digits}}}"
        rf"-\d{{{policy.seq_min_digits},{policy.seq_max_digits}}}"
    )
    return rf"(?<={contexts}\s*[:：]?\s*)(?<![A-Z0-9-]){code}(?![A-Z0-9-])"


# ---- D-01/D-05/D-13/D-14 确定性校验 ----


def _contains_placeholder(text: str, policy: SecretPolicy) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in policy.placeholder_markers)


def api_key_secret_valid(text: str, policy: SecretPolicy) -> bool:
    """API Key 确定性校验：政策前缀、主体字符集、最小长度、占位标记。"""
    for prefix in policy.api_key_prefixes:
        if text.startswith(prefix):
            body = text[len(prefix) :]
            break
    else:
        return False
    if len(body) < policy.api_key_min_body_length:
        return False
    if any(char not in policy.api_key_body_chars for char in body):
        return False
    return not _contains_placeholder(text, policy)


def pem_private_key_valid(text: str, policy: SecretPolicy) -> bool:
    """PEM 私钥块确定性校验：首尾算法名一致、块体非空且只含 base64 字符集与空白。"""
    match = _PEM_PRIVATE_KEY_STRICT.fullmatch(text)
    if match is None:
        return False
    if match.group(1) != match.group(3):
        return False
    body = match.group(2)
    if not body.strip():
        return False
    if _PEM_BODY_ALLOWED.fullmatch(body) is None:
        return False
    if "PRIVATE KEY" in body:
        return False
    return not _contains_placeholder(text, policy)


def password_value_valid(text: str, policy: SecretPolicy) -> bool:
    """密码值确定性校验：非空、不含分隔标点、不是公开占位示例。"""
    if _PASSWORD_VALUE_STRICT.fullmatch(text) is None:
        return False
    return not _contains_placeholder(text, policy)


def money_amount_valid(text: str, policy: MoneyPolicy) -> bool:
    """金额形状复核；语境邻近性由候选正则的 lookbehind 保证。"""
    return re.fullmatch(_money_strict_pattern(policy), text) is not None


def account_number_valid(text: str, policy: AccountPolicy) -> bool:
    """账号确定性校验：政策长度区间内的纯数字串。"""
    return re.fullmatch(rf"\d{{{policy.min_digits},{policy.max_digits}}}", text) is not None


def contract_number_valid(text: str, policy: ContractPolicy) -> bool:
    """合同编号确定性校验：政策格式（大写字母-数字-数字，段长参数化）。"""
    code = (
        rf"[A-Z]{{{policy.prefix_min_letters},{policy.prefix_max_letters}}}"
        rf"-\d{{{policy.year_min_digits},{policy.year_max_digits}}}"
        rf"-\d{{{policy.seq_min_digits},{policy.seq_max_digits}}}"
    )
    return re.fullmatch(code, text) is not None


class _CnPatternRecognizer(PatternRecognizer):
    """公共配置守卫：正则只提取候选，validate_result 只做确定性判定。

    ``span_priority`` 是该识别器输出 Span 的优先级：默认最低档（3），
    秘密识别器覆写为 0（整请求阻断，语义由 spans.merge_spans 承载）。
    """

    span_priority = SPAN_PRIORITY

    def __init__(
        self,
        *,
        supported_entity: str,
        name: str,
        patterns: tuple[Pattern, ...],
        score: float,
    ) -> None:
        if not isinstance(supported_entity, str) or _ENTITY_NAME.fullmatch(supported_entity) is None:
            raise SafetyError(SafetyCode.INVALID_RECOGNIZER, "supported_entity")
        if not isinstance(name, str) or not name:
            raise SafetyError(SafetyCode.INVALID_RECOGNIZER, "name")
        if not patterns:
            raise SafetyError(SafetyCode.INVALID_RECOGNIZER, "patterns")
        for pattern in patterns:
            if not isinstance(pattern, Pattern) or not isinstance(pattern.regex, str) or not pattern.regex:
                raise SafetyError(SafetyCode.INVALID_RECOGNIZER, "pattern")
        if not isinstance(score, (int, float)) or isinstance(score, bool) or not (0 < score <= 1):
            raise SafetyError(SafetyCode.INVALID_RECOGNIZER, "score")
        super().__init__(
            supported_entity=supported_entity,
            name=name,
            supported_language="zh",
            patterns=[Pattern(p.name, p.regex, float(score)) for p in patterns],
            global_regex_flags=0,
        )


class SecretRecognizer(_CnPatternRecognizer):
    """D-01 秘密识别器：API Key / PEM 私钥块 / 政策密码上下文。

    命中输出 priority=0 的 Span；整请求阻断由 spans.merge_spans 的
    P0 语义承载。validate_result 按命中形状分发：BEGIN 块按 PEM 校验；
    策略前缀开头且通过 API Key 校验的直接通过；策略前缀开头但未通过
    API Key 校验的按密码值回退校验（如 ``password=sk-含中文的值``），
    全部失败则不命中。
    """

    span_priority = 0

    def __init__(
        self,
        *,
        name: str = "SecretRecognizer",
        score: float = 1.0,
        policy: SecretPolicy | None = None,
    ) -> None:
        if policy is None:
            policy = SecretPolicy()
        _check_policy(policy, SecretPolicy)
        self._policy = policy
        super().__init__(
            supported_entity=SECRET,
            name=name,
            patterns=(
                Pattern("secret_pem_private_key", _PEM_PRIVATE_KEY_CANDIDATE, 1.0),
                Pattern("secret_api_key", _api_key_candidate(policy), 1.0),
                Pattern("secret_password_value", _password_candidate(policy), 1.0),
            ),
            score=score,
        )

    def validate_result(self, pattern_text: str) -> bool:
        policy = self._policy
        if pattern_text.startswith("-----BEGIN"):
            return pem_private_key_valid(pattern_text, policy)
        for prefix in policy.api_key_prefixes:
            if pattern_text.startswith(prefix):
                if api_key_secret_valid(pattern_text, policy):
                    return True
                break
        return password_value_valid(pattern_text, policy)


class MoneyAmountRecognizer(_CnPatternRecognizer):
    """D-05 金额识别器：仅政策符号/单位/语境约束下的金额表达式命中。"""

    def __init__(
        self,
        *,
        name: str = "MoneyAmountRecognizer",
        score: float = 1.0,
        policy: MoneyPolicy | None = None,
    ) -> None:
        if policy is None:
            policy = MoneyPolicy()
        _check_policy(policy, MoneyPolicy)
        self._policy = policy
        self._strict = re.compile(_money_strict_pattern(policy))
        super().__init__(
            supported_entity=MONEY_AMOUNT,
            name=name,
            patterns=(Pattern("money_amount_candidate", _money_candidate(policy), 1.0),),
            score=score,
        )

    def validate_result(self, pattern_text: str) -> bool:
        return self._strict.fullmatch(pattern_text) is not None


class AccountNumberRecognizer(_CnPatternRecognizer):
    """D-13 账号识别器：政策语境词邻近且长度在政策区间内的数字串。"""

    def __init__(
        self,
        *,
        name: str = "AccountNumberRecognizer",
        score: float = 1.0,
        policy: AccountPolicy | None = None,
    ) -> None:
        if policy is None:
            policy = AccountPolicy()
        _check_policy(policy, AccountPolicy)
        self._policy = policy
        super().__init__(
            supported_entity=ACCOUNT_NUMBER,
            name=name,
            patterns=(Pattern("account_number_candidate", _account_candidate(policy), 1.0),),
            score=score,
        )

    def validate_result(self, pattern_text: str) -> bool:
        return account_number_valid(pattern_text, self._policy)


class ContractNumberRecognizer(_CnPatternRecognizer):
    """D-14 合同编号识别器：政策语境词邻近且符合政策格式的编号。"""

    def __init__(
        self,
        *,
        name: str = "ContractNumberRecognizer",
        score: float = 1.0,
        policy: ContractPolicy | None = None,
    ) -> None:
        if policy is None:
            policy = ContractPolicy()
        _check_policy(policy, ContractPolicy)
        self._policy = policy
        super().__init__(
            supported_entity=CONTRACT_NUMBER,
            name=name,
            patterns=(Pattern("contract_number_candidate", _contract_candidate(policy), 1.0),),
            score=score,
        )

    def validate_result(self, pattern_text: str) -> bool:
        return contract_number_valid(pattern_text, self._policy)


class CnPhoneRecognizer(_CnPatternRecognizer):
    """D-02 中国大陆手机号识别器。"""

    def __init__(self, *, name: str = "CnPhoneRecognizer", score: float = 1.0) -> None:
        super().__init__(
            supported_entity=PHONE_NUMBER,
            name=name,
            patterns=(Pattern("cn_mobile_candidate", _PHONE_CANDIDATE.pattern, 1.0),),
            score=score,
        )

    def validate_result(self, pattern_text: str) -> bool:
        return phone_candidate_valid(pattern_text)


class CnIdNumberRecognizer(_CnPatternRecognizer):
    """D-03 居民身份证号识别器（GB 11643 校验位 + 出生日期合法性）。"""

    def __init__(
        self,
        *,
        name: str = "CnIdNumberRecognizer",
        score: float = 1.0,
        today: date | None = None,
    ) -> None:
        if today is None:
            today = date.today()
        if type(today) is not date:
            raise SafetyError(SafetyCode.INVALID_RECOGNIZER, "today")
        self._today = today
        super().__init__(
            supported_entity=CN_ID_NUMBER,
            name=name,
            patterns=(Pattern("cn_id_candidate", _ID_CANDIDATE.pattern, 1.0),),
            score=score,
        )

    def validate_result(self, pattern_text: str) -> bool:
        return id_check_digit_valid(pattern_text) and id_birth_date_valid(pattern_text, self._today)


class CnUsccRecognizer(_CnPatternRecognizer):
    """D-04 统一社会信用代码识别器（GB 32100 字符集与校验位）。"""

    def __init__(self, *, name: str = "CnUsccRecognizer", score: float = 1.0) -> None:
        super().__init__(
            supported_entity=CN_USCC,
            name=name,
            patterns=(Pattern("cn_uscc_candidate", _USCC_CANDIDATE.pattern, 1.0),),
            score=score,
        )

    def validate_result(self, pattern_text: str) -> bool:
        return uscc_valid(pattern_text)


def default_recognizers() -> tuple[EntityRecognizer, ...]:
    """默认七路中文规则识别器（每次都是新实例，无共享可变状态）。

    含秘密（D-01，priority=0）与 D-02/03/04/05/13/14 候选识别器；
    秘密的整请求阻断语义由 spans.merge_spans 承载。
    """
    return (
        SecretRecognizer(),
        CnPhoneRecognizer(),
        CnIdNumberRecognizer(),
        CnUsccRecognizer(),
        MoneyAmountRecognizer(),
        AccountNumberRecognizer(),
        ContractNumberRecognizer(),
    )


def analyze_text(
    text: str,
    recognizers: Iterable[EntityRecognizer] | None = None,
) -> tuple[Span, ...]:
    """对原文运行识别器编排，返回按 (start, end, entity_type) 排序的候选跨度。

    偏移为 Python code point 半开区间，与 presidio ``RecognizerResult``
    的 start/end 坐标系一致；本函数不做归一化与语义判断。每个识别器
    的 ``span_priority`` 决定输出 Span 的优先级（默认最低档 3）。
    """
    if not isinstance(text, str):
        raise SafetyError(SafetyCode.INVALID_TEXT, "text")
    if recognizers is None:
        active = default_recognizers()
    else:
        invalid = False
        try:
            active = tuple(recognizers)
        except TypeError:
            invalid = True
        if invalid:
            raise SafetyError(SafetyCode.INVALID_RECOGNIZER, "recognizers")
    for recognizer in active:
        if not isinstance(recognizer, EntityRecognizer):
            raise SafetyError(SafetyCode.INVALID_RECOGNIZER, "recognizers")
    spans: list[Span] = []
    for recognizer in active:
        priority = getattr(recognizer, "span_priority", SPAN_PRIORITY)
        for result in recognizer.analyze(text, entities=None, nlp_artifacts=None):
            spans.append(Span(result.start, result.end, result.entity_type, priority))
    spans.sort(key=lambda span: (span.start, span.end, span.entity_type))
    return tuple(spans)
