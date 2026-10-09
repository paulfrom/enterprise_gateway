"""中文规则识别器测试（身份证、手机号、统一信用代码、银行卡、金额、合同号、私钥及API Key等）。

夹具全部为合成数据（地址码 9901xx / 9199 前缀刻意不可分配，
校验位按 GB 11643 / GB 32100 算法合成），不含真实号码；
私钥夹具与运行时密钥均为显式标注的合成 PEM。
"""

import json
import unittest
from datetime import date, datetime
from pathlib import Path

from presidio_analyzer import EntityRecognizer, Pattern

from infra.errors import SafetyCode, SafetyError
from detection.recognizers import (
    ACCOUNT_NUMBER,
    CN_ID_NUMBER,
    CN_USCC,
    CONTRACT_NUMBER,
    MONEY_AMOUNT,
    PHONE_NUMBER,
    SECRET,
    AccountNumberRecognizer,
    AccountPolicy,
    CnIdNumberRecognizer,
    CnPhoneRecognizer,
    CnUsccRecognizer,
    ContractNumberRecognizer,
    ContractPolicy,
    MoneyAmountRecognizer,
    MoneyPolicy,
    SecretPolicy,
    SecretRecognizer,
    _CnPatternRecognizer,
    account_number_valid,
    analyze_text,
    api_key_secret_valid,
    contract_number_valid,
    default_recognizers,
    id_birth_date_valid,
    id_check_digit_valid,
    money_amount_valid,
    password_value_valid,
    pem_private_key_valid,
    phone_candidate_valid,
    uscc_valid,
)
from detection.spans import Span

FIXTURES_DIR = Path(__file__).parent / "fixtures"

# 手工验算的公开算法样例（用于锚定校验函数实现）：
# GB 11643：body 11010119900307758 加权和 244，244 mod 11 = 2 → 映射 'X'。
_ID_SAMPLE_VALID = "11010119900307758X"
# GB 32100：body 91110000000000000 加权和 48，48 mod 31 = 17 → 校验位字符集第 14 位 'E'。
_USCC_SAMPLE_VALID = "91110000000000000E"


def load_cases(rule_name: str) -> dict:
    with open(FIXTURES_DIR / "rules" / rule_name / "cases.json", "r", encoding="utf-8") as f:
        return json.load(f)


class ValidatorFunctionTests(unittest.TestCase):
    """确定性校验函数本身的手工验算向量（与识别器解耦）。"""

    def test_gb11643_hand_verified_vector(self) -> None:
        self.assertTrue(id_check_digit_valid(_ID_SAMPLE_VALID))
        self.assertFalse(id_check_digit_valid(_ID_SAMPLE_VALID[:-1] + "3"))

    def test_gb11643_validator_rejects_shape_errors(self) -> None:
        self.assertFalse(id_check_digit_valid("1101011990030775"))
        self.assertFalse(id_check_digit_valid("11010119900307758x"))
        self.assertFalse(id_check_digit_valid("X" * 18))

    def test_gb32100_hand_verified_vector(self) -> None:
        self.assertTrue(uscc_valid(_USCC_SAMPLE_VALID))
        self.assertFalse(uscc_valid(_USCC_SAMPLE_VALID[:-1] + "0"))

    def test_gb32100_validator_rejects_charset_and_shape(self) -> None:
        self.assertFalse(uscc_valid("91I10000000000000E"))
        self.assertFalse(uscc_valid("91O10000000000000E"))
        self.assertFalse(uscc_valid("91Z10000000000000E"))
        self.assertFalse(uscc_valid("91S10000000000000E"))
        self.assertFalse(uscc_valid("91V10000000000000E"))
        self.assertFalse(uscc_valid("9111000000000000"))
        self.assertFalse(uscc_valid("91110000000000000e"))

    def test_phone_validator_normalizes_separators(self) -> None:
        self.assertTrue(phone_candidate_valid("13812345678"))
        self.assertTrue(phone_candidate_valid("138-1234-5678"))
        self.assertTrue(phone_candidate_valid("138 1234 5678"))
        self.assertFalse(phone_candidate_valid("138123456789"))
        self.assertFalse(phone_candidate_valid("138-1234"))

    def test_id_birth_date_rules_with_fixed_today(self) -> None:
        today = date(2024, 6, 1)
        body = "990101{date}{seq}"
        self.assertTrue(id_birth_date_valid(id_number(body, "2000", "0229", "007"), today))
        self.assertFalse(id_birth_date_valid(id_number(body, "1901", "0229", "007"), today))
        self.assertFalse(id_birth_date_valid(id_number(body, "1899", "0307", "758"), today))
        self.assertFalse(id_birth_date_valid(id_number(body, "2024", "0602", "007"), today))
        self.assertFalse(id_birth_date_valid(id_number(body, "2024", "0615", "007"), today))
        self.assertTrue(id_birth_date_valid(id_number(body, "1900", "0101", "000"), today))
        self.assertFalse(id_birth_date_valid(id_number(body, "1900", "0001", "000"), today))
        self.assertFalse(id_birth_date_valid(id_number(body, "2000", "1301", "000"), today))


_ID_W = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_ID_MAP = "10X98765432"


def id_number(template: str, year: str, month_day: str, seq: str) -> str:
    body = template.format(date=year + month_day, seq=seq)
    return body + _ID_MAP[sum(int(d) * w for d, w in zip(body, _ID_W)) % 11]


class PhoneRecognizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.recognizer = CnPhoneRecognizer()

    def assert_spans(self, text: str, spans: list[Span]) -> None:
        self.assertEqual(analyze_text(text, [self.recognizer]), tuple(spans))

    def test_contiguous_number_hits_with_exact_span(self) -> None:
        self.assert_spans(
            "联系电话13812345678，请尽快回复",
            [Span(4, 15, PHONE_NUMBER, 3)],
        )

    def test_all_supported_segments_hit(self) -> None:
        for segment_prefix in ("13", "14", "15", "16", "17", "18", "19"):
            text = f"号码{segment_prefix}123456789在文中"
            spans = analyze_text(text, [self.recognizer])
            self.assertEqual(len(spans), 1, text)
            self.assertEqual((spans[0].start, spans[0].end), (2, 13))

    def test_hyphen_and_space_separated_hit_covering_separators(self) -> None:
        self.assert_spans("拨138-1234-5678", [Span(1, 14, PHONE_NUMBER, 3)])
        self.assert_spans("拨138 1234 5678", [Span(1, 14, PHONE_NUMBER, 3)])

    def test_non_mobile_prefixes_miss(self) -> None:
        for text in ("10123456789", "12123456789", "11123456789", "12345678901"):
            self.assert_spans(f"号码{text}", [])

    def test_wrong_lengths_miss(self) -> None:
        self.assert_spans("短号1381234567", [])
        self.assert_spans("长号138123456789", [])

    def test_landline_misses(self) -> None:
        self.assert_spans("固话010-12345678", [])
        self.assert_spans("固话0571-87654321", [])

    def test_plain_serial_misses(self) -> None:
        self.assert_spans("订单编号20240012345678", [])

    def test_embedded_in_longer_digit_string_misses(self) -> None:
        self.assert_spans("串913812345678含号", [])
        self.assert_spans("串138123456780含号", [])
        self.assert_spans("串9138123456789含号", [])

    def test_letter_glued_still_hits_by_rule(self) -> None:
        spans = analyze_text("call13812345678now", [self.recognizer])
        self.assertEqual(spans, (Span(4, 15, PHONE_NUMBER, 3),))


class IdNumberRecognizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.recognizer = CnIdNumberRecognizer(today=date(2024, 6, 1))

    def assert_spans(self, text: str, spans: list[Span]) -> None:
        self.assertEqual(analyze_text(text, [self.recognizer]), tuple(spans))

    def test_valid_synthetic_number_hits(self) -> None:
        number = id_number("990101{date}{seq}", "1990", "0307", "758")
        self.assertTrue(id_check_digit_valid(number))
        self.assert_spans(f"证件{number}", [Span(2, 20, CN_ID_NUMBER, 3)])

    def test_wrong_check_digit_does_not_validate(self) -> None:
        number = id_number("990101{date}{seq}", "1990", "0307", "758")
        wrong = number[:-1] + ("0" if number[-1] != "0" else "1")
        self.assertFalse(id_check_digit_valid(wrong))
        self.assert_spans(f"证件{wrong}", [])

    def test_illegal_dates_miss_even_with_valid_check_digit(self) -> None:
        for year, md in (("1990", "1307"), ("1990", "0230"), ("1991", "0229"), ("1990", "0332")):
            number = id_number("990101{date}{seq}", year, md, "758")
            self.assertTrue(id_check_digit_valid(number), number)
            self.assertFalse(id_birth_date_valid(number, date(2024, 6, 1)), number)
            self.assert_spans(f"证件{number}", [])

    def test_year_bounds_miss(self) -> None:
        low = id_number("990101{date}{seq}", "1899", "0307", "758")
        high = id_number("990101{date}{seq}", "2099", "0307", "758")
        for number in (low, high):
            self.assertTrue(id_check_digit_valid(number), number)
            self.assert_spans(f"证件{number}", [])

    def test_wrong_lengths_and_embedding_miss(self) -> None:
        number = id_number("990101{date}{seq}", "1990", "0307", "758")
        self.assert_spans(f"号{number[:-1]}", [])
        self.assert_spans(f"号{number}0", [])
        self.assert_spans(f"x{number}Y", [])

    def test_lowercase_x_check_digit_misses(self) -> None:
        body = "99010119900307004"
        self.assertEqual(_ID_MAP[sum(int(d) * w for d, w in zip(body, _ID_W)) % 11], "X")
        self.assert_spans(f"证件{body}x", [])


class UsccRecognizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.recognizer = CnUsccRecognizer()

    def assert_spans(self, text: str, spans: list[Span]) -> None:
        self.assertEqual(analyze_text(text, [self.recognizer]), tuple(spans))

    def test_valid_synthetic_codes_hit(self) -> None:
        self.assert_spans("代码91110000000000000E", [Span(2, 20, CN_USCC, 3)])

    def test_wrong_check_digit_misses(self) -> None:
        self.assert_spans("代码911100000000000000", [])

    def test_illegal_charset_characters_miss(self) -> None:
        code = "91110000000000000E"
        for bad in ("I", "O", "Z", "S", "V"):
            tampered = code[:2] + bad + code[3:]
            self.assertEqual(len(tampered), 18)
            self.assertFalse(uscc_valid(tampered))
            self.assert_spans(f"代码{tampered}", [])

    def test_lowercase_misses(self) -> None:
        self.assert_spans("代码91110000000000000e", [])

    def test_wrong_lengths_and_embedding_miss(self) -> None:
        code = "91110000000000000E"
        self.assert_spans(f"码{code[:-1]}", [])
        self.assert_spans(f"码{code}A", [])
        self.assert_spans(f"a{code}9", [])


class PresidioOffsetContractTests(unittest.TestCase):
    """证明 presidio RecognizerResult.start/end 在中文/补充平面字符
    上下文中就是 Python code point 偏移（UTF-16 长度会不同）。"""

    def test_cjk_context_offsets_are_code_points(self) -> None:
        text = "甲之手机号乃13812345678也"
        prefix_length = len("甲之手机号乃")
        self.assertEqual(prefix_length, 6)
        results = CnPhoneRecognizer().analyze(text, entities=None, nlp_artifacts=None)
        self.assertEqual(len(results), 1)
        self.assertEqual((results[0].start, results[0].end), (prefix_length, prefix_length + 11))
        self.assertEqual(text[results[0].start:results[0].end], "13812345678")

    def test_astral_character_counts_as_one_code_point(self) -> None:
        # 😀 与 𠀀 都是增补平面字符：Python len 计 1（UTF-16 计 2）。
        text = "😀𠀀中13812345678尾"
        prefix = "😀𠀀中"
        self.assertEqual(len(prefix), 3)
        spans = analyze_text(text, [CnPhoneRecognizer()])
        self.assertEqual(spans, (Span(3, 14, PHONE_NUMBER, 3),))


class OrchestrationTests(unittest.TestCase):
    def test_default_recognizers_detect_all_three_entities(self) -> None:
        number = id_number("990101{date}{seq}", "1990", "0307", "758")
        text = f"手机13812345678证件{number}代码91110000000000000E"
        spans = analyze_text(text)
        self.assertEqual(
            spans,
            (
                Span(2, 13, PHONE_NUMBER, 3),
                Span(15, 33, CN_ID_NUMBER, 3),
                Span(35, 53, CN_USCC, 3),
            ),
        )

    def test_output_sorted_and_deterministic(self) -> None:
        number = id_number("990101{date}{seq}", "1990", "0307", "758")
        text = f"代码91110000000000000E手机13812345678证件{number}"
        first = analyze_text(text)
        second = analyze_text(text, list(reversed(default_recognizers())))
        self.assertEqual(first, second)
        starts = [span.start for span in first]
        self.assertEqual(starts, sorted(starts))

    def test_empty_text_has_no_spans(self) -> None:
        self.assertEqual(analyze_text(""), ())

    def test_spans_merge_with_spans_module_contract(self) -> None:
        from detection.spans import merge_spans

        text = "手机号13812345678"
        spans = analyze_text(text)
        merged = merge_spans(spans, text_length=len(text))
        self.assertEqual(merged, spans)


class FixtureDrivenTests(unittest.TestCase):
    def check_fixture(self, task: str) -> None:
        doc = load_cases(task)
        self.assertTrue(doc["synthetic"])
        recognizers = {
            "PHONE_NUMBER": CnPhoneRecognizer(),
            "CN_ID_NUMBER": CnIdNumberRecognizer(),
            "CN_USCC": CnUsccRecognizer(),
        }
        recognizer = recognizers[doc["entity_type"]]
        hits = 0
        for case in doc["cases"]:
            with self.subTest(case=case["id"]):
                spans = analyze_text(case["text"], [recognizer])
                if case["expect"] == "hit":
                    hits += 1
                    expected = tuple(
                        Span(s["start"], s["end"], s["entity_type"], 3) for s in case["spans"]
                    )
                    self.assertEqual(spans, expected)
                else:
                    self.assertEqual(spans, ())
        self.assertGreater(hits, 0, f"{task} fixture must contain positive hits")

    def test_phone_fixture(self) -> None:
        self.check_fixture("phone")

    def test_id_card_fixture(self) -> None:
        self.check_fixture("id_card")

    def test_uscc_fixture(self) -> None:
        self.check_fixture("uscc")


class SecretRecognizerTests(unittest.TestCase):
    """秘密识别器测试：API Key / PEM 私钥块 / 政策密码上下文。"""

    def setUp(self) -> None:
        self.recognizer = SecretRecognizer()

    def assert_spans(self, text: str, spans: list[Span]) -> None:
        self.assertEqual(analyze_text(text, [self.recognizer]), tuple(spans))

    def test_api_key_prefixes_hit_with_exact_chinese_prefix_offsets(self) -> None:
        for prefix, key in (
            ("在配置中写入 ", "sk-AbCdEfG0123456789xyz"),
            ("使用 ", "ak-9f8e7d6c5b4a3210ZxQw"),
        ):
            text = prefix + key + " 保存"
            start = len(prefix)
            self.assert_spans(text, [Span(start, start + len(key), SECRET, 0)])

    def test_api_key_short_body_and_bad_charset_miss(self) -> None:
        self.assert_spans("密钥 sk-AbC123 不可用", [])
        self.assert_spans("密钥 sk-AbCd_Ef0123456789xyz 非法", [])

    def test_api_key_doc_placeholders_miss(self) -> None:
        for text in (
            "示例 sk-exampleAbCdEf012345 勿用",
            "示例 sk-xxxxxxxxxxxxxxxxAbC 勿用",
            "示例 ak-yourKeyGoesHere0123 勿用",
        ):
            self.assert_spans(text, [])

    def test_api_key_embedded_in_alnum_misses(self) -> None:
        # 前缀前紧邻字母数字（嵌入更长串）不命中。
        self.assert_spans("串xsk-AbCdEfG0123456789xyz后缀", [])
        self.assert_spans("串9sk-AbCdEfG0123456789xyz后缀", [])
        # 尾侧字母数字会被主体字符集整体吞入（主体贪心），整块仍是一个密钥命中。
        text = "串sk-AbCdEfG0123456789xyzY后缀"
        self.assert_spans(text, [Span(1, 25, SECRET, 0)])

    def test_pem_block_hit_covers_whole_block_with_chinese_prefix(self) -> None:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
        ).decode("utf-8")
        self.assertIn("-----BEGIN RSA PRIVATE KEY-----", pem)
        text = "服务器密钥如下\n" + pem + "完"
        spans = analyze_text(text, [self.recognizer])
        begin = text.index("-----BEGIN")
        end = text.index("-----END RSA PRIVATE KEY-----") + len("-----END RSA PRIVATE KEY-----")
        self.assertEqual(spans, (Span(begin, end, SECRET, 0),))

    def test_pem_pkcs8_without_algo_hit(self) -> None:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        ).decode("utf-8")
        self.assertIn("-----BEGIN PRIVATE KEY-----", pem)
        spans = analyze_text("备份\n" + pem, [self.recognizer])
        self.assertEqual(len(spans), 1)
        self.assertEqual(spans[0].entity_type, SECRET)
        self.assertEqual(spans[0].priority, 0)

    def test_pem_mismatched_algo_and_placeholder_miss(self) -> None:
        self.assert_spans(
            "-----BEGIN RSA PRIVATE KEY-----\na1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V2w3X4y5Z6\n-----END EC PRIVATE KEY-----",
            [],
        )
        self.assert_spans(
            "-----BEGIN RSA PRIVATE KEY-----\nyourprivatekeymaterialhere\n-----END RSA PRIVATE KEY-----",
            [],
        )

    def test_password_contexts_hit_value_only_span(self) -> None:
        for prefix, value in (
            ("数据库密码：", "P@ssw0rd!2024"),
            ("系统口令=", "z9X8c7v6B5nMq"),
            ("账号password:", "x9Y8z7w6V5"),
            ("登录密码: ", "Qw3r!ty9Ui"),
        ):
            text = prefix + value
            start = len(prefix)
            self.assert_spans(text, [Span(start, start + len(value), SECRET, 0)])

    def test_password_json_form_hit_inside_quotes(self) -> None:
        text = '{"password":"kJ9#mQ2vL8p"}'
        start = text.index("kJ9#mQ2vL8p")
        self.assert_spans(text, [Span(start, start + 11, SECRET, 0)])

    def test_password_empty_value_misses(self) -> None:
        self.assert_spans("数据库密码：，请设置", [])
        self.assert_spans("password=，未设置", [])
        self.assert_spans("口令：。立即修改", [])

    def test_password_undefined_context_misses(self) -> None:
        for text in (
            "pwd=S3cret!value",
            "密碼：S3cret!value",
            "pass=S3cret!value",
            "密码是S3cret!value",
        ):
            self.assert_spans(text, [])

    def test_password_doc_example_misses(self) -> None:
        for text in ("password=example", "密码：example123", '口令="test"'):
            self.assert_spans(text, [])

    def test_secret_spans_priority_zero_blocks_merge(self) -> None:
        from detection.spans import merge_spans

        text = "密码：S3cret!value"
        spans = analyze_text(text)
        self.assertEqual(spans, (Span(3, len(text), SECRET, 0),))
        with self.assertRaises(SafetyError) as caught:
            merge_spans(spans, text_length=len(text))
        self.assertEqual(caught.exception.code, SafetyCode.SECRET_DETECTED)

    def test_validators_with_default_policy(self) -> None:
        policy = SecretPolicy()
        self.assertTrue(api_key_secret_valid("sk-AbCdEfG0123456789xyz", policy))
        self.assertFalse(api_key_secret_valid("sk-AbCdEfG0123456789example", policy))
        self.assertTrue(password_value_valid("S3cret!value", policy))
        self.assertFalse(password_value_valid("example", policy))

    def test_custom_policy_vocab_and_prefix_parameterized(self) -> None:
        policy = SecretPolicy(
            api_key_prefixes=("pk-",),
            password_contexts=("口令", "密碼"),
            placeholder_markers=("example",),
        )
        recognizer = SecretRecognizer(policy=policy)
        text = "密碼：S3cret!value"
        start = len("密碼：")
        self.assertEqual(
            analyze_text(text, [recognizer]),
            (Span(start, start + len("S3cret!value"), SECRET, 0),),
        )
        self.assertEqual(analyze_text("密码：S3cret!value", [recognizer]), ())
        self.assertEqual(
            analyze_text("pk-AbCdEfG0123456789xyz", [recognizer]),
            (Span(0, 23, SECRET, 0),),
        )
        self.assertEqual(analyze_text("sk-AbCdEfG0123456789xyz", [recognizer]), ())

    def test_custom_policy_separators_parameterized(self) -> None:
        policy = SecretPolicy(password_contexts=("密码",), password_separators=("~",))
        recognizer = SecretRecognizer(policy=policy)
        text = "密码~S3cret!value"
        start = len("密码~")
        self.assertEqual(
            analyze_text(text, [recognizer]),
            (Span(start, start + len("S3cret!value"), SECRET, 0),),
        )
        self.assertEqual(analyze_text("密码：S3cret!value", [recognizer]), ())

    def test_invalid_policy_configs_rejected(self) -> None:
        for build in (
            lambda: SecretPolicy(api_key_prefixes=()),
            lambda: SecretPolicy(api_key_prefixes="sk-"),
            lambda: SecretPolicy(api_key_min_body_length=0),
            lambda: SecretPolicy(api_key_min_body_length=True),
            lambda: SecretPolicy(api_key_body_chars=("ab",)),
            lambda: SecretPolicy(password_contexts=("密码", "")),
            lambda: SecretPolicy(password_separators=()),
            lambda: SecretPolicy(password_separators=("::",)),
            lambda: SecretPolicy(placeholder_markers=()),
            lambda: SecretRecognizer(policy=MoneyPolicy()),
        ):
            with self.assertRaises(SafetyError) as caught:
                build()
            self.assertEqual(caught.exception.code, SafetyCode.INVALID_RECOGNIZER)

    def test_config_error_messages_have_no_business_text(self) -> None:
        try:
            SecretRecognizer(policy=123)
        except SafetyError as exc:
            self.assertEqual(exc.code, SafetyCode.INVALID_RECOGNIZER)
            self.assertEqual(str(exc), "INVALID_RECOGNIZER (policy)")
        else:
            self.fail("expected SafetyError")


class MoneyAmountRecognizerTests(unittest.TestCase):
    """金额识别器测试：政策符号/单位/语境约束。"""

    def setUp(self) -> None:
        self.recognizer = MoneyAmountRecognizer()

    def assert_spans(self, text: str, spans: list[Span]) -> None:
        self.assertEqual(analyze_text(text, [self.recognizer]), tuple(spans))

    def test_symbol_before_and_after_hit(self) -> None:
        for prefix, value in (
            ("服务费", "¥3500元"),
            ("报价", "$1,234,567.89"),
            ("尾款", "€2500.75"),
            ("总价", "100$"),
        ):
            text = prefix + value
            start = len(prefix)
            self.assert_spans(text, [Span(start, start + len(value), MONEY_AMOUNT, 3)])

    def test_unit_after_and_prefix_unit_hit(self) -> None:
        for prefix, value in (
            ("赔偿", "3.5万元"),
            ("按", "美元800"),
            ("总价款为", "人民币12万元"),
            ("押金", "500元"),
        ):
            text = prefix + value
            start = len(prefix)
            self.assert_spans(text, [Span(start, start + len(value), MONEY_AMOUNT, 3)])

    def test_context_bare_number_hit_with_exact_span(self) -> None:
        for prefix, value in (
            ("合同金额：", "50000"),
            ("违约金 ", "2500"),
            ("定金:", "8000"),
        ):
            text = prefix + value
            start = len(prefix)
            self.assert_spans(text, [Span(start, start + len(value), MONEY_AMOUNT, 3)])

    def test_year_chapter_serial_plain_miss(self) -> None:
        for text in (
            "2026年预算已批",
            "详见第3.2节规定",
            "数量为5000个",
            "编号A-2026-001",
            "版本v2.5发布",
        ):
            self.assert_spans(text, [])

    def test_era_yuan_and_context_year_miss(self) -> None:
        self.assert_spans("公元2026年建成", [])
        self.assert_spans("违约金：2026年支付", [])
        self.assert_spans("合同金额：2026-01-01", [])

    def test_malformed_amount_miss(self) -> None:
        self.assert_spans("金额12,34元", [])
        self.assert_spans("价格¥1,23元", [])

    def test_context_glued_bare_number_misses_without_separator(self) -> None:
        # 语境词后裸数字必须经显式分隔符（冒号或空白）；"金额5000"不命中。
        self.assert_spans("违约金5000", [])
        # 带符号/单位的仍由符号/单位分支命中。
        self.assert_spans("违约金5000元", [Span(3, 8, MONEY_AMOUNT, 3)])

    def test_custom_policy_symbols_and_contexts(self) -> None:
        policy = MoneyPolicy(symbols=("₿",), contexts=("价款",))
        recognizer = MoneyAmountRecognizer(policy=policy)
        self.assertEqual(analyze_text("支付₿3.5", [recognizer]), (Span(2, 6, MONEY_AMOUNT, 3),))
        self.assertEqual(analyze_text("价款：100", [recognizer]), (Span(3, 6, MONEY_AMOUNT, 3),))
        self.assertEqual(analyze_text("合同金额：100", [recognizer]), ())
        self.assertEqual(analyze_text("支付¥100", [recognizer]), ())

    def test_invalid_policy_rejected(self) -> None:
        for build in (
            lambda: MoneyPolicy(symbols=()),
            lambda: MoneyPolicy(symbols=("人民币",)),
            lambda: MoneyPolicy(units=()),
            lambda: MoneyPolicy(contexts=("金额", "")),
            lambda: MoneyAmountRecognizer(policy=SecretPolicy()),
        ):
            with self.assertRaises(SafetyError) as caught:
                build()
            self.assertEqual(caught.exception.code, SafetyCode.INVALID_RECOGNIZER)

    def test_money_amount_valid_with_default_policy(self) -> None:
        policy = MoneyPolicy()
        self.assertTrue(money_amount_valid("¥3500元", policy))
        self.assertTrue(money_amount_valid("50000", policy))
        self.assertFalse(money_amount_valid("¥五十", policy))


class AccountNumberRecognizerTests(unittest.TestCase):
    """账号识别器测试：政策语境词 + 政策长度区间。"""

    def setUp(self) -> None:
        self.recognizer = AccountNumberRecognizer()

    def assert_spans(self, text: str, spans: list[Span]) -> None:
        self.assertEqual(analyze_text(text, [self.recognizer]), tuple(spans))

    def test_context_accounts_hit_with_exact_chinese_prefix(self) -> None:
        for prefix, value in (
            ("请汇入银行账号：", "6222021001112345678"),
            ("卡号", "6222020200112233"),
            ("账号", "123456789"),
            ("收款账号 ", "987654321"),
        ):
            text = prefix + value
            start = len(prefix)
            self.assert_spans(text, [Span(start, start + len(value), ACCOUNT_NUMBER, 3)])

    def test_length_boundaries(self) -> None:
        self.assert_spans("账号1234567", [])
        self.assert_spans("账号12345678", [Span(2, 10, ACCOUNT_NUMBER, 3)])
        self.assert_spans("账户" + "1" * 30, [Span(2, 32, ACCOUNT_NUMBER, 3)])
        self.assert_spans("账号" + "1" * 31, [])

    def test_embedded_in_longer_digit_string_misses(self) -> None:
        self.assert_spans("串62220210011123456780尾", [])
        self.assert_spans("串06222021001112345678尾", [])

    def test_no_context_plain_numbers_miss(self) -> None:
        for text in (
            "6222021001112345678",
            "流水号20240001234567",
            "订单2024000100123456",
            "户名：张三",
        ):
            self.assert_spans(text, [])

    def test_custom_policy_bounds_parameterized(self) -> None:
        policy = AccountPolicy(contexts=("客户号",), min_digits=5, max_digits=10)
        recognizer = AccountNumberRecognizer(policy=policy)
        self.assertEqual(analyze_text("客户号12345", [recognizer]), (Span(3, 8, ACCOUNT_NUMBER, 3),))
        self.assertEqual(analyze_text("账号12345", [recognizer]), ())
        self.assertEqual(analyze_text("客户号1234", [recognizer]), ())
        self.assertEqual(analyze_text("客户号" + "1" * 11, [recognizer]), ())

    def test_invalid_policy_rejected(self) -> None:
        for build in (
            lambda: AccountPolicy(contexts=()),
            lambda: AccountPolicy(min_digits=0),
            lambda: AccountPolicy(min_digits=12, max_digits=8),
            lambda: AccountNumberRecognizer(policy=MoneyPolicy()),
        ):
            with self.assertRaises(SafetyError) as caught:
                build()
            self.assertEqual(caught.exception.code, SafetyCode.INVALID_RECOGNIZER)

    def test_account_number_valid_with_default_policy(self) -> None:
        policy = AccountPolicy()
        self.assertTrue(account_number_valid("12345678", policy))
        self.assertFalse(account_number_valid("1234567", policy))
        self.assertFalse(account_number_valid("123a5678", policy))


class ContractNumberRecognizerTests(unittest.TestCase):
    """合同编号识别器测试：政策语境词 + 政策格式。"""

    def setUp(self) -> None:
        self.recognizer = ContractNumberRecognizer()

    def assert_spans(self, text: str, spans: list[Span]) -> None:
        self.assertEqual(analyze_text(text, [self.recognizer]), tuple(spans))

    def test_context_codes_hit_with_exact_chinese_prefix(self) -> None:
        for prefix, value in (
            ("合同编号：", "HT-2026-001"),
            ("本协议编号 ", "XY-2025-123456"),
            ("合同号", "AB-2024-0001"),
        ):
            text = prefix + value
            start = len(prefix)
            self.assert_spans(text, [Span(start, start + len(value), CONTRACT_NUMBER, 3)])

    def test_format_and_context_misses(self) -> None:
        for text in (
            "编号HT-2026-001待查",
            "合同编号：HT-2026-01",
            "合同编号：HT-2026-001X",
            "合同编号：ht-2026-001",
            "合同编号：H-2026-001",
            "合同编号：ABCDE-2026-001",
            "航班号CA-2026-088已起飞",
            "合同编号：HT-2026-001-02",
        ):
            self.assert_spans(text, [])

    def test_custom_policy_format_parameterized(self) -> None:
        policy = ContractPolicy(contexts=("采购单号",), prefix_min_letters=3, prefix_max_letters=3, seq_min_digits=4, seq_max_digits=4)
        recognizer = ContractNumberRecognizer(policy=policy)
        self.assertEqual(
            analyze_text("采购单号ABC-2026-0001", [recognizer]),
            (Span(4, 17, CONTRACT_NUMBER, 3),),
        )
        self.assertEqual(analyze_text("合同编号ABC-2026-0001", [recognizer]), ())
        self.assertEqual(analyze_text("采购单号AB-2026-0001", [recognizer]), ())
        self.assertEqual(analyze_text("采购单号ABC-2026-001", [recognizer]), ())

    def test_invalid_policy_rejected(self) -> None:
        for build in (
            lambda: ContractPolicy(contexts=()),
            lambda: ContractPolicy(prefix_min_letters=0),
            lambda: ContractPolicy(prefix_min_letters=5, prefix_max_letters=2),
            lambda: ContractNumberRecognizer(policy=AccountPolicy()),
        ):
            with self.assertRaises(SafetyError) as caught:
                build()
            self.assertEqual(caught.exception.code, SafetyCode.INVALID_RECOGNIZER)

    def test_contract_number_valid_with_default_policy(self) -> None:
        policy = ContractPolicy()
        self.assertTrue(contract_number_valid("HT-2026-001", policy))
        self.assertFalse(contract_number_valid("ht-2026-001", policy))
        self.assertFalse(contract_number_valid("H-2026-001", policy))


class PolicyFixtureTests(unittest.TestCase):
    """综合夹具驱动测试（含跨度优先级断言）。"""

    RECOGNIZERS = {
        "SECRET": (SecretRecognizer, 0),
        "MONEY_AMOUNT": (MoneyAmountRecognizer, 3),
        "ACCOUNT_NUMBER": (AccountNumberRecognizer, 3),
        "CONTRACT_NUMBER": (ContractNumberRecognizer, 3),
    }

    def check_fixture(self, task: str) -> None:
        doc = load_cases(task)
        self.assertTrue(doc["synthetic"])
        factory, default_priority = self.RECOGNIZERS[doc["entity_type"]]
        recognizer = factory()
        hits = 0
        for case in doc["cases"]:
            with self.subTest(case=case["id"]):
                spans = analyze_text(case["text"], [recognizer])
                if case["expect"] == "hit":
                    hits += 1
                    expected = tuple(
                        Span(
                            s["start"],
                            s["end"],
                            s["entity_type"],
                            s.get("priority", default_priority),
                        )
                        for s in case["spans"]
                    )
                    self.assertEqual(spans, expected)
                else:
                    self.assertEqual(spans, ())
        self.assertGreater(hits, 0, f"{task} fixture must contain positive hits")

    def test_secret_fixture(self) -> None:
        self.check_fixture("secret")

    def test_money_fixture(self) -> None:
        self.check_fixture("money")

    def test_account_fixture(self) -> None:
        self.check_fixture("account")

    def test_contract_fixture(self) -> None:
        self.check_fixture("contract")


class PolicyOrchestrationTests(unittest.TestCase):
    def test_default_recognizers_include_policy_recognizers(self) -> None:
        recognizers = default_recognizers()
        self.assertEqual(len(recognizers), 7)
        self.assertIsInstance(recognizers[0], SecretRecognizer)

    def test_default_chain_detects_across_new_entities(self) -> None:
        text = "手机13812345678合同金额：¥5000合同编号：HT-2026-001"
        spans = analyze_text(text)
        self.assertEqual(
            spans,
            (
                Span(2, 13, PHONE_NUMBER, 3),
                Span(18, 23, MONEY_AMOUNT, 3),
                Span(28, 39, CONTRACT_NUMBER, 3),
            ),
        )

    def test_default_chain_secret_blocks_merge(self) -> None:
        from detection.spans import merge_spans

        text = "数据库密码：P@ssw0rd!2024"
        spans = analyze_text(text)
        self.assertEqual(spans, (Span(6, 19, SECRET, 0),))
        with self.assertRaises(SafetyError) as caught:
            merge_spans(spans, text_length=len(text))
        self.assertEqual(caught.exception.code, SafetyCode.SECRET_DETECTED)


class ControlledFailureTests(unittest.TestCase):
    def assert_blocked(self, code: SafetyCode, fn) -> None:
        with self.assertRaises(SafetyError) as caught:
            fn()
        self.assertEqual(caught.exception.code, code)

    def test_non_str_text_rejected(self) -> None:
        for payload in (123, b"13812345678", None, ["13812345678"]):
            self.assert_blocked(SafetyCode.INVALID_TEXT, lambda p=payload: analyze_text(p))

    def test_non_str_text_error_message_has_no_business_text(self) -> None:
        try:
            analyze_text(b"13812345678")
        except SafetyError as exc:
            self.assertNotIn("13812345678", str(exc))
        else:
            self.fail("expected SafetyError")

    def test_invalid_recognizer_configs_rejected(self) -> None:
        self.assert_blocked(SafetyCode.INVALID_RECOGNIZER, lambda: CnPhoneRecognizer(name=""))
        self.assert_blocked(SafetyCode.INVALID_RECOGNIZER, lambda: CnPhoneRecognizer(name=123))
        self.assert_blocked(SafetyCode.INVALID_RECOGNIZER, lambda: CnPhoneRecognizer(score=0))
        self.assert_blocked(SafetyCode.INVALID_RECOGNIZER, lambda: CnPhoneRecognizer(score=1.5))
        self.assert_blocked(SafetyCode.INVALID_RECOGNIZER, lambda: CnPhoneRecognizer(score=True))
        self.assert_blocked(
            SafetyCode.INVALID_RECOGNIZER,
            lambda: CnIdNumberRecognizer(today="2024-01-01"),
        )
        self.assert_blocked(
            SafetyCode.INVALID_RECOGNIZER,
            lambda: CnIdNumberRecognizer(today=datetime(2024, 1, 1)),
        )

    def test_private_base_validates_entity_and_patterns(self) -> None:
        pattern = Pattern("p", r"\d+", 1.0)
        self.assert_blocked(
            SafetyCode.INVALID_RECOGNIZER,
            lambda: _CnPatternRecognizer(
                supported_entity="phone", name="X", patterns=(pattern,), score=1.0
            ),
        )
        self.assert_blocked(
            SafetyCode.INVALID_RECOGNIZER,
            lambda: _CnPatternRecognizer(
                supported_entity="PHONE_NUMBER", name="X", patterns=(), score=1.0
            ),
        )
        self.assert_blocked(
            SafetyCode.INVALID_RECOGNIZER,
            lambda: _CnPatternRecognizer(
                supported_entity="PHONE_NUMBER",
                name="X",
                patterns=(Pattern("p", "", 1.0),),
                score=1.0,
            ),
        )

    def test_config_error_messages_have_no_business_text(self) -> None:
        try:
            CnIdNumberRecognizer(today="13812345678")
        except SafetyError as exc:
            self.assertEqual(exc.code, SafetyCode.INVALID_RECOGNIZER)
            self.assertNotIn("13812345678", str(exc))
        else:
            self.fail("expected SafetyError")

    def test_non_recognizer_in_orchestration_rejected(self) -> None:
        self.assert_blocked(
            SafetyCode.INVALID_RECOGNIZER,
            lambda: analyze_text("text", recognizers=[object()]),
        )
        self.assert_blocked(
            SafetyCode.INVALID_RECOGNIZER,
            lambda: analyze_text("text", recognizers=object()),
        )
        self.assertIsInstance(CnPhoneRecognizer(), EntityRecognizer)


if __name__ == "__main__":
    unittest.main()
