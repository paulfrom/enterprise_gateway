"""Tests for P-08 branch streaming restorer with token defragmentation."""

from __future__ import annotations

import unittest

from infra.errors import SafetyCode, SafetyError
from masking.mapping import MappingContext
from masking.stream_restorer import BranchStreamingRestorer

TEST_HMAC_KEY = b"secure-stream-test-key-32bytes!!"


class TestBranchStreamingRestorer(unittest.TestCase):
    def test_every_character_and_all_two_part_splits(self) -> None:
        with MappingContext("corp.test", "v1", TEST_HMAC_KEY) as ctx:
            token = ctx.token_for("ORG", "SYNTHETIC_ORG")
            for chunks in ([*token], *([token[:i], token[i:]] for i in range(len(token) + 1))):
                restorer = BranchStreamingRestorer(ctx)
                output = "".join(restorer.feed("b", chunk) for chunk in chunks)
                output += restorer.finalize("b")
                self.assertEqual("SYNTHETIC_ORG", output)

    def setUp(self) -> None:
        self.domain = "corp.test"

    def test_single_chunk_token_restoration(self) -> None:
        """Complete token in a single delta is restored immediately."""
        with MappingContext(self.domain, "v1", TEST_HMAC_KEY) as ctx:
            token = ctx.token_for("ORG", "阿尔法科技")
            restorer = BranchStreamingRestorer(ctx)

            chunk = f"已收到关于 {token} 的查询。"
            out = restorer.feed("b0", chunk)
            out += restorer.finalize("b0")
            self.assertEqual("已收到关于 阿尔法科技 的查询。", out)

    def test_split_token_across_multiple_chunks(self) -> None:
        """Token split across 3 chunks is buffered and restored atomically."""
        with MappingContext(self.domain, "v1", TEST_HMAC_KEY) as ctx:
            token = ctx.token_for("PER", "张三")
            restorer = BranchStreamingRestorer(ctx)

            # Split token into 3 parts
            part1 = token[:8]
            part2 = token[8:20]
            part3 = token[20:]

            out1 = restorer.feed("b0", f"员工编号：{part1}")
            self.assertEqual("员工编号：", out1)  # Token prefix is buffered!

            out2 = restorer.feed("b0", part2)
            self.assertEqual("", out2)  # Still buffering!

            out3 = restorer.feed("b0", f"{part3} 已打卡。")
            self.assertEqual(f"张三 已打卡。", out3)  # Restored atomically!

            out4 = restorer.finalize("b0")
            self.assertEqual("", out4)

    def test_branch_isolation(self) -> None:
        """Multiple parallel branches maintain strictly independent buffers."""
        with MappingContext(self.domain, "v1", TEST_HMAC_KEY) as ctx:
            token_a = ctx.token_for("ORG", "公司甲")
            token_b = ctx.token_for("ORG", "公司乙")
            restorer = BranchStreamingRestorer(ctx)

            # Feed partial token to branch 0
            restorer.feed("branch_0", f"A: {token_a[:10]}")
            # Feed complete token to branch 1
            out_b = restorer.feed("branch_1", f"B: {token_b}")
            self.assertEqual("B: 公司乙", out_b)

            # Complete branch 0
            out_a = restorer.feed("branch_0", token_a[10:])
            self.assertEqual("公司甲", out_a)

    def test_unknown_token_fails_closed(self) -> None:
        """Token with valid syntax but unknown value fails closed."""
        with MappingContext(self.domain, "v1", TEST_HMAC_KEY) as ctx:
            restorer = BranchStreamingRestorer(ctx)
            fake_token = f"<<ENT_v1_{'0' * 32}>>"
            with self.assertRaises(SafetyError) as exc_info:
                restorer.feed("b0", fake_token)
            self.assertEqual(SafetyCode.UNKNOWN_TOKEN, exc_info.exception.code)

    def test_malformed_token_fails_closed(self) -> None:
        """Malformed token syntax fails closed."""
        with MappingContext(self.domain, "v1", TEST_HMAC_KEY) as ctx:
            restorer = BranchStreamingRestorer(ctx)
            bad_token = "<<ENT_invalid_token>>"
            with self.assertRaises(SafetyError) as exc_info:
                restorer.feed("b0", bad_token)
            self.assertEqual(SafetyCode.MALFORMED_TOKEN, exc_info.exception.code)

    def test_tail_truncation_fails_closed(self) -> None:
        """Stream terminating with incomplete token prefix fails closed on finalize."""
        with MappingContext(self.domain, "v1", TEST_HMAC_KEY) as ctx:
            restorer = BranchStreamingRestorer(ctx)
            restorer.feed("b0", "结果如下：<<ENT_v1_abcd")
            with self.assertRaises(SafetyError) as exc_info:
                restorer.finalize("b0")
            self.assertEqual(SafetyCode.MALFORMED_TOKEN, exc_info.exception.code)

    def test_cancel_branch_cleans_up_resources(self) -> None:
        """P-14: Canceling branch removes buffered state."""
        with MappingContext(self.domain, "v1", TEST_HMAC_KEY) as ctx:
            restorer = BranchStreamingRestorer(ctx)
            restorer.feed("b0", "Partial <<ENT_v1_")
            restorer.cancel_branch("b0")
            # Finalize after cancel returns empty string without error
            self.assertEqual("", restorer.finalize("b0"))


if __name__ == "__main__":
    unittest.main()
