"""Tests for P-09 and P-10 bounded tool call parameter buffer and release verifier."""

from __future__ import annotations

import json
import unittest

from pydantic import BaseModel, ConfigDict

from infra.errors import SafetyCode, SafetyError
from masking.mapping import MappingContext
from protocol.tool_buffer import (
    BoundedToolCallBuffer,
    MAX_SINGLE_TOOL_BYTES,
)

TEST_HMAC_KEY = b"secure-tool-test-key-32bytes!!!!"


class QueryToolArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    query: str
    limit: int


class TestToolCallBuffer(unittest.TestCase):
    def setUp(self) -> None:
        self.domain = "corp.test"
        self.buffer = BoundedToolCallBuffer()

    def test_p09_exact_boundary_budget(self) -> None:
        """P-09: 65536 bytes is allowed; 65537 bytes triggers ADMISSION_LIMIT_EXCEEDED."""
        self.buffer.register_tool("call_1", "search")

        # 65535 bytes is within budget
        chunk_65535 = b"a" * (MAX_SINGLE_TOOL_BYTES - 1)
        self.buffer.feed_argument_delta("call_1", chunk_65535)

        # 1 additional byte reaches exact 65536 bytes
        self.buffer.feed_argument_delta("call_1", b"a")

        # 1 more byte exceeds budget (65537)
        with self.assertRaises(SafetyError) as exc_info:
            self.buffer.feed_argument_delta("call_1", b"a")
        self.assertEqual(SafetyCode.ADMISSION_LIMIT_EXCEEDED, exc_info.exception.code)

    def test_p09_request_wide_total_budget(self) -> None:
        """P-09: Sum of parallel tool calls exceeding total budget fails closed."""
        tiny_buffer = BoundedToolCallBuffer(max_single_bytes=1000, max_total_bytes=1500)
        tiny_buffer.register_tool("tool_a", "f1")
        tiny_buffer.register_tool("tool_b", "f2")

        tiny_buffer.feed_argument_delta("tool_a", b"x" * 900)
        # Adding 700 to tool_b reaches 1600 > 1500 limit
        with self.assertRaises(SafetyError) as exc_info:
            tiny_buffer.feed_argument_delta("tool_b", b"y" * 700)
        self.assertEqual(SafetyCode.ADMISSION_LIMIT_EXCEEDED, exc_info.exception.code)

    def test_p10_token_restoration_and_release(self) -> None:
        """P-10: Complete arguments with tokens are restored and verified before release."""
        with MappingContext(self.domain, "v1", TEST_HMAC_KEY) as ctx:
            token = ctx.token_for("ORG", "阿尔法科技")
            self.buffer.register_tool("call_search", "query_tool")

            # Stream chunks
            self.buffer.feed_argument_delta("call_search", '{"query": "查询 ')
            self.buffer.feed_argument_delta("call_search", f'{token}')
            self.buffer.feed_argument_delta("call_search", ' 的财报", "limit": 10}')

            allowed = {"query_tool": QueryToolArgs}
            result = self.buffer.finalize_and_verify("call_search", ctx, allowed)

            self.assertEqual("查询 阿尔法科技 的财报", result["query"])
            self.assertEqual(10, result["limit"])

    def test_p10_malformed_json_zero_release(self) -> None:
        """P-10: Malformed JSON arguments fail closed with zero release."""
        with MappingContext(self.domain, "v1", TEST_HMAC_KEY) as ctx:
            self.buffer.register_tool("call_bad", "query_tool")
            self.buffer.feed_argument_delta("call_bad", '{"query": incomplete...')

            with self.assertRaises(SafetyError) as exc_info:
                self.buffer.finalize_and_verify("call_bad", ctx)
            self.assertEqual(SafetyCode.MALFORMED_JSON, exc_info.exception.code)

    def test_p10_schema_mismatch_zero_release(self) -> None:
        """P-10: Arguments failing schema validation fail closed with zero release."""
        with MappingContext(self.domain, "v1", TEST_HMAC_KEY) as ctx:
            self.buffer.register_tool("call_schema_fail", "query_tool")
            # Missing required 'limit' field and unexpected extra field
            self.buffer.feed_argument_delta("call_schema_fail", '{"query": "test", "extra": 123}')

            allowed = {"query_tool": QueryToolArgs}
            with self.assertRaises(SafetyError) as exc_info:
                self.buffer.finalize_and_verify("call_schema_fail", ctx, allowed)
            self.assertEqual(SafetyCode.CONTRACT_VIOLATION, exc_info.exception.code)

    def test_p10_unknown_tool_fails_closed(self) -> None:
        """P-10: Tool call not in allowed whitelist fails closed."""
        with MappingContext(self.domain, "v1", TEST_HMAC_KEY) as ctx:
            self.buffer.register_tool("call_rogue", "delete_database")
            self.buffer.feed_argument_delta("call_rogue", '{"force": true}')

            allowed = {"query_tool": QueryToolArgs}
            with self.assertRaises(SafetyError) as exc_info:
                self.buffer.finalize_and_verify("call_rogue", ctx, allowed)
            self.assertEqual(SafetyCode.CONTRACT_VIOLATION, exc_info.exception.code)

    def test_p14_cancellation_releases_buffers(self) -> None:
        """P-14: Cancellation frees memory and clears tool state."""
        self.buffer.register_tool("call_cancel", "query_tool")
        self.buffer.feed_argument_delta("call_cancel", b"12345")
        self.assertEqual(5, self.buffer._total_bytes)

        self.buffer.cancel_tool("call_cancel")
        self.assertEqual(0, self.buffer._total_bytes)
        self.assertNotIn("call_cancel", self.buffer._buffers)


if __name__ == "__main__":
    unittest.main()
