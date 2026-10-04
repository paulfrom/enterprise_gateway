"""P-08 Branch streaming restorer with token defragmentation.

Buffers partial token prefixes (e.g., '<<', '<<ENT_v1_...') across streaming
delta chunks, restores complete tokens atomically via MappingContext, isolates
branch buffers, and fails closed on unknown or malformed tokens.
"""

from __future__ import annotations

import re
from typing import Mapping

from infra.errors import SafetyCode, SafetyError
from masking.mapping import MappingContext, _TOKEN as _TOKEN_RE
_RESERVED_PREFIX = "<<"


class BranchStreamingRestorer:
    """Defragments and restores redacted tokens in streaming responses per branch (P-08)."""

    def __init__(self, context: MappingContext) -> None:
        if not isinstance(context, MappingContext):
            raise TypeError("context must be an active MappingContext")
        context.require_active()
        self.context = context
        self._buffers: dict[str, str] = {}

    def feed(self, branch_id: str, delta: str) -> str:
        """Process incoming delta text for a specific branch and return restored text.

        Retains partial token prefixes in the buffer until complete or disproven.
        """
        self.context.require_active()
        if not delta:
            return ""

        current = self._buffers.get(branch_id, "") + delta
        output_parts: list[str] = []
        cursor = 0

        while cursor < len(current):
            idx = current.find(_RESERVED_PREFIX, cursor)
            if idx == -1:
                # No token prefix, all text from cursor onwards can be emitted
                output_parts.append(current[cursor:])
                current = ""
                break

            # Emit text preceding the token prefix
            if idx > cursor:
                output_parts.append(current[cursor:idx])

            # Check if we have a full token starting at idx
            match = _TOKEN_RE.match(current, idx)
            if match is not None:
                token = match.group()
                restored = self.context.restore(token)
                output_parts.append(restored)
                cursor = match.end()
                continue

            # Incomplete prefix at the end of current?
            tail = current[idx:]
            # If tail could still be the start of a token:
            # Token looks like <<ENT_v1_...>>
            if (
                _RESERVED_PREFIX.startswith(tail)
                or tail.startswith(_RESERVED_PREFIX)
                and ">>" not in tail
                and len(tail) < 80
            ):
                # Buffer this tail for the next chunk
                current = tail
                break
            else:
                # Not a valid token prefix, but contains '<<'
                # Check if it was malformed
                if ">>" in tail:
                    # Token ended but didn't match _TOKEN_RE
                    raise SafetyError(SafetyCode.MALFORMED_TOKEN, "malformed token in streaming chunk")
                # Exceeded max token length without closing '>>'
                raise SafetyError(SafetyCode.MALFORMED_TOKEN, "unterminated token syntax in stream")

        self._buffers[branch_id] = current
        return "".join(output_parts)

    def finalize(self, branch_id: str) -> str:
        """Finalize a branch stream. Fails closed if an incomplete token prefix remains."""
        self.context.require_active()
        tail = self._buffers.pop(branch_id, "")
        if not tail:
            return ""

        # If tail starts with reserved prefix, stream was truncated mid-token!
        if tail.startswith(_RESERVED_PREFIX):
            raise SafetyError(SafetyCode.MALFORMED_TOKEN, "stream truncated mid-token")

        return tail

    def cancel_branch(self, branch_id: str) -> None:
        """Clean up resources for a canceled branch (P-14)."""
        self._buffers.pop(branch_id, None)

    def cancel_all(self) -> None:
        """Clean up all buffers on stream termination or disconnect (P-14)."""
        self._buffers.clear()
