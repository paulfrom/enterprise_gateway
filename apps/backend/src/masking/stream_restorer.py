"""Per-branch defragmentation of readable placeholders."""
from __future__ import annotations

import re
from infra.errors import SafetyCode, SafetyError
from masking.mapping import MappingContext, check_text


class BranchStreamingRestorer:
    def __init__(self, context: MappingContext) -> None:
        if not isinstance(context, MappingContext):
            raise TypeError("context must be an active MappingContext")
        context.require_active()
        self.context = context
        self._buffers: dict[str, str] = {}

    def feed(self, branch_id: str, delta: str) -> str:
        self.context.require_active()
        check_text(delta)
        current = self._buffers.get(branch_id, "") + delta
        start = current.rfind("<")
        if start > 0 and current[start - 1:start + 1] == "<<":
            start -= 1
        if (start >= 0 and ">" not in current[start:]
                and (current[start:] in ('<', '<<')
                     or re.fullmatch(r'<<?\s*[A-Za-z][A-Za-z0-9_-]*(?:\s*[_-]\s*\d*)?', current[start:]))):
            pending = current[start:]
            if len(pending) > 96:
                raise SafetyError(SafetyCode.MALFORMED_TOKEN)
            self._buffers[branch_id] = pending
            return self.context.restore(current[:start])
        self._buffers[branch_id] = ""
        return self.context.restore(current)

    def finalize(self, branch_id: str) -> str:
        self.context.require_active()
        return self.context.restore(self._buffers.pop(branch_id, ""))

    def cancel_branch(self, branch_id: str) -> None:
        self._buffers.pop(branch_id, None)

    def cancel_all(self) -> None:
        self._buffers.clear()
