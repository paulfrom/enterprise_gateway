"""Small public contracts for sensitive request history."""
from __future__ import annotations

from infra.errors import SafetyCode

STAGES = ("input", "redacted", "upstream", "restored")
FINAL_STATUSES = frozenset({"completed", "blocked", "failed", "partial"})
STATUSES = FINAL_STATUSES | {"processing"}
MEDIA_TYPES = frozenset({"application/json", "text/event-stream"})
STAGE_STATES = frozenset({"complete", "partial"})
ERROR_CODES = frozenset(code.value for code in SafetyCode) | {
    "HISTORY_UNAVAILABLE", "UPSTREAM_FAILED", "STREAM_INTERRUPTED", "INTERNAL_ERROR",
    "UPSTREAM_ERROR", "CLIENT_DISCONNECTED", "STREAM_FAILED", "UPSTREAM_FAILURE",
    "INTERNAL_FAILURE", "STREAM_PROTECTION_FAILED", "STREAM_TRANSPORT_FAILED",
}
PROTOCOLS = frozenset({'deepseek-chat-completions', 'claude-messages'})
PURPOSE = "request-history"


class HistoryUnavailable(RuntimeError):
    """Fixed failure, deliberately excluding provider/database diagnostics."""

    def __init__(self) -> None:
        super().__init__("Request history unavailable")


class HistoryNotFound(LookupError):
    """Missing, foreign-domain and expired records are indistinguishable."""

    def __init__(self) -> None:
        super().__init__("Request history not found")
