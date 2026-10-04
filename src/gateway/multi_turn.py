"""P-15 Multi-turn conversation processing and historical re-detection.

Ensures that in multi-turn conversations:
1. Historical messages are re-evaluated through the detection orchestrator on every turn.
2. Each turn uses an independent, ephemeral MappingContext; no long-term mapping storage.
3. Callers cannot smuggle reserved token literals from previous sessions.
4. Upstream receives freshly redacted tokens on every turn.
5. Plaintext is faithfully restored to caller upon receiving upstream response.
"""

from __future__ import annotations

import json
from typing import Any, Sequence

from infra.errors import SafetyCode, SafetyError
from gateway.pipeline import ProtectedPipeline, PipelineResult
from masking.mapping import MappingContext
from protocol.identity import TrustedIdentity


class MultiTurnConversationSession:
    """Manages multi-turn state while ensuring per-turn isolation and re-detection (P-15)."""

    def __init__(self, pipeline: ProtectedPipeline, identity: TrustedIdentity) -> None:
        self.pipeline = pipeline
        self.identity = identity
        self.history: list[dict[str, str]] = []

    def execute_turn(
        self,
        user_message: str,
        category: str,
        turn_hmac_key: bytes,
        model: str = "deepseek-flash",
    ) -> str:
        """Execute one conversational turn through the protected pipeline.

        Appends the new user message, submits full history to the pipeline,
        restores upstream response, updates local history, and returns plaintext response.
        """
        self.history.append({"role": "user", "content": user_message})

        raw_req = json.dumps({
            "model": model,
            "messages": self.history,
        })

        with MappingContext(self.pipeline.domain, "v1", turn_hmac_key) as ctx:
            result = self.pipeline.process_request(
                raw_body=raw_req,
                headers={},
                identity=self.identity,
                category=category,
                context=ctx,
            )

        # Extract assistant response text
        assistant_reply = result.response.choices[0].message.content
        self.history.append({"role": "assistant", "content": assistant_reply})
        return assistant_reply
