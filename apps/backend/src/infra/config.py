"""Only a local review profile exists; production needs implemented admission gates."""

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict


class ReviewSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    profile: Literal["local-review"] = "local-review"
    external_egress: Literal[False] = False
    real_knowledge_capture: Literal[False] = False
    persistent_audit: Literal[False] = False


def load_settings(path: Path) -> ReviewSettings:
    def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate configuration key")
            result[key] = value
        return result

    payload = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_pairs)
    return ReviewSettings.model_validate(payload)

