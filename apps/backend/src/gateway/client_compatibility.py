"""Normalize known agent metadata without trusting client identity claims."""
from copy import deepcopy
from collections.abc import Mapping

from protocol.identity import FORBIDDEN_CLIENT_IDENTITY_HEADERS


def compatible_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Discard identity claims; authorization still comes from the BYOK token."""
    return {name: value for name, value in headers.items()
            if name.lower() not in FORBIDDEN_CLIENT_IDENTITY_HEADERS}


def compatible_payload(payload: dict) -> dict:
    """Preserve opaque client fields and fill a supported reasoning alias."""
    normalized = deepcopy(payload)
    messages = normalized.get('messages')
    if not isinstance(messages, list):
        return normalized  # The protocol parser rejects invalid message shapes.
    for message in messages:
        if not isinstance(message, dict):
            continue
        if (message.get('role') == 'assistant' and isinstance(message.get('reasoning'), str)
                and 'reasoning_content' not in message):
            message['reasoning_content'] = message['reasoning']
    return normalized
