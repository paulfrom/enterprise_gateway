"""Client-echoed DeepSeek history: admitted for compatibility, never serialized.

A real WorkBuddy client replays the previous assistant message verbatim on the
next turn. Those messages carry provider/client ledger fields (``reasoning_content``,
``annotations``, ``messageId`` ...). The protocol layer admits them so parsing
succeeds, but ``Field(exclude=True)`` guarantees they never appear in any
serialization used for detection, evidence, knowledge or egress.
"""
import json
import unittest

from infra.errors import SafetyCode, SafetyError
from protocol.protocols import DeepSeekChatRequest, parse_deepseek_chat_completion

LEDGER_MESSAGE_KEYS = (
    'reasoning_content', 'reasoning', 'startsNewUserRequest', 'agent',
    'conversationRequestId', 'messageId', 'stepSeq', 'model', 'requestModelId',
    'requestModelName', 'traceId', 'rawUsage', 'usage',
)


def _realistic_payload():
    return {
        'model': 'deepseek-flash',
        'messages': [
            {'role': 'system', 'content': 'system'},
            {'role': 'user', 'content': 'u1', 'startsNewUserRequest': True,
             'agent': 'main', 'conversationRequestId': 'c-1'},
            {'role': 'assistant',
             'content': [{'type': 'text', 'text': 'a1',
                          'annotations': [{'kind': 'citation', 'secret': 'SENSITIVE'}]}],
             'conversationRequestId': 'c-1', 'messageId': 'm-1', 'stepSeq': 1,
             'model': 'deepseek-flash', 'requestModelId': 'rm-1',
             'requestModelName': 'deepseek-flash', 'traceId': 't-1',
             'rawUsage': {'prompt_tokens': 1}, 'usage': {'total_tokens': 2},
             'reasoning': 'alias-body', 'reasoning_content': 'think-body'},
            {'role': 'user', 'content': 'u2'},
        ],
    }


class DeepSeekClientHistory(unittest.TestCase):
    def parse(self, payload):
        return parse_deepseek_chat_completion(
            json.dumps(payload, ensure_ascii=False),
            allowed_models=frozenset({'deepseek-flash'}),
        )

    def test_realistic_round2_history_is_admitted(self):
        parsed = self.parse(_realistic_payload())
        self.assertEqual('deepseek-flash', parsed.model)
        self.assertEqual(4, len(parsed.messages))

    def test_ledger_fields_are_never_serialized(self):
        parsed = self.parse(_realistic_payload())
        assistant = parsed.messages[2]
        for exclude in ({}, {'exclude_unset': True}, {'exclude_none': True}):
            with self.subTest(exclude=exclude):
                payload = parsed.model_dump(**exclude)
                dumped = payload['messages'][2]
                for key in LEDGER_MESSAGE_KEYS:
                    self.assertNotIn(key, dumped)
                self.assertNotIn('annotations', dumped['content'][0])
        # The admission check used by ingress must also drop them.
        self.assertNotIn('reasoning_content',
                         parsed.model_dump(exclude_none=True)['messages'][2])

    def test_direct_model_dump_never_emits_ledger(self):
        parsed = DeepSeekChatRequest.model_validate(_realistic_payload())
        serialized = json.dumps(parsed.model_dump(), ensure_ascii=False)
        for token in ('think-body', 'alias-body', 'SENSITIVE', 'messageId',
                      'stepSeq', 'requestModelName', 'rawUsage'):
            self.assertNotIn(token, serialized)

    def test_reasoning_on_non_assistant_role_is_rejected(self):
        payload = _realistic_payload()
        payload['messages'][3] = {'role': 'user', 'content': 'u2',
                                  'reasoning_content': 'think-body'}
        with self.assertRaises(SafetyError) as refused:
            self.parse(payload)
        self.assertEqual(SafetyCode.CONTRACT_VIOLATION, refused.exception.code)

    def test_unknown_ledger_key_still_fails_closed(self):
        payload = _realistic_payload()
        payload['messages'][2]['compression'] = 'unproved'
        with self.assertRaises(SafetyError):
            self.parse(payload)

    def test_unknown_block_key_still_fails_closed(self):
        payload = _realistic_payload()
        payload['messages'][2]['content'][0]['redacted_thinking'] = True
        with self.assertRaises(SafetyError):
            self.parse(payload)


if __name__ == '__main__':
    unittest.main()
