"""All-or-nothing file redaction using the runtime's mandatory detector."""
from __future__ import annotations

from collections import Counter
import threading
import time
from typing import Callable

from detection.detection_orchestrator import DetectionOrchestrator
from detection.inference_executor import InferenceExecutor
from detection.spans import Span, redact_text
from document.extract import Block, DocumentError, extraction_worker
from masking.mapping import MappingContext


def render_markdown(blocks: list[Block]) -> str:
    lines = []
    in_table = False
    table_width = 0
    for block in blocks:
        if block.kind == 'row':
            values = [value.replace('\\', '\\\\').replace('|', '\\|').replace('\r', '').replace('\n', '<br>') for value in block.texts]
            if not in_table:
                table_width = len(values)
                lines.extend(['', '| ' + ' | '.join('列' + str(i + 1) for i in range(table_width)) + ' |',
                              '| ' + ' | '.join('---' for _ in range(table_width)) + ' |'])
            elif len(values) != table_width:
                # CSV rows may have unequal widths. Start a new complete table.
                in_table = False
                table_width = len(values)
                lines.extend(['', '| ' + ' | '.join('列' + str(i + 1) for i in range(table_width)) + ' |',
                              '| ' + ' | '.join('---' for _ in range(table_width)) + ' |'])
            lines.append('| ' + ' | '.join(values) + ' |')
            in_table = True
        else:
            in_table = False
            if block.kind != 'separator':
                lines.extend(['', '#' * block.level + (' ' if block.level else '') + '\n'.join(block.texts)])
    return '\n'.join(lines).strip() + '\n'


class FileRedactor:
    def __init__(self, *, detector: DetectionOrchestrator, domain: str, scope: str,
                 verify_assets: Callable[[], str]):
        self.detector = detector
        self.domain = domain
        self.scope = scope
        self.verify_assets = verify_assets
        self.slot = threading.BoundedSemaphore(1)
        self.parser = InferenceExecutor(max_workers=1, max_pending=1)

    def close(self):
        self.parser.close()

    def redact(self, data: bytes, file_format: str, *, deadline_at: float, cancel):
        version = self.verify_assets()
        document, error = self.parser.submit(extraction_worker, data, file_format,
            timeout=min(20, max(0.001, deadline_at - time.monotonic())), cancel=cancel)
        if error:
            raise DocumentError(error)
        texts = tuple(value for block in document.blocks for value in block.texts)
        outcomes = self.detector.detect_many(texts, deadline_at=deadline_at, cancel=cancel)
        counts = Counter(span.entity_type for outcome in outcomes for span in outcome.spans)
        blocks = []
        cursor = 0
        with MappingContext(scope=self.domain) as context:
            context.assign_roles((text, outcome.spans) for text, outcome in zip(texts, outcomes, strict=True))
            for block in document.blocks:
                values = []
                for text in block.texts:
                    outcome = outcomes[cursor]
                    values.append(redact_text(text, (Span(s.start, s.end, s.entity_type, s.priority) for s in outcome.spans), context))
                    cursor += 1
                blocks.append(Block(block.kind, tuple(values), block.level))
            entity_count = context.entry_count
        if cancel.is_set() or time.monotonic() >= deadline_at:
            raise DocumentError('DOCUMENT_TIMEOUT')
        return {
            'format': file_format, 'output_format': 'markdown', 'redacted_text': render_markdown(blocks),
            'characters': document.characters, 'block_count': len(document.blocks),
            'entity_count': entity_count, 'replacement_count': sum(counts.values()),
            'entity_types': dict(counts), 'warnings': document.warnings,
            'package_hash': version,
        }
