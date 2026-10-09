"""Evidence-gate contract tests: no egress before every persistence boundary.

All verification is local: temporary directories for the intent ledger and the
evidence directory, a synthetic StaticTestKmsProvider, failure injection via
mocked durable-write interop points, and a loopback spy server on 127.0.0.1
for the P-17 bound client. No real KMS, no real storage, no real supplier is
ever contacted. Every evidence body is a synthetic canary.

The shared ``events`` list records the order in which persistence boundaries
and egress actually happened; "evidence persisted before egress" is asserted
on that recording, and every injected failure asserts the spy saw zero calls.
"""

import dataclasses
import errno
import hashlib
import json
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from audit import audit_intent
from infra import durable_write
from audit.audit_intent import ReleaseIntent
from infra.egress_client import BoundEgressClient, BoundUpstream
from infra.envelope_crypto import (
    KmsProvider,
    KmsUnavailableError,
    StaticTestKmsProvider,
    decrypt_record,
    parse_record,
)
from infra.errors import SafetyCode, SafetyError
from audit.evidence_gate import (
    EvidenceGate,
    EvidencePermit,
    EvidenceSpec,
    gated_send,
)

FIXTURES = Path(__file__).parent / "fixtures" / "evidence"
EG = "audit.evidence_gate"
DW = "infra.durable_write"

RECORDED_AT = datetime(2026, 10, 3, 14, 15, 0, tzinfo=timezone.utc)
CREDENTIAL = "Bearer CNRY-a03-cred-77c1"
BODY_CANARY = "CNRY-A03-body-29cd"
EVIDENCE_CANARY = "CNRY-A03-evidence-6b41"
INTENT_ID = "intent-20261003-a0301"
RECORD_ID = "ev-20261003-a0301"
LOOPBACK = "127.0.0.1"


def fixture_meta() -> dict:
    return json.loads((FIXTURES / "release_versions.json").read_text(encoding="utf-8"))


def make_intent(**overrides) -> ReleaseIntent:
    meta = fixture_meta()
    fields = {
        "intent_id": INTENT_ID,
        "recorded_at": RECORDED_AT,
        "domain": meta["domain"],
        "category": meta["category"],
        "policy_version": meta["policy_version"],
        "package_version": meta["package_version"],
        "purpose": meta["purpose"],
    }
    fields.update(overrides)
    return ReleaseIntent(**fields)


def evidence_plaintext() -> bytes:
    return (FIXTURES / "evidence_plaintext.txt").read_bytes()


def make_evidence(**overrides) -> EvidenceSpec:
    fields = {
        "plaintext": evidence_plaintext(),
        "bucket": "egress-original-30d",
        "record_id": RECORD_ID,
        "purpose": "original-text-retention",
    }
    fields.update(overrides)
    return EvidenceSpec(**fields)


def make_gate(intent_dir, evidence_dir=None, kms=None, **overrides) -> EvidenceGate:
    return EvidenceGate(intent_dir, evidence_directory=evidence_dir, kms=kms, **overrides)


def make_binding(port: int) -> BoundUpstream:
    template = json.loads((FIXTURES / "channel_binding.json").read_text(encoding="utf-8"))
    template.pop("note", None)
    template.pop("host")
    return BoundUpstream(
        host=LOOPBACK,
        port=port,

        allowed_addresses=frozenset({LOOPBACK}),
        **template,
    )


def loopback_resolver(host: str):
    return (LOOPBACK,)


class _SpyHandler(BaseHTTPRequestHandler):
    server_version = "A03Spy/1.0"

    def _dispatch(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        self.server.events.append("egress")
        self.server.recorded.append(
            {"method": self.command, "path": self.path, "body": body}
        )
        payload = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _dispatch
    do_POST = _dispatch

    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        pass


class _SpyServer(ThreadingHTTPServer):
    def __init__(self) -> None:
        super().__init__((LOOPBACK, 0), _SpyHandler)
        self.recorded = []
        self.events = []

    @property
    def port(self) -> int:
        return self.server_address[1]

    def start(self) -> None:
        threading.Thread(target=self.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self.shutdown()
        self.server_close()


# --- persistence-boundary recorders (order proof) ---------------------------


def record_intent_commit(events):
    """Wrap A-01 commit so a successful boundary appends to ``events``."""

    def wrapper(directory, intent):
        permit = audit_intent.commit_release_intent(directory, intent)
        events.append("intent-persisted")
        return permit

    return wrapper


def record_evidence_commit(events):
    """Wrap the evidence durable commit, recording the attempt itself."""

    def wrapper(directory, filename, data):
        events.append("evidence-commit-attempted")
        return durable_write.durable_commit(directory, filename, data)

    return wrapper


class FailingKmsProvider(KmsProvider):
    """Test double: signals key-service outage on every operation."""

    def wrap(self, dek, *, purpose, bucket):
        raise KmsUnavailableError("synthetic outage")

    def unwrap(self, wrapped_dek, *, purpose, bucket):
        raise KmsUnavailableError("synthetic outage")


def fail_durable_commit_on_call(exc: OSError, n: int):
    """Patch payload for EG.durable_commit: the ``n``-th call raises ``exc``.

    Only the gate's evidence commit goes through ``EG.durable_commit`` (the
    intent commit uses A-01's own reference), so ``n=1`` fails the evidence
    commit after a successful intent commit. ``exc`` is the controlled
    :class:`DurableWriteError` that ``durable_commit`` itself raises, keeping
    the injection faithful to real storage-failure semantics.
    """
    calls = {"count": 0}

    def wrapper(directory, filename, data, **kwargs):
        calls["count"] += 1
        if calls["count"] >= n:
            raise durable_write.DurableWriteError(type(exc).__name__)
        return durable_write.durable_commit(directory, filename, data, **kwargs)

    return wrapper


def fail_interop_on_call(target: str, exc: OSError, n: int):
    """Patch payload for DW interop points: the ``n``-th call raises ``exc``.

    Each durable commit (intent, then evidence) exercises the interop point
    once, so ``n=2`` fails the evidence commit after a successful intent one.
    """
    real = getattr(durable_write, target)
    calls = {"count": 0}

    def wrapper(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] >= n:
            raise exc
        return real(*args, **kwargs)

    return wrapper


class GatePositiveTests(unittest.TestCase):
    def test_intent_only_admit_returns_permit_with_no_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            gate = make_gate(d)
            permit = gate.admit(make_intent())
            self.assertIsInstance(permit, EvidencePermit)
            self.assertIsNone(permit.evidence)
            self.assertEqual(permit.intent_id, INTENT_ID)
            self.assertTrue(permit.intent_path.exists())
            raw = permit.intent_path.read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), permit.intent_sha256)

    def test_full_admit_commits_encrypted_evidence_and_permit_references_it(self):
        with tempfile.TemporaryDirectory() as intent_d, tempfile.TemporaryDirectory() as evidence_d:
            kms = StaticTestKmsProvider()
            gate = make_gate(intent_d, evidence_d, kms)
            permit = gate.admit(make_intent(), make_evidence())
            self.assertIsNotNone(permit.evidence)
            ref = permit.evidence
            self.assertEqual(ref.record_id, RECORD_ID)
            self.assertTrue(ref.path.exists())
            blob = ref.path.read_bytes()
            self.assertEqual(hashlib.sha256(blob).hexdigest(), ref.sha256)
            self.assertEqual(ref.bytes_written, len(blob))
            # The evidence at rest is the A-02 envelope, never the plaintext.
            self.assertNotIn(EVIDENCE_CANARY, blob.decode("utf-8", errors="replace"))
            record = parse_record(blob)
            self.assertEqual(decrypt_record(kms, record), evidence_plaintext())
            # The intent reached its own boundary too.
            self.assertTrue(permit.intent_path.exists())

    def test_permit_handle_is_immutable_and_granted_at_is_aware(self):
        with tempfile.TemporaryDirectory() as d:
            permit = make_gate(d).admit(make_intent())
            self.assertIsNotNone(permit.granted_at.tzinfo)
            self.assertIsNotNone(permit.granted_at.utcoffset())
            with self.assertRaises(dataclasses.FrozenInstanceError):
                permit.intent_id = "tampered"  # type: ignore[misc]


class GateOrderingTests(unittest.TestCase):
    """Gate-then-send composition with a loopback spy: order and exactly-once."""

    @classmethod
    def setUpClass(cls):
        cls.server = _SpyServer()
        cls.server.start()
        cls.client = BoundEgressClient(
            make_binding(cls.server.port), resolver=loopback_resolver
        )

    @classmethod
    def tearDownClass(cls):
        cls.client.close()
        cls.server.stop()

    def setUp(self):
        self.server.recorded.clear()
        self.events = []
        self.server.events = self.events

    def _gated_send(self, tmp, evidence=None, kms=None):
        intent_d = Path(tmp) / "intents"
        evidence_d = Path(tmp) / "evidence"
        intent_d.mkdir()
        evidence_d.mkdir()
        gate = make_gate(intent_d, evidence_d, kms or StaticTestKmsProvider())
        with mock.patch(f"{EG}.commit_release_intent", side_effect=record_intent_commit(self.events)):
            with mock.patch(f"{EG}.durable_commit", side_effect=record_evidence_commit(self.events)):
                return gated_send(
                    gate,
                    self.client,
                    intent=make_intent(),
                    evidence=evidence,
                    method="POST",
                    path="/v1/chat/completions",
                    headers={"Authorization": CREDENTIAL, "Content-Type": "application/json"},
                    content=(FIXTURES / "chat_request.json").read_bytes(),
                )

    def test_gated_send_persists_intent_then_evidence_then_egresses_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self._gated_send(tmp, evidence=make_evidence())
            self.assertEqual(self.events, ["intent-persisted", "evidence-commit-attempted", "egress"])
            self.assertEqual(len(self.server.recorded), 1)
            seen = self.server.recorded[0]
            self.assertEqual(seen["path"], "/v1/chat/completions")
            self.assertEqual(seen["body"], (FIXTURES / "chat_request.json").read_bytes())
            self.assertEqual(result.response.status_code, 200)
            permit = result.permit
            self.assertIsNotNone(permit.evidence)
            self.assertTrue(permit.evidence.path.exists())
            self.assertTrue(permit.intent_path.exists())

    def test_gated_send_without_evidence_persists_intent_before_egress(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self._gated_send(tmp)
            self.assertEqual(self.events, ["intent-persisted", "egress"])
            self.assertEqual(len(self.server.recorded), 1)
            self.assertIsNone(result.permit.evidence)


class GateFailureTests(unittest.TestCase):
    """Every injected gate failure: no permit, zero egress, clean messages."""

    @classmethod
    def setUpClass(cls):
        cls.server = _SpyServer()
        cls.server.start()
        cls.client = BoundEgressClient(
            make_binding(cls.server.port), resolver=loopback_resolver
        )

    @classmethod
    def tearDownClass(cls):
        cls.client.close()
        cls.server.stop()

    def setUp(self):
        self.server.recorded.clear()
        self.events = []
        self.server.events = self.events

    def _dirs(self, tmp):
        intent_d = Path(tmp) / "intents"
        evidence_d = Path(tmp) / "evidence"
        intent_d.mkdir()
        evidence_d.mkdir()
        return intent_d, evidence_d

    def _assert_gate_failure(self, ctx, code, intent_d, evidence_d):
        exc = ctx.exception
        self.assertIsInstance(exc, SafetyError)
        self.assertEqual(exc.code, code)
        self.assertIsNone(exc.__cause__)
        self.assertIsNone(exc.__context__)
        message = str(exc)
        self.assertNotIn(EVIDENCE_CANARY, message)
        self.assertNotIn(INTENT_ID, message)
        self.assertNotIn(RECORD_ID, message)
        self.assertEqual(self.server.recorded, [])  # upstream egress is zero
        self.assertNotIn("egress", self.events)
        # No fabricated evidence final name; temp residue carries no permit meaning.
        self.assertEqual(list(Path(evidence_d).iterdir()), [])

    def _gated_send_with_patches(self, gate, evidence, patches):
        stack = [mock.patch(f"{EG}.commit_release_intent", side_effect=record_intent_commit(self.events))]
        stack.append(mock.patch(f"{EG}.durable_commit", side_effect=record_evidence_commit(self.events)))
        stack.extend(patches)
        for p in stack:
            p.start()
        try:
            return gated_send(
                gate,
                self.client,
                intent=make_intent(),
                evidence=evidence,
                method="POST",
                path="/v1/chat/completions",
                headers={"Authorization": CREDENTIAL},
                content=b"{}",
            )
        finally:
            for p in reversed(stack):
                p.stop()

    def test_intent_write_failure_blocks_permit_and_egress(self):
        with tempfile.TemporaryDirectory() as tmp:
            intent_d, evidence_d = self._dirs(tmp)
            gate = make_gate(intent_d, evidence_d, StaticTestKmsProvider())
            with mock.patch(f"{DW}._write_all", side_effect=OSError(errno.ENOSPC, "No space left on device")):
                with self.assertRaises(SafetyError) as ctx:
                    self._gated_send_with_patches(gate, make_evidence(), [])
            self._assert_gate_failure(ctx, SafetyCode.AUDIT_WRITE_FAILED, intent_d, evidence_d)
            self.assertEqual(list(Path(intent_d).iterdir()), [])

    def test_intent_fsync_failure_blocks_permit_and_egress(self):
        with tempfile.TemporaryDirectory() as tmp:
            intent_d, evidence_d = self._dirs(tmp)
            gate = make_gate(intent_d, evidence_d, StaticTestKmsProvider())
            with mock.patch(f"{DW}._flush_and_fsync", side_effect=OSError(errno.EIO, "fsync failed")):
                with self.assertRaises(SafetyError) as ctx:
                    self._gated_send_with_patches(gate, make_evidence(), [])
            self._assert_gate_failure(ctx, SafetyCode.AUDIT_WRITE_FAILED, intent_d, evidence_d)
            self.assertEqual(list(Path(intent_d).iterdir()), [])

    def test_intent_rename_failure_blocks_permit_and_egress(self):
        with tempfile.TemporaryDirectory() as tmp:
            intent_d, evidence_d = self._dirs(tmp)
            gate = make_gate(intent_d, evidence_d, StaticTestKmsProvider())
            with mock.patch(f"{DW}._replace", side_effect=OSError(errno.EPERM, "rename denied")):
                with self.assertRaises(SafetyError) as ctx:
                    self._gated_send_with_patches(gate, make_evidence(), [])
            self._assert_gate_failure(ctx, SafetyCode.AUDIT_WRITE_FAILED, intent_d, evidence_d)
            self.assertEqual(list(Path(intent_d).iterdir()), [])

    def test_kms_unavailable_blocks_evidence_and_egress(self):
        with tempfile.TemporaryDirectory() as tmp:
            intent_d, evidence_d = self._dirs(tmp)
            gate = make_gate(intent_d, evidence_d, FailingKmsProvider())
            with self.assertRaises(SafetyError) as ctx:
                self._gated_send_with_patches(gate, make_evidence(), [])
            self._assert_gate_failure(ctx, SafetyCode.KMS_UNAVAILABLE, intent_d, evidence_d)
            # The intent really is committed (A-01 truth); encryption fails
            # before any evidence commit is attempted, and no permit exists.
            self.assertEqual(self.events, ["intent-persisted"])
            self.assertTrue((Path(intent_d) / f"{INTENT_ID}.intent.json").exists())

    def test_evidence_write_failure_after_encryption_blocks_permit_and_egress(self):
        with tempfile.TemporaryDirectory() as tmp:
            intent_d, evidence_d = self._dirs(tmp)
            gate = make_gate(intent_d, evidence_d, StaticTestKmsProvider())
            boom = fail_durable_commit_on_call(OSError(errno.ENOSPC, "No space left on device"), n=1)
            with mock.patch(f"{EG}.durable_commit", side_effect=boom):
                with self.assertRaises(SafetyError) as ctx:
                    gated_send(
                        gate,
                        self.client,
                        intent=make_intent(),
                        evidence=make_evidence(),
                        method="POST",
                        path="/v1/chat/completions",
                        headers={"Authorization": CREDENTIAL},
                content=b"{}",
                    )
            self._assert_gate_failure(ctx, SafetyCode.EVIDENCE_GATE_FAILED, intent_d, evidence_d)
            self.assertTrue((Path(intent_d) / f"{INTENT_ID}.intent.json").exists())

    def test_evidence_fsync_failure_after_encryption_blocks_permit_and_egress(self):
        with tempfile.TemporaryDirectory() as tmp:
            intent_d, evidence_d = self._dirs(tmp)
            gate = make_gate(intent_d, evidence_d, StaticTestKmsProvider())
            boom = fail_interop_on_call("_flush_and_fsync", OSError(errno.EIO, "fsync failed"), n=2)
            with mock.patch(f"{DW}._flush_and_fsync", side_effect=boom):
                with self.assertRaises(SafetyError) as ctx:
                    gated_send(
                        gate,
                        self.client,
                        intent=make_intent(),
                        evidence=make_evidence(),
                        method="POST",
                        path="/v1/chat/completions",
                        headers={"Authorization": CREDENTIAL},
                content=b"{}",
                    )
            self._assert_gate_failure(ctx, SafetyCode.EVIDENCE_GATE_FAILED, intent_d, evidence_d)
            self.assertTrue((Path(intent_d) / f"{INTENT_ID}.intent.json").exists())

    def test_evidence_rename_failure_after_encryption_blocks_permit_and_egress(self):
        with tempfile.TemporaryDirectory() as tmp:
            intent_d, evidence_d = self._dirs(tmp)
            gate = make_gate(intent_d, evidence_d, StaticTestKmsProvider())
            boom = fail_interop_on_call("_replace", OSError(errno.EPERM, "rename denied"), n=2)
            with mock.patch(f"{DW}._replace", side_effect=boom):
                with self.assertRaises(SafetyError) as ctx:
                    gated_send(
                        gate,
                        self.client,
                        intent=make_intent(),
                        evidence=make_evidence(),
                        method="POST",
                        path="/v1/chat/completions",
                        headers={"Authorization": CREDENTIAL},
                content=b"{}",
                    )
            self._assert_gate_failure(ctx, SafetyCode.EVIDENCE_GATE_FAILED, intent_d, evidence_d)
            self.assertTrue((Path(intent_d) / f"{INTENT_ID}.intent.json").exists())

    def test_gate_failure_via_gated_send_leaves_spy_at_zero(self):
        # Intent-only channel, fsync dies on the single commit: no permit, no send.
        with tempfile.TemporaryDirectory() as tmp:
            intent_d, evidence_d = self._dirs(tmp)
            gate = make_gate(intent_d, evidence_d, StaticTestKmsProvider())
            with mock.patch(f"{DW}._flush_and_fsync", side_effect=OSError(errno.EIO, "fsync failed")):
                with self.assertRaises(SafetyError) as ctx:
                    gated_send(
                        gate,
                        self.client,
                        intent=make_intent(),
                        method="POST",
                        path="/v1/chat/completions",
                        headers={"Authorization": CREDENTIAL},
                content=b"{}",
                    )
            self._assert_gate_failure(ctx, SafetyCode.AUDIT_WRITE_FAILED, intent_d, evidence_d)


class GateContractTests(unittest.TestCase):
    def test_admit_rejects_non_release_intent(self):
        with tempfile.TemporaryDirectory() as d:
            gate = make_gate(d)
            with self.assertRaises(TypeError):
                gate.admit({"intent_id": INTENT_ID})  # type: ignore[arg-type]

    def test_evidence_record_id_traversal_fails_closed_before_any_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            intent_d = Path(tmp) / "intents"
            evidence_d = Path(tmp) / "evidence"
            intent_d.mkdir()
            evidence_d.mkdir()
            with self.assertRaises(SafetyError) as ctx:
                make_evidence(record_id="../escape")
            self.assertEqual(ctx.exception.code, SafetyCode.CONTRACT_VIOLATION)
            gate = make_gate(intent_d, evidence_d, StaticTestKmsProvider())
            with self.assertRaises(SafetyError) as ctx:
                gate.admit(make_intent(), make_evidence(record_id="bad/id"))
            self.assertEqual(ctx.exception.code, SafetyCode.CONTRACT_VIOLATION)
            self.assertEqual(list(Path(intent_d).iterdir()), [])
            self.assertEqual(list(Path(evidence_d).iterdir()), [])

    def test_evidence_without_kms_config_is_contract_violation(self):
        with tempfile.TemporaryDirectory() as tmp:
            intent_d = Path(tmp) / "intents"
            evidence_d = Path(tmp) / "evidence"
            intent_d.mkdir()
            evidence_d.mkdir()
            gate = make_gate(intent_d, evidence_d, kms=None)
            with self.assertRaises(SafetyError) as ctx:
                gate.admit(make_intent(), make_evidence())
            self.assertEqual(ctx.exception.code, SafetyCode.CONTRACT_VIOLATION)
            # Intent commit runs first and is real state; evidence never starts.
            self.assertTrue((Path(intent_d) / f"{INTENT_ID}.intent.json").exists())
            self.assertEqual(list(Path(evidence_d).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
