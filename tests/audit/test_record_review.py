"""Real authentication, durable files and AES-GCM, using synthetic credentials/KEKs."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
import multiprocessing
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from audit.record_review import RecordReviewService, REVIEW_PURPOSE
from audit.audit_intent import ReleaseIntent
from audit.evidence_gate import EvidenceGate, EvidenceSpec
from infra.durable_write import DurableWriteError
from infra.envelope_crypto import (
    StaticTestKmsProvider, encrypt_record, parse_record, KmsUnavailableError,
)
from infra.errors import SafetyCode, SafetyError
from protocol.identity import EnterpriseAuthenticator, TrustedIdentity


def _child_read(directory, ticket_id, record, kek, now, output):
    identity = TrustedIdentity(subject_id="reader", tenant_id="tenant", domain="domain",
        roles=frozenset({"audit-reader"}), purposes=frozenset({REVIEW_PURPOSE}),
        auth_source="synthetic-enterprise-authenticator", authenticated_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(hours=1))
    service = RecordReviewService(directory, EnterpriseAuthenticator({"reader": identity}),
        StaticTestKmsProvider({("audit-evidence", "synthetic-bucket"): kek}), clock=lambda: now)
    try:
        output.put(service.read({"authorization": "Bearer reader"}, ticket_id, record,
                                purpose=REVIEW_PURPOSE))
    except SafetyError:
        output.put(None)


class RecordReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.now = datetime(2026, 10, 6, 0, 0, tzinfo=timezone.utc)
        self.identities = {
            "reader": self.identity("reader", {"audit-reader"}),
            "security": self.identity("security", {"audit-security-approver"}),
            "data": self.identity("data", {"audit-data-approver"}),
            "both": self.identity("both", {"audit-security-approver", "audit-data-approver"}),
            "other": self.identity("other", {"audit-reader"}),
            "outside": self.identity("outside", {"audit-reader"}, domain="other-domain"),
            "other-tenant": self.identity("other-tenant", {"audit-reader"}, tenant="other-tenant"),
            "wrong-purpose": self.identity("wrong-purpose", {"audit-reader"}, purposes={"model-query"}),
        }
        self.auth = EnterpriseAuthenticator(self.identities)
        self.kms = StaticTestKmsProvider()
        self.service = self.make_service()
        self.raw = b"SYNTHETIC AUDIT CANARY, not business material"
        self.record = encrypt_record(self.kms, self.raw, domain="domain", bucket="synthetic-bucket",
                                     record_id="record-1", purpose="audit-evidence")

    def identity(self, subject, roles, domain="domain", tenant="tenant", purposes=None, expires=None):
        return TrustedIdentity(subject_id=subject, tenant_id=tenant, domain=domain,
            roles=frozenset(roles), purposes=frozenset(purposes or {REVIEW_PURPOSE}),
            auth_source="synthetic-enterprise-authenticator", authenticated_at=self.now - timedelta(minutes=1),
            expires_at=expires or self.now + timedelta(hours=1))

    def make_service(self):
        return RecordReviewService(self.directory, self.auth, self.kms, clock=lambda: self.now)

    @staticmethod
    def headers(name):
        return {"authorization": f"Bearer {name}"}

    def request(self, **overrides):
        args = dict(tenant_id="tenant", purpose=REVIEW_PURPOSE,
                    expires_at=self.now + timedelta(minutes=10))
        args.update(overrides)
        return self.service.request(self.headers("reader"), self.record, **args)

    def approve(self, ticket):
        self.service.approve(self.headers("security"), ticket.ticket_id, role="audit-security-approver")
        self.service.approve(self.headers("data"), ticket.ticket_id, role="audit-data-approver")

    def read(self, ticket, service=None, name="reader", record=None, purpose=REVIEW_PURPOSE):
        return (service or self.service).read(self.headers(name), ticket.ticket_id,
                                             record or self.record, purpose=purpose)

    def events(self):
        return [json.loads(path.read_text()) for path in self.directory.glob("*.review-event.json")]

    def assert_denied(self, operation, code=None):
        before = len(self.events())
        with self.assertRaises(SafetyError) as error:
            operation()
        if code:
            self.assertEqual(code, error.exception.code)
        self.assertGreater(len(self.events()), before)
        self.assertTrue(any(event["outcome"] == "denied" for event in self.events()))

    def test_dual_distinct_approvals_real_decrypt_and_metadata_only_audit(self):
        ticket = self.request()
        self.approve(ticket)
        self.assertEqual(self.raw, self.read(ticket))
        events = self.events()
        self.assertEqual({"requested", "approved", "access_attempt", "accessed"},
                         {event["outcome"] for event in events})
        for path in self.directory.iterdir():
            if path.is_file():
                self.assertNotIn(self.raw, path.read_bytes())
                self.assertNotIn(b"Bearer ", path.read_bytes())

    def test_existing_evidence_gate_durable_record_is_reviewed_exactly(self):
        intent_dir = self.directory / "intents"
        evidence_dir = self.directory / "evidence"
        intent_dir.mkdir()
        evidence_dir.mkdir()
        gate = EvidenceGate(intent_dir, evidence_directory=evidence_dir, kms=self.kms,
                            clock=lambda: self.now)
        permit = gate.admit(ReleaseIntent(intent_id="synthetic-intent", recorded_at=self.now,
            domain="domain", category="approved_external", policy_version="synthetic-policy",
            package_version="synthetic-package", purpose="model-query", tenant_id="tenant",
            caller_id="reader"), EvidenceSpec(plaintext=self.raw, bucket="synthetic-bucket",
                                            record_id="record-from-gate", purpose="model-query"))
        record = parse_record(permit.evidence.path.read_bytes())
        self.assertNotIn(self.raw, permit.evidence.path.read_bytes())
        ticket = self.service.request(self.headers("reader"), record, tenant_id="tenant",
                    purpose=REVIEW_PURPOSE, expires_at=self.now + timedelta(minutes=10))
        self.approve(ticket)
        self.assertEqual(self.raw, self.read(ticket, record=record))

    def test_missing_or_forged_credentials_and_identity_headers_are_audited(self):
        ticket = self.request()
        self.approve(ticket)
        for headers in ({}, self.headers("fake"),
                        self.headers("reader") | {"x-role": "audit-reader"},
                        self.headers("reader") | {"x-domain": "domain"}):
            with self.subTest(headers=list(headers)):
                self.assert_denied(lambda: self.service.read(headers, ticket.ticket_id,
                                                            self.record, purpose=REVIEW_PURPOSE))

    def test_cross_domain_cross_tenant_other_requester_and_wrong_purpose_are_denied(self):
        ticket = self.request()
        self.approve(ticket)
        for name in ("outside", "other-tenant", "other", "wrong-purpose"):
            with self.subTest(name=name):
                self.assert_denied(lambda: self.read(ticket, name=name))
        self.assert_denied(lambda: self.read(ticket, purpose="model-query"))
        self.assertEqual(self.raw, self.read(ticket))

    def test_missing_one_approval_denied_before_kms(self):
        ticket = self.request()
        self.service.approve(self.headers("security"), ticket.ticket_id, role="audit-security-approver")
        with patch.object(self.kms, "unwrap", wraps=self.kms.unwrap) as unwrap:
            self.assert_denied(lambda: self.read(ticket))
            unwrap.assert_not_called()

    def test_self_approval_wrong_role_and_duplicate_role_denied(self):
        ticket = self.request()
        for name, role in (("reader", "audit-security-approver"), ("data", "audit-security-approver"),
                           ("security", "administrator")):
            self.assert_denied(lambda: self.service.approve(self.headers(name), ticket.ticket_id, role=role))
        self.service.approve(self.headers("security"), ticket.ticket_id, role="audit-security-approver")
        self.assert_denied(lambda: self.service.approve(self.headers("both"), ticket.ticket_id,
                                                      role="audit-security-approver"))

    def test_same_person_holding_both_roles_cannot_fill_both_approvals(self):
        ticket = self.request()
        self.service.approve(self.headers("both"), ticket.ticket_id, role="audit-security-approver")
        self.assert_denied(lambda: self.service.approve(self.headers("both"), ticket.ticket_id,
                                                      role="audit-data-approver"))

    def test_expired_and_future_dated_identity_denied(self):
        ticket = self.request()
        self.approve(ticket)
        self.now += timedelta(hours=1)
        self.assert_denied(lambda: self.read(ticket), SafetyCode.AUTH_EXPIRED)
        self.now -= timedelta(hours=2)
        self.assert_denied(lambda: self.read(ticket), SafetyCode.FUTURE_DATED_AUTH)

    def test_ticket_expiration_is_exclusive(self):
        ticket = self.request()
        self.approve(ticket)
        self.now = ticket.expires_at
        self.assert_denied(lambda: self.read(ticket))
        self.assert_denied(lambda: self.service.approve(self.headers("both"), ticket.ticket_id,
                                                      role="audit-data-approver"))

    def test_approver_expiration_blocks_existing_grant(self):
        self.identities["short"] = self.identity("short", {"audit-data-approver"},
                                                expires=self.now + timedelta(minutes=2))
        self.auth = EnterpriseAuthenticator(self.identities)
        self.service = self.make_service()
        ticket = self.request()
        self.service.approve(self.headers("security"), ticket.ticket_id, role="audit-security-approver")
        self.service.approve(self.headers("short"), ticket.ticket_id, role="audit-data-approver")
        self.now += timedelta(minutes=3)
        self.assert_denied(lambda: self.read(ticket))

    def test_kms_delay_past_ticket_expiration_never_releases_plaintext(self):
        ticket = self.request()
        self.approve(ticket)
        real_unwrap = self.kms.unwrap

        def slow_unwrap(*args, **kwargs):
            result = real_unwrap(*args, **kwargs)
            self.now = ticket.expires_at
            return result

        with patch.object(self.kms, "unwrap", side_effect=slow_unwrap):
            self.assert_denied(lambda: self.read(ticket))
        self.assertTrue((self.directory / f"{ticket.ticket_id}.consumed.json").exists())

    def test_kms_delay_past_approver_expiration_never_releases_plaintext(self):
        self.identities["short"] = self.identity("short", {"audit-data-approver"},
                                                expires=self.now + timedelta(seconds=30))
        self.auth = EnterpriseAuthenticator(self.identities)
        self.service = self.make_service()
        ticket = self.request()
        self.service.approve(self.headers("security"), ticket.ticket_id, role="audit-security-approver")
        self.service.approve(self.headers("short"), ticket.ticket_id, role="audit-data-approver")
        real_unwrap = self.kms.unwrap

        def slow_unwrap(*args, **kwargs):
            result = real_unwrap(*args, **kwargs)
            self.now += timedelta(seconds=31)
            return result

        with patch.object(self.kms, "unwrap", side_effect=slow_unwrap):
            self.assert_denied(lambda: self.read(ticket))

    def test_final_audit_delay_past_expiration_never_releases_plaintext(self):
        ticket = self.request()
        self.approve(ticket)
        real_log = self.service._log

        def slow_log(action, outcome, *args, **kwargs):
            real_log(action, outcome, *args, **kwargs)
            if outcome == "accessed":
                self.now = ticket.expires_at

        with patch.object(self.service, "_log", side_effect=slow_log):
            self.assert_denied(lambda: self.read(ticket))

    def test_unexpected_kms_failure_and_invalid_headers_are_audited_without_detail(self):
        ticket = self.request()
        self.approve(ticket)
        with patch.object(self.kms, "unwrap", side_effect=RuntimeError(self.raw.decode())):
            self.assert_denied(lambda: self.read(ticket), SafetyCode.CONTRACT_VIOLATION)
        self.assert_denied(lambda: self.service.read(None, ticket.ticket_id, self.record,
                                                   purpose=REVIEW_PURPOSE))
        for path in self.directory.glob("*.review-event.json"):
            self.assertNotIn(self.raw, path.read_bytes())

    def test_exact_record_and_envelope_binding_prevents_substitution(self):
        ticket = self.request()
        self.approve(ticket)
        changed_ciphertext = self.record.ciphertext[:-1] + bytes([self.record.ciphertext[-1] ^ 1])
        self.assertNotEqual(self.record.ciphertext, changed_ciphertext)
        changed = [self.record.model_copy(update=update) for update in (
            {"record_id": "record-2"}, {"domain": "other-domain"}, {"purpose": "knowledge"},
            {"bucket": "other-bucket"}, {"ciphertext": changed_ciphertext})]
        for record in changed:
            with self.subTest(record=record.record_id):
                self.assert_denied(lambda: self.read(ticket, record=record))
        self.assertEqual(self.raw, self.read(ticket))

    def test_restart_does_not_reopen_consumed_ticket(self):
        ticket = self.request()
        self.approve(ticket)
        self.assertEqual(self.raw, self.read(ticket))
        self.assert_denied(lambda: self.read(ticket, service=self.make_service()))

    def test_concurrent_services_release_single_plaintext(self):
        ticket = self.request()
        self.approve(ticket)

        def attempt(_):
            try:
                return self.read(ticket, service=self.make_service())
            except SafetyError:
                return None

        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(attempt, range(6)))
        self.assertEqual(1, results.count(self.raw))
        self.assertEqual(5, results.count(None))

    def test_stale_lock_and_corrupt_consumption_marker_fail_closed(self):
        ticket = self.request()
        self.approve(ticket)
        lock = self.directory / f"{ticket.ticket_id}.review-lock"
        lock.mkdir()
        self.assert_denied(lambda: self.read(ticket))
        lock.rmdir()  # explicit controlled test recovery, never service fallback
        (self.directory / f"{ticket.ticket_id}.consumed.json").write_bytes(b"")
        self.assert_denied(lambda: self.read(ticket))

    def test_distinct_processes_release_single_plaintext(self):
        ticket = self.request()
        self.approve(ticket)
        context = multiprocessing.get_context("spawn")
        output = context.Queue()
        processes = [context.Process(target=_child_read, args=(str(self.directory), ticket.ticket_id,
            self.record, self.kms.kek_for("audit-evidence", "synthetic-bucket"), self.now, output))
            for _ in range(3)]
        try:
            for process in processes:
                process.start()
            results = [output.get(timeout=30) for _ in processes]
            for process in processes:
                process.join(timeout=30)
                self.assertEqual(0, process.exitcode)
            self.assertEqual(1, results.count(self.raw))
            self.assertEqual(2, results.count(None))
        finally:
            for process in processes:
                if process.is_alive():
                    process.terminate()
                    process.join()
            output.close()

    def test_kms_failure_consumes_ticket_and_denies_without_plaintext(self):
        ticket = self.request()
        self.approve(ticket)
        with patch.object(self.kms, "unwrap", side_effect=KmsUnavailableError):
            self.assert_denied(lambda: self.read(ticket), SafetyCode.KMS_UNAVAILABLE)
        self.assert_denied(lambda: self.read(ticket))

    def test_real_aead_authentication_failure_is_audited_and_consumed(self):
        corrupt = self.record.model_copy(update={"ciphertext": self.record.ciphertext[:-1] +
                                                        bytes([self.record.ciphertext[-1] ^ 1])})
        ticket = self.service.request(self.headers("reader"), corrupt, tenant_id="tenant",
                purpose=REVIEW_PURPOSE, expires_at=self.now + timedelta(minutes=10))
        self.approve(ticket)
        self.assert_denied(lambda: self.read(ticket, record=corrupt), SafetyCode.DECRYPTION_FAILED)
        self.assert_denied(lambda: self.read(ticket, record=corrupt))

    def test_access_audit_failure_never_returns_plaintext_and_consumes_ticket(self):
        ticket = self.request()
        self.approve(ticket)
        real_log = self.service._log

        def fail_access(action, outcome, *args, **kwargs):
            if outcome == "accessed":
                raise SafetyError(SafetyCode.AUDIT_WRITE_FAILED)
            return real_log(action, outcome, *args, **kwargs)

        with patch.object(self.service, "_log", side_effect=fail_access):
            self.assert_denied(lambda: self.read(ticket), SafetyCode.AUDIT_WRITE_FAILED)
        self.assert_denied(lambda: self.read(ticket))

    def test_consume_write_failure_cannot_call_kms(self):
        ticket = self.request()
        self.approve(ticket)
        real_write = self.service._write

        def fail_consumption(name, payload):
            if name.endswith(".consumed.json"):
                raise SafetyError(SafetyCode.AUDIT_WRITE_FAILED)
            real_write(name, payload)

        with patch.object(self.service, "_write", side_effect=fail_consumption), \
             patch.object(self.kms, "unwrap", wraps=self.kms.unwrap) as unwrap:
            self.assert_denied(lambda: self.read(ticket), SafetyCode.AUDIT_WRITE_FAILED)
            unwrap.assert_not_called()

    def test_all_storage_failure_blocks_decryption(self):
        ticket = self.request()
        self.approve(ticket)
        with patch("audit.record_review.durable_commit", side_effect=DurableWriteError("injected")), \
             patch.object(self.kms, "unwrap", wraps=self.kms.unwrap) as unwrap:
            with self.assertRaises(SafetyError) as error:
                self.read(ticket)
            self.assertEqual(SafetyCode.AUDIT_WRITE_FAILED, error.exception.code)
            unwrap.assert_not_called()

    def test_invalid_scope_interval_and_bulk_inputs_are_denied(self):
        for kwargs in ({"tenant_id": "other-tenant"}, {"purpose": "knowledge"},
                       {"expires_at": self.now}, {"expires_at": self.now + timedelta(hours=2)},
                       {"expires_at": datetime(2026, 10, 6)}):
            self.assert_denied(lambda: self.request(**kwargs))
        self.assert_denied(lambda: self.service.request(self.headers("reader"), [self.record],
            tenant_id="tenant", purpose=REVIEW_PURPOSE, expires_at=self.now + timedelta(minutes=10)))
        ticket = self.request()
        self.assert_denied(lambda: self.service.read(self.headers("reader"), "../outside", self.record,
                                                   purpose=REVIEW_PURPOSE))
        self.assertFalse(hasattr(self.service, "export"))
        self.assertFalse(hasattr(self.service, "read_all"))


if __name__ == "__main__":
    unittest.main()
