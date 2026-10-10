"""Admin knowledge governance HTTP API: auth/CSRF matrix, error mapping, availability shape.

Route enumeration covers the frozen route table end to end: every endpoint refuses
unauthenticated traffic before touching the governance service (call count stays
zero), every write route enforces the same-origin and session-bound CSRF guard as
the rest of the admin console, and strict request bodies reject unknown fields.

The governance service is faked at the frozen T2 surface; dedicated real-PG tests
exercise one honest governance round trip through the HTTP layer.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from uuid import uuid4

from httpx import ASGITransport, AsyncClient

from gateway.admin_auth import SESSION_COOKIE_NAME, AdminAuthService
from gateway.admin_storage import AdminStateStore
from gateway.app import create_app
import gateway.admin_knowledge_api as knowledge_api
from knowledge.governance import (
    AdminActionContext,
    Availability,
    GovernanceError,
    KnowledgeGovernanceService,
    ReuseAsset,
)
from knowledge.storage import KnowledgeSchemaError

from tests.pg_support import prepare_test_database, test_configuration

ORIGIN = "http://knowledge.test"
CANDIDATE_ID = "11111111-2222-3333-4444-555555555555"
PUBLICATION_ID = "66666666-7777-8888-9999-000000000000"

READ_ROUTES = (
    ("GET", "/api/admin/sources"),
    ("GET", "/api/admin/sources/src-1"),
    ("GET", "/api/admin/candidates"),
    ("GET", f"/api/admin/candidates/{CANDIDATE_ID}"),
    ("GET", "/api/admin/publications"),
    ("GET", f"/api/admin/publications/{PUBLICATION_ID}"),
    ("GET", "/api/admin/observations"),
    ("GET", "/api/admin/observations/obs-1"),
)
WRITE_ROUTES = (
    ("POST", "/api/admin/sources/src-1/governance"),
    ("POST", "/api/admin/sources/src-1/withdraw"),
    ("POST", f"/api/admin/candidates/{CANDIDATE_ID}/publish"),
    ("POST", f"/api/admin/candidates/{CANDIDATE_ID}/reject"),
    ("POST", f"/api/admin/candidates/{CANDIDATE_ID}/revise"),
    ("POST", f"/api/admin/publications/{PUBLICATION_ID}/revoke"),
)
ALL_ROUTES = READ_ROUTES + WRITE_ROUTES

NOW = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)
AVAILABILITY = Availability(
    governance_status="publishable",
    blocking_reasons=(),
    eligibility="not_evaluated",
    evaluated_consumer=None,
    evaluated_use=None,
    effective_audiences=("legal",),
    effective_use="contract-review",
    valid_until=NOW + timedelta(days=5),
    delivery_status="pending",
    pending_event_count=1,
    last_attempt_at=None,
    last_error_code=None,
    reuse_assets=(ReuseAsset(
        consumer_id="consumer-1",
        asset_id=PUBLICATION_ID,
        asset_version=3,
        asset_kind="dictionary",
        receipt_id="rcpt-1",
        applied_at=NOW,
        invalidation_status="active",
    ),),
    evidence_status="available",
    evaluated_at=NOW,
    state_version=7,
)

SOURCE_ROW = {
    "source_id": "src-1", "version": "v1", "source_kind": "document",
    "purpose": "contract-review", "acl": ["legal"], "withdrawn": False,
    "observed_at": NOW.isoformat(), "retention_until": (NOW + timedelta(days=60)).isoformat(),
    "independence_verified": True,
}
CANDIDATE_ROW = {
    "candidate_id": CANDIDATE_ID, "claim_id": str(uuid4()), "acl": ["legal"],
    "purpose": "contract-review", "state": "proposed", "rejection_reason": None,
    "candidate_version": 1, "derived_from": None, "updated_at": NOW.isoformat(),
}
PUBLICATION_ROW = {
    "publication_id": PUBLICATION_ID, "candidate_id": CANDIDATE_ID, "candidate_version": 1,
    "intended_use": "contract-review", "consumer_audiences": ["legal"],
    "published_at": NOW.isoformat(), "valid_until": (NOW + timedelta(days=5)).isoformat(),
    "acl": ["legal"], "purpose": "contract-review", "idempotency_key": "idem-1",
}
OBSERVATION_ROW = {
    "dedup_key": "obs-1", "source_id": "src-1", "source_version": "v1",
    "candidate_ids": [CANDIDATE_ID], "acl": ["legal"], "purpose": "contract-review",
    "created_at": NOW.isoformat(),
}


class FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def fetchone(self):
        return self._rows[0] if self._rows else None


class FakeAdminConnection:
    """Scripted admin connection; single-row detail lookups keyed by table."""

    def __init__(self, storage):
        self._storage = storage

    def execute(self, query, params=None):
        for table, row in self._storage.detail_rows.items():
            if f"FROM {table}" in query:
                return FakeResult([row] if row is not None else [])
        return FakeResult([])


class FakeStorage:
    admin_dsn = "fake-admin-dsn"

    def __init__(self):
        self.detail_rows = {}
        self.fail = None

    @contextmanager
    def admin_transaction(self, *, tenant_id, domain):
        if self.fail is not None:
            raise self.fail
        yield FakeAdminConnection(self)


class FakeGovernance:
    """Frozen T2 surface with call recording; canned happy-path data."""

    def __init__(self, tenant_id="tenant-a", domain="domain-b"):
        self._tenant_id = tenant_id
        self._domain = domain
        self._storage = FakeStorage()
        self.calls = []
        self.action_contexts = []
        self.block = threading.Event()
        self.list_sources_result = ([dict(SOURCE_ROW)], None)
        self.list_candidates_result = ([dict(CANDIDATE_ROW)], None)
        self.list_publications_result = ([dict(PUBLICATION_ROW)], None)
        self.list_observations_result = ([dict(OBSERVATION_ROW)], None)
        self.availability_error = None

    def _record(self, name, **kwargs):
        self.calls.append((name, kwargs))

    def list_sources(self, *, status=None, use=None, audience=None, limit=50, cursor=None):
        if self._storage.fail is not None:
            raise self._storage.fail
        self._record("list_sources", status=status, use=use, audience=audience,
                     limit=limit, cursor=cursor)
        return self.list_sources_result

    def list_candidates(self, *, state=None, source_id=None, limit=50, cursor=None):
        self._record("list_candidates", state=state, source_id=source_id,
                     limit=limit, cursor=cursor)
        return self.list_candidates_result

    def list_publications(self, *, limit=50, cursor=None):
        self._record("list_publications", limit=limit, cursor=cursor)
        return self.list_publications_result

    def list_observations(self, *, limit=50, cursor=None):
        self._record("list_observations", limit=limit, cursor=cursor)
        return self.list_observations_result

    def evaluate_availability(self, *, candidate_id=None, publication_id=None,
                              consumer=None, use=None, now=None):
        self._record("evaluate_availability", candidate_id=candidate_id,
                     publication_id=publication_id, consumer=consumer, use=use, now=now)
        if self.availability_error is not None:
            raise self.availability_error
        return AVAILABILITY

    def _action(self, context):
        self.action_contexts.append(context)

    def confirm_source_governance(self, source_id, *, source_version,
                                  expected_governance_version, ownership, use,
                                  audiences, valid_until, basis, context):
        self._record("confirm_source_governance", source_id=source_id,
                     source_version=source_version,
                     expected_governance_version=expected_governance_version,
                     ownership=ownership, use=use, audiences=audiences,
                     valid_until=valid_until, basis=basis)
        self._action(context)
        return "gv-synthetic-1"

    def withdraw_source(self, source_id, *, source_version, basis, context):
        self._record("withdraw_source", source_id=source_id,
                     source_version=source_version, basis=basis)
        self._action(context)
        return None

    def publish_candidate(self, candidate_id, *, expected_version, use, audiences,
                          valid_until, idempotency_key, basis, context):
        self._record("publish_candidate", candidate_id=candidate_id,
                     expected_version=expected_version, use=use, audiences=audiences,
                     valid_until=valid_until, idempotency_key=idempotency_key, basis=basis)
        self._action(context)
        return PUBLICATION_ID

    def reject_candidate(self, candidate_id, *, basis, context):
        self._record("reject_candidate", candidate_id=candidate_id, basis=basis)
        self._action(context)
        return None

    def revise_candidate(self, candidate_id, *, modifications, basis, context):
        self._record("revise_candidate", candidate_id=candidate_id,
                     modifications=modifications, basis=basis)
        self._action(context)
        return str(uuid4())

    def revoke_publication(self, publication_id, *, basis, context):
        self._record("revoke_publication", publication_id=publication_id, basis=basis)
        self._action(context)
        return None


def write_headers(token, csrf, origin=ORIGIN):
    headers = {"cookie": f"{SESSION_COOKIE_NAME}={token}", "origin": origin}
    if csrf is not None:
        headers["x-admin-csrf"] = csrf
    return headers


class KnowledgeApiFixture:
    """Shared admin state with one issued session (real clock, long idle budget)."""

    def __init__(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = AdminStateStore(Path(self.temp.name) / "admin")
        self.store.initialize(salt=b"s" * 16, derived_key=b"d" * 32,
                              scrypt_n=2 ** 17, scrypt_r=8, scrypt_p=1, dklen=32)
        self.service = AdminAuthService(self.store, scope="tenant-a/domain-b")
        seed = b"synthetic-knowledge-session".ljust(32, b"\0")
        self.token = seed.hex()
        self.digest = hashlib.sha256(seed).hexdigest()
        self.store.create_session(self.digest)

    def cleanup(self):
        self.temp.cleanup()

    def app(self, governance):
        return create_app(admin_service=self.service, knowledge_governance=governance)

    def csrf(self, client):
        response = client.get("/api/admin/session",
                              headers={"cookie": f"{SESSION_COOKIE_NAME}={self.token}"})
        assert response.status_code == 200, response.text
        return response.json()["csrf_token"]


class AdminKnowledgeApiTests(unittest.TestCase):
    """Auth/CSRF/validation matrix over the frozen route table with a fake service."""

    def setUp(self):
        self.fixture = KnowledgeApiFixture()
        self.addCleanup(self.fixture.cleanup)
        self.governance = FakeGovernance()
        self.client = TestClientBridge(self.fixture.app(self.governance))

    def tearDown(self):
        self.client.close()

    def auth_headers(self, csrf=True, origin=ORIGIN):
        return write_headers(self.fixture.token, self.fixture.csrf(self.client) if csrf else None,
                             origin=origin)

    # ------------------------------------------------------------------
    # Route enumeration: unauthenticated refuses before any service call.
    # ------------------------------------------------------------------
    def test_every_route_refuses_unauthenticated_without_touching_service(self):
        for method, path in ALL_ROUTES:
            with self.subTest(method=method, path=path):
                response = self.client.request(method, path)
                self.assertEqual(response.status_code, 401, (method, path, response.text))
                self.assertEqual(response.json(), {"error": {"code": "ADMIN_SESSION_INVALID"}})
        self.assertEqual(self.governance.calls, [])
        self.assertEqual(self.governance.action_contexts, [])

    def test_credential_headers_do_not_authenticate_admin_routes(self):
        for headers in ({"authorization": "Bearer " + "0" * 64},
                        {"x-api-key": "vendor"}, {"x-admin-actor": "admin"}):
            for method, path in ALL_ROUTES:
                with self.subTest(headers=headers, path=path):
                    response = self.client.request(method, path, headers=headers)
                    self.assertEqual(response.status_code, 401, (method, path))
        self.assertEqual(self.governance.calls, [])

    # ------------------------------------------------------------------
    # Write routes: same-origin + session-bound CSRF guard.
    # ------------------------------------------------------------------
    def test_write_routes_require_csrf_header(self):
        for method, path in WRITE_ROUTES:
            with self.subTest(path=path):
                response = self.client.request(method, path, headers=self.auth_headers(csrf=False),
                                               json={"basis": "x"})
                self.assertEqual(response.status_code, 403, response.text)
                self.assertEqual(response.json(), {"error": {"code": "ADMIN_CSRF_INVALID"}})
        self.assertEqual(self.governance.calls, [])

    def test_write_routes_reject_foreign_origin(self):
        for method, path in WRITE_ROUTES:
            with self.subTest(path=path):
                response = self.client.request(
                    method, path,
                    headers=self.auth_headers(origin="http://foreign.example"),
                    json={"basis": "x"})
                self.assertEqual(response.status_code, 403, response.text)
                self.assertEqual(response.json(), {"error": {"code": "ADMIN_ORIGIN_REJECTED"}})
        self.assertEqual(self.governance.calls, [])

    def test_write_routes_reject_wrong_csrf_token(self):
        for method, path in WRITE_ROUTES:
            with self.subTest(path=path):
                headers = self.auth_headers()
                headers["x-admin-csrf"] = "0" * 64
                response = self.client.request(method, path, headers=headers, json={"basis": "x"})
                self.assertEqual(response.status_code, 403, response.text)
                self.assertEqual(response.json(), {"error": {"code": "ADMIN_CSRF_INVALID"}})
        self.assertEqual(self.governance.calls, [])

    # ------------------------------------------------------------------
    # Strict request bodies: unknown or malformed fields refuse with 422.
    # ------------------------------------------------------------------
    def test_unknown_request_fields_refuse_with_422(self):
        cases = (
            ("/api/admin/sources/src-1/governance",
             {"source_version": "v1", "ownership": "confirmed", "use": "u",
              "audiences": ["legal"], "valid_until": NOW.isoformat(), "basis": "b",
              "surprise": True}),
            (f"/api/admin/candidates/{CANDIDATE_ID}/publish",
             {"expected_version": 1, "use": "u", "audiences": ["legal"],
              "valid_until": NOW.isoformat(), "basis": "b", "extra": 1}),
            (f"/api/admin/candidates/{CANDIDATE_ID}/revise",
             {"modifications": {}, "basis": "b", "extra": 1}),
            ("/api/admin/sources/src-1/withdraw", {"source_version": "v1", "basis": "b", "extra": 1}),
            (f"/api/admin/candidates/{CANDIDATE_ID}/reject", {"basis": "b", "extra": 1}),
            (f"/api/admin/publications/{PUBLICATION_ID}/revoke", {"basis": "b", "extra": 1}),
        )
        for path, body in cases:
            with self.subTest(path=path):
                response = self.client.post(path, headers=self.auth_headers(), json=body)
                self.assertEqual(response.status_code, 422, response.text)
                self.assertEqual(response.json()["error"]["code"], "ADMIN_REQUEST_INVALID")
        self.assertEqual(self.governance.calls, [])

    def test_malformed_or_incomplete_bodies_refuse_with_422(self):
        cases = (
            ("/api/admin/sources/src-1/governance",
             {"source_version": "v1", "ownership": "confirmed", "use": "u",
              "audiences": ["legal"], "valid_until": "not-a-time", "basis": "b"}),
            ("/api/admin/sources/src-1/governance",
             {"source_version": "v1", "ownership": "maybe", "use": "u",
              "audiences": ["legal"], "valid_until": NOW.isoformat(), "basis": "b"}),
            (f"/api/admin/candidates/{CANDIDATE_ID}/publish",
             {"expected_version": "1", "use": "u", "audiences": ["legal"],
              "valid_until": NOW.isoformat(), "basis": "b"}),
            (f"/api/admin/candidates/{CANDIDATE_ID}/publish",
             {"expected_version": 1, "use": "u", "audiences": [],
              "valid_until": NOW.isoformat(), "basis": "b"}),
            (f"/api/admin/candidates/{CANDIDATE_ID}/revise",
             {"modifications": {"acl": []}, "basis": "b"}),
            ("/api/admin/sources/src-1/withdraw", {"basis": "b"}),
            (f"/api/admin/candidates/{CANDIDATE_ID}/reject", {"basis": " "}),
        )
        for path, body in cases:
            with self.subTest(path=path, body=body):
                response = self.client.post(path, headers=self.auth_headers(), json=body)
                self.assertEqual(response.status_code, 422, response.text)
                self.assertEqual(response.json()["error"]["code"], "ADMIN_REQUEST_INVALID")
        self.assertEqual(self.governance.calls, [])

    def test_duplicate_json_and_oversized_body_refuse_before_governance(self):
        for body in ('{"basis":"first","basis":"second"}', '{"basis":"' + 'x'*16384 + '"}'):
            response = self.client.post(f'/api/admin/candidates/{CANDIDATE_ID}/reject',
                headers=dict(self.auth_headers(), **{'content-type': 'application/json'}), content=body)
            self.assertEqual(response.status_code, 422)
            self.assertEqual(response.json(), {'error': {'code': 'ADMIN_REQUEST_INVALID'}})
        self.assertEqual(self.governance.calls, [])

    def test_naive_valid_until_refuses_with_422(self):
        response = self.client.post(
            "/api/admin/sources/src-1/governance", headers=self.auth_headers(),
            json={"source_version": "v1", "ownership": "confirmed", "use": "u",
                  "audiences": ["legal"], "valid_until": "2027-01-01T00:00:00", "basis": "b"})
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json()["error"]["code"], "ADMIN_REQUEST_INVALID")

    # ------------------------------------------------------------------
    # Query parsing: whitelist, duplicates, bounds.
    # ------------------------------------------------------------------
    def test_bad_list_queries_refuse_without_service_calls(self):
        queries = ("limit=0", "limit=101", "limit=nan", "cursor=" + "c" * 513,
                   "status=unknown", "state=unknown", "use=", "audience=",
                   "source_id=", "limit=1&limit=2", "q=synthetic", "cursor=%E4%B8%AD")
        targets = ("/api/admin/sources", "/api/admin/candidates",
                   "/api/admin/publications", "/api/admin/observations")
        for target in targets:
            for query in queries:
                with self.subTest(target=target, query=query):
                    response = self.client.get(f"{target}?{query}", headers=self.auth_headers())
                    self.assertEqual(response.status_code, 422, response.text)
                    self.assertEqual(response.json()["error"]["code"], "ADMIN_REQUEST_INVALID")
        self.assertEqual(self.governance.calls, [])

    # ------------------------------------------------------------------
    # Unavailable service: the domain reports its real state with 503.
    # ------------------------------------------------------------------
    def test_missing_governance_service_reports_503_on_every_route(self):
        client = TestClientBridge(self.fixture.app(None))
        with client:
            headers = write_headers(self.fixture.token, None)
            response = client.get("/api/admin/session", headers=headers)
            csrf = response.json()["csrf_token"]
            headers = write_headers(self.fixture.token, csrf)
            for method, path in ALL_ROUTES:
                with self.subTest(method=method, path=path):
                    response = client.request(method, path, headers=headers, json={"basis": "x"})
                    self.assertEqual(response.status_code, 503, (method, path, response.text))
                    self.assertEqual(response.json(),
                                     {"error": {"code": "KNOWLEDGE_ADMIN_UNAVAILABLE"}})

    # ------------------------------------------------------------------
    # Happy paths against the fake surface: shape, scope, session binding.
    # ------------------------------------------------------------------
    def test_sources_list_forwards_filters_and_pagination(self):
        response = self.client.get(
            "/api/admin/sources?status=active&use=contract-review&audience=legal&limit=7",
            headers=self.auth_headers())
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["items"], [SOURCE_ROW])
        self.assertIsNone(response.json()["next_cursor"])
        name, kwargs = self.governance.calls[0]
        self.assertEqual(name, "list_sources")
        self.assertEqual(kwargs["status"], "active")
        self.assertEqual(kwargs["use"], "contract-review")
        self.assertEqual(kwargs["audience"], "legal")
        self.assertEqual(kwargs["limit"], 7)

    def test_source_detail_returns_single_row(self):
        self.governance._storage.detail_rows["knowledge_sources"] = SOURCE_ROW
        response = self.client.get("/api/admin/sources/src-1?version=v1",
                                   headers=self.auth_headers())
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["item"], SOURCE_ROW)

    def test_source_detail_not_found_uses_fixed_code(self):
        response = self.client.get("/api/admin/sources/missing?version=v1",
                                   headers=self.auth_headers())
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {"error": {"code": "KNOWLEDGE_SOURCE_NOT_FOUND"}})

    def test_candidate_detail_embeds_frozen_availability_fields(self):
        self.governance._storage.detail_rows["knowledge_candidates"] = CANDIDATE_ROW
        response = self.client.get(f"/api/admin/candidates/{CANDIDATE_ID}",
                                   headers=self.auth_headers())
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual({k: v for k, v in body["item"].items() if k != "availability"}, CANDIDATE_ROW)
        availability = body["item"]["availability"]
        self.assertEqual(set(availability), {
            "governance_status", "blocking_reasons", "eligibility",
            "evaluated_consumer", "evaluated_use", "effective_audiences",
            "effective_use", "valid_until", "delivery_status", "pending_event_count",
            "last_attempt_at", "last_error_code", "reuse_assets", "evidence_status",
            "evaluated_at", "state_version",
        })
        self.assertEqual(availability["eligibility"], "not_evaluated")
        self.assertEqual(availability["evaluated_consumer"], None)
        self.assertEqual(availability["reuse_assets"][0]["asset_id"], PUBLICATION_ID)
        self.assertEqual(availability["reuse_assets"][0]["invalidation_status"], "active")
        name, kwargs = self.governance.calls[-1]
        self.assertEqual(name, "evaluate_availability")
        self.assertEqual(kwargs["candidate_id"], CANDIDATE_ID)
        self.assertEqual(kwargs["consumer"], None)

    def test_candidate_detail_evaluates_requested_consumer_and_use(self):
        self.governance._storage.detail_rows["knowledge_candidates"] = CANDIDATE_ROW
        response = self.client.get(
            f"/api/admin/candidates/{CANDIDATE_ID}?consumer=legal&use=contract-review",
            headers=self.auth_headers())
        self.assertEqual(response.status_code, 200, response.text)
        name, kwargs = self.governance.calls[-1]
        self.assertEqual(kwargs["consumer"], "legal")
        self.assertEqual(kwargs["use"], "contract-review")

    def test_publication_detail_uses_publication_scoped_evaluation(self):
        self.governance._storage.detail_rows["knowledge_publications"] = PUBLICATION_ROW
        response = self.client.get(f"/api/admin/publications/{PUBLICATION_ID}",
                                   headers=self.auth_headers())
        self.assertEqual(response.status_code, 200, response.text)
        name, kwargs = self.governance.calls[-1]
        self.assertEqual(name, "evaluate_availability")
        self.assertEqual(kwargs["publication_id"], PUBLICATION_ID)
        self.assertEqual(kwargs["candidate_id"], None)

    def test_candidate_list_items_embed_availability_consistent_with_detail(self):
        response = self.client.get("/api/admin/candidates?state=proposed&source_id=src-1",
                                   headers=self.auth_headers())
        self.assertEqual(response.status_code, 200, response.text)
        items = response.json()["items"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["candidate_id"], CANDIDATE_ROW["candidate_id"])
        self.assertEqual(items[0]["availability"]["state_version"], 7)
        names = [name for name, _ in self.governance.calls]
        self.assertEqual(names, ["list_candidates", "evaluate_availability"])

    def test_observation_detail_returns_single_row(self):
        self.governance._storage.detail_rows["knowledge_observations"] = OBSERVATION_ROW
        response = self.client.get("/api/admin/observations/obs-1", headers=self.auth_headers())
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["item"], OBSERVATION_ROW)

    # ------------------------------------------------------------------
    # Governance writes: server-built action context, code mapping.
    # ------------------------------------------------------------------
    def _governance_body(self, **overrides):
        body = {"source_version": "v1", "expected_governance_version": None,
                "ownership": "confirmed", "use": "contract-review",
                "audiences": ["legal"], "valid_until": (NOW + timedelta(days=30)).isoformat(),
                "basis": "verified against source"}
        body.update(overrides)
        return body

    def test_governance_confirm_builds_server_action_context(self):
        response = self.client.post("/api/admin/sources/src-1/governance",
                                    headers=self.auth_headers(), json=self._governance_body())
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), {"governance_version_id": "gv-synthetic-1"})
        context = self.governance.action_contexts[0]
        self.assertIsInstance(context, AdminActionContext)
        self.assertEqual(context.actor_id, "admin")
        self.assertEqual(context.session_digest, self.fixture.digest[:16])
        self.assertEqual((context.tenant_id, context.domain), ("tenant-a", "domain-b"))

    def test_publish_body_is_forwarded_verbatim(self):
        body = {"expected_version": 1, "use": "contract-review", "audiences": ["legal"],
                "valid_until": (NOW + timedelta(days=5)).isoformat(),
                "idempotency_key": "idem-1", "basis": "admission verified"}
        response = self.client.post(f"/api/admin/candidates/{CANDIDATE_ID}/publish",
                                    headers=self.auth_headers(), json=body)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), {"publication_id": PUBLICATION_ID})
        name, kwargs = self.governance.calls[-1]
        self.assertEqual(kwargs["expected_version"], 1)
        self.assertEqual(kwargs["idempotency_key"], "idem-1")

    def test_revise_forwards_modifications(self):
        response = self.client.post(
            f"/api/admin/candidates/{CANDIDATE_ID}/revise", headers=self.auth_headers(),
            json={"modifications": {"acl": ["legal"], "purpose": "contract-review"},
                  "basis": "tighten audience"})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("candidate_id", response.json())
        name, kwargs = self.governance.calls[-1]
        self.assertEqual(kwargs["modifications"], {"acl": ["legal"], "purpose": "contract-review"})

    def test_reject_withdraw_revoke_return_confirmation(self):
        for path, expected in (
                (f"/api/admin/candidates/{CANDIDATE_ID}/reject", {"rejected": True}),
                ("/api/admin/sources/src-1/withdraw",
                 {"source_version": "v1", "withdrawn": True}),
                (f"/api/admin/publications/{PUBLICATION_ID}/revoke", {"revoked": True})):
            with self.subTest(path=path):
                body = {"basis": "not acceptable"}
                if "withdraw" in path:
                    body["source_version"] = "v1"
                response = self.client.post(path, headers=self.auth_headers(), json=body)
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(response.json(), expected)

    def test_governance_error_codes_map_to_fixed_statuses(self):
        cases = (
            ("KNOWLEDGE_SOURCE_NOT_FOUND", 404),
            ("KNOWLEDGE_SOURCE_WITHDRAWN", 422),
            ("KNOWLEDGE_SOURCE_EXPIRED", 422),
            ("KNOWLEDGE_GOVERNANCE_VERSION_CONFLICT", 409),
            ("KNOWLEDGE_GOVERNANCE_VERSION_INVALID", 409),
            ("KNOWLEDGE_CANDIDATE_NOT_FOUND", 404),
            ("KNOWLEDGE_CANDIDATE_VERSION_CONFLICT", 409),
            ("KNOWLEDGE_PUBLICATION_NOT_FOUND", 404),
            ("KNOWLEDGE_PUBLISH_REJECTED", 422),
            ("KNOWLEDGE_VALIDITY_EXCEEDS_SOURCE", 422),
            ("KNOWLEDGE_ADMIN_UNAVAILABLE", 503),
            ("AUDIT_WRITE_FAILED", 503),
        )

        def fail(_self, _source_id, **_kwargs):
            raise GovernanceError(code, "synthetic detail never leaves the server")

        for code, status in cases:
            with self.subTest(code=code):
                with patch.object(FakeGovernance, "confirm_source_governance", side_effect=fail,
                                  autospec=True):
                    response = self.client.post("/api/admin/sources/src-1/governance",
                                                headers=self.auth_headers(),
                                                json=self._governance_body())
                self.assertEqual(response.status_code, status, response.text)
                self.assertEqual(response.json(), {"error": {"code": code}})

    def test_publish_rejection_carries_fixed_blocking_reasons(self):
        def reject(_self, _candidate_id, **kwargs):
            raise GovernanceError("KNOWLEDGE_PUBLISH_REJECTED",
                                  blocking_reasons=("AUDIENCE_DENIED",))

        with patch.object(FakeGovernance, "publish_candidate", side_effect=reject, autospec=True):
            response = self.client.post(
                f"/api/admin/candidates/{CANDIDATE_ID}/publish", headers=self.auth_headers(),
                json={"expected_version": 1, "use": "contract-review", "audiences": ["hr"],
                      "valid_until": (NOW + timedelta(days=5)).isoformat(), "basis": "b"})
        self.assertEqual(response.status_code, 422, response.text)
        self.assertEqual(response.json(),
                         {"error": {"code": "KNOWLEDGE_PUBLISH_REJECTED",
                                    "blocking_reasons": ["AUDIENCE_DENIED"]}})

    def test_schema_incompatibility_reports_fixed_503_code(self):
        self.governance._storage.fail = KnowledgeSchemaError("synthetic fingerprint mismatch")
        response = self.client.get("/api/admin/sources", headers=self.auth_headers())
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(),
                         {"error": {"code": "KNOWLEDGE_SCHEMA_INCOMPATIBLE"}})

    def test_unexpected_failures_never_echo_details(self):
        self.governance.list_sources_result = None
        with patch.object(FakeGovernance, "list_sources",
                          side_effect=RuntimeError("SYNTHETIC-private-dsn-detail"), autospec=True):
            response = self.client.get("/api/admin/sources", headers=self.auth_headers())
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"error": {"code": "KNOWLEDGE_ADMIN_UNAVAILABLE"}})
        self.assertNotIn("SYNTHETIC", response.text)


class TestClientBridge:
    """Minimal sync wrapper kept local so threading tests own their clients."""

    def __init__(self, app):
        from starlette.testclient import TestClient
        self._app = app
        self._client = TestClient(app, base_url=ORIGIN)
        self._client.__enter__()

    def request(self, method, path, **kwargs):
        return self._client.request(method, path, **kwargs)

    def get(self, path, **kwargs):
        return self._client.get(path, **kwargs)

    def post(self, path, **kwargs):
        return self._client.post(path, **kwargs)

    def close(self):
        self._client.__exit__(None, None, None)
        for name in ("admin_audit_executor", "admin_knowledge_executor"):
            getattr(self._app.state, name).shutdown(wait=False)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class AdminKnowledgeConcurrencyTests(unittest.TestCase):
    """The knowledge admin domain caps its own concurrency; excess load is a fixed 503."""

    def setUp(self):
        self.fixture = KnowledgeApiFixture()
        self.addCleanup(self.fixture.cleanup)

    def test_fifth_concurrent_operation_gets_fixed_busy_code(self):
        governance = FakeGovernance()
        entered = threading.Barrier(5)
        release = threading.Event()
        def blocking_list_sources(self, **_kwargs):
            entered.wait(5)
            release.wait(10)
            return ([], None)
        app = self.fixture.app(governance)
        outcomes = []
        def worker():
            with TestClientBridge(app) as client:
                outcomes.append(client.get('/api/admin/sources',
                    headers=write_headers(self.fixture.token, None)).status_code)
        with patch.object(FakeGovernance, 'list_sources', blocking_list_sources):
            threads = [threading.Thread(target=worker) for _ in range(4)]
            for thread in threads:
                thread.start()
            try:
                entered.wait(5)
                with TestClientBridge(app) as client:
                    response = client.get('/api/admin/sources', headers=write_headers(self.fixture.token, None))
                    self.assertEqual(response.status_code, 503)
                    self.assertEqual(response.json(), {'error': {'code': 'KNOWLEDGE_ADMIN_UNAVAILABLE'}})
            finally:
                release.set()
                for thread in threads:
                    thread.join(10)
        self.assertEqual(outcomes, [200] * 4)


class AdminKnowledgeLauncherSpecTests(unittest.TestCase):
    """`_admin_knowledge_spec` mirrors the history spec contract (exactly one source)."""

    def test_absent_or_empty_selection_means_unconfigured(self):
        import start_gateway
        with patch.dict("os.environ", {}, clear=True):
            self.assertIsNone(start_gateway._admin_knowledge_spec())
        with patch.dict("os.environ",
                        {"GATEWAY_ADMIN_KNOWLEDGE_PG_DSN": "",
                         "GATEWAY_ADMIN_KNOWLEDGE_PG_DSN_FILE": ""}, clear=True):
            self.assertIsNone(start_gateway._admin_knowledge_spec())

    def test_value_source_loads_and_both_sources_refuse(self):
        import start_gateway
        from infra.errors import SafetyError
        with patch.dict("os.environ", {"GATEWAY_ADMIN_KNOWLEDGE_PG_DSN": "synthetic-dsn"},
                        clear=True):
            self.assertEqual(start_gateway._admin_knowledge_spec(),
                             {"connection_uri": "synthetic-dsn"})
        with patch.dict("os.environ",
                        {"GATEWAY_ADMIN_KNOWLEDGE_PG_DSN": "synthetic-dsn",
                         "GATEWAY_ADMIN_KNOWLEDGE_PG_DSN_FILE": "synthetic-file"}, clear=True):
            with self.assertRaises(SafetyError):
                start_gateway._admin_knowledge_spec()

    def test_secret_file_source_loads(self):
        import start_gateway
        with tempfile.TemporaryDirectory() as directory:
            secret = Path(directory) / "dsn.txt"
            secret.write_text("synthetic-file-dsn", encoding="ascii")
            with patch.dict("os.environ",
                            {"GATEWAY_ADMIN_KNOWLEDGE_PG_DSN_FILE": str(secret)}, clear=True):
                self.assertEqual(start_gateway._admin_knowledge_spec(),
                                 {"connection_uri": "synthetic-file-dsn"})


class AdminKnowledgeRealPgTests(unittest.TestCase):
    """One honest governance round trip through the HTTP layer on real PostgreSQL."""

    @classmethod
    def setUpClass(cls):
        prepare_test_database()
        cls.config = test_configuration()

    def setUp(self):
        self.tenant = "tenant-a"
        self.domain = "pg-" + uuid4().hex[:12]
        prepare_test_database()
        config = test_configuration()
        storage = self.storage = __import__("knowledge.storage", fromlist=["PostgresKnowledgeStorage"]) \
            .PostgresKnowledgeStorage(
                config["app_dsn"], tenant_id=self.tenant, domain=self.domain,
                admin_dsn=config["admin_app_dsn"], admin_role=config["admin_role"])
        self.governance = KnowledgeGovernanceService(
            tenant_id=self.tenant, domain=self.domain, storage=storage)
        self.fixture = KnowledgeApiFixture()
        self.addCleanup(self.fixture.cleanup)
        self.client = TestClientBridge(self.fixture.app(self.governance))

    def tearDown(self):
        self.client.close()

    def _seed_source(self, source_id, *, version="v1", retention_days=60, acl=None):
        import psycopg
        from psycopg import sql
        config = test_configuration()
        now = datetime.now(timezone.utc)
        conn = psycopg.connect(config["admin_app_dsn"])
        try:
            conn.execute(sql.SQL("SET LOCAL ROLE {}").format(
                sql.Identifier(config["admin_role"])))
            conn.execute("SELECT set_config('app.tenant',%s,true)", (self.tenant,))
            conn.execute("SELECT set_config('app.domain',%s,true)", (self.domain,))
            conn.execute("SELECT set_config('app.admin_context','true',true)")
            conn.execute(
                "INSERT INTO knowledge_sources(tenant_id,domain,source_id,version,source_kind,"
                "acl,purpose,observed_at,retention_until,independence_verified)"
                " VALUES (%s,%s,%s,%s,'document',%s,'contract-review',%s,%s,true)",
                (self.tenant, self.domain, source_id, version,
                 list(acl or ("legal",)), now, now + timedelta(days=retention_days)))
            conn.commit()
        finally:
            conn.close()
        return now

    def _auth(self):
        response = self.client.get("/api/admin/session",
                                   headers=write_headers(self.fixture.token, None))
        return write_headers(self.fixture.token, response.json()["csrf_token"])

    def test_governance_confirm_list_detail_withdraw_round_trip(self):
        self._seed_source("pg-src-1")
        headers = self._auth()
        valid_until = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        response = self.client.post(
            "/api/admin/sources/pg-src-1/governance", headers=headers,
            json={"source_version": "v1", "ownership": "confirmed", "use": "contract-review",
                  "audiences": ["legal"], "valid_until": valid_until,
                  "basis": "ownership verified against the signed source"})
        self.assertEqual(response.status_code, 200, response.text)
        governance_version = response.json()["governance_version_id"]
        self.assertTrue(governance_version)

        listing = self.client.get("/api/admin/sources?status=active", headers=headers)
        self.assertEqual(listing.status_code, 200, listing.text)
        item = listing.json()["items"][0]
        self.assertEqual(item["source_id"], "pg-src-1")
        self.assertFalse(item["withdrawn"])

        detail = self.client.get("/api/admin/sources/pg-src-1?version=v1", headers=headers)
        self.assertEqual(detail.status_code, 200, detail.text)
        self.assertEqual(detail.json()["item"]["source_id"], "pg-src-1")

        missing = self.client.get("/api/admin/sources/pg-src-1?version=v9", headers=headers)
        self.assertEqual(missing.status_code, 404)
        self.assertEqual(missing.json(), {"error": {"code": "KNOWLEDGE_SOURCE_NOT_FOUND"}})

        withdraw = self.client.post("/api/admin/sources/pg-src-1/withdraw", headers=headers,
                                    json={"source_version": "v1", "basis": "source recalled"})
        self.assertEqual(withdraw.status_code, 200, withdraw.text)
        self.assertEqual(withdraw.json(), {"source_version": "v1", "withdrawn": True})

        again = self.client.post("/api/admin/sources/pg-src-1/withdraw", headers=headers,
                                 json={"source_version": "v1", "basis": "source recalled"})
        self.assertEqual(again.status_code, 422)
        self.assertEqual(again.json(), {"error": {"code": "KNOWLEDGE_SOURCE_WITHDRAWN"}})

        withdrawn = self.client.get("/api/admin/sources?status=withdrawn", headers=headers)
        self.assertEqual([row["source_id"] for row in withdrawn.json()["items"]],
                         ["pg-src-1"])

    def test_runtime_restricted_pool_preserves_schema_limits_connections_and_recovers(self):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo
        import start_gateway
        config = test_configuration()
        password = uuid4().hex
        with psycopg.connect(config['admin_app_dsn']) as owner:
            owner.execute(sql.SQL('ALTER ROLE {} LOGIN PASSWORD {}').format(
                sql.Identifier(config['admin_role']), sql.Literal(password)))
        dsn = make_conninfo(config['admin_app_dsn'], user=config['admin_role'], password=password)
        governance = start_gateway._assemble_admin_knowledge({'connection_uri': dsn}, tenant=self.tenant, domain=self.domain)
        storage = governance._storage
        self.addCleanup(storage.close)
        self.assertEqual(storage._pool.maxsize, 2)
        self.assertEqual(storage._pool.qsize(), 2)
        scope = dict(tenant_id=self.tenant, domain=self.domain)
        with storage.admin_transaction(**scope) as first:
            self.assertEqual(first.execute('SHOW search_path').fetchone()[0], config['schema'])
            self.assertEqual(first.execute('SHOW statement_timeout').fetchone()[0], '5s')
            with storage.admin_transaction(**scope) as second:
                self.assertNotEqual(first.info.backend_pid, second.info.backend_pid)
                self.assertEqual(storage._pool.qsize(), 0)
                with patch.object(storage._pool, 'get', side_effect=__import__('queue').Empty):
                    with self.assertRaises(__import__('queue').Empty):
                        with storage.admin_transaction(**scope):
                            pass
        damaged = storage._pool.get()
        damaged.close()
        storage._pool.put(damaged)
        # FIFO reaches the damaged connection on the second checkout.
        with storage.admin_transaction(**scope):
            pass
        with storage.admin_transaction(**scope) as recovered:
            self.assertFalse(recovered.closed)
            self.assertEqual(recovered.execute('SHOW statement_timeout').fetchone()[0], '5s')

    def test_runtime_rejects_management_ownership_of_non_sources_objects(self):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo
        import start_gateway
        config = test_configuration()
        password = uuid4().hex
        with psycopg.connect(config['admin_app_dsn']) as owner:
            owner_role = owner.execute('SELECT current_user').fetchone()[0]
            owner.execute(sql.SQL('ALTER ROLE {} LOGIN PASSWORD {}').format(
                sql.Identifier(config['admin_role']), sql.Literal(password)))
        dsn = make_conninfo(config['admin_app_dsn'], user=config['admin_role'], password=password)
        for table in ('knowledge_publications', 'knowledge_governance_versions', 'knowledge_admin_actions'):
            with self.subTest(table=table):
                try:
                    with psycopg.connect(config['admin_app_dsn']) as owner:
                        owner.execute(sql.SQL('ALTER TABLE {} OWNER TO {}').format(
                            sql.Identifier(table), sql.Identifier(config['admin_role'])))
                    with self.assertRaises(ValueError):
                        start_gateway._assemble_admin_knowledge({'connection_uri': dsn}, tenant=self.tenant, domain=self.domain)
                finally:
                    with psycopg.connect(config['admin_app_dsn']) as owner:
                        owner.execute(sql.SQL('ALTER TABLE {} OWNER TO {}').format(
                            sql.Identifier(table), sql.Identifier(owner_role)))
                        owner.execute(sql.SQL('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {} TO {}').format(
                            sql.Identifier(config['schema']), sql.Identifier(config['admin_role'])))
        # An indirect NOINHERIT path to a non-privileged table owner is equally forbidden.
        reachable_owner = 'owner_' + uuid4().hex[:16]
        try:
            with psycopg.connect(config['admin_app_dsn']) as owner:
                owner.execute(sql.SQL('CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS').format(sql.Identifier(reachable_owner)))
                owner.execute(sql.SQL('GRANT USAGE ON SCHEMA {} TO {}').format(sql.Identifier(config['schema']), sql.Identifier(reachable_owner)))
                owner.execute(sql.SQL('ALTER TABLE knowledge_publications OWNER TO {}').format(sql.Identifier(reachable_owner)))
                owner.execute(sql.SQL('GRANT {} TO {} WITH INHERIT FALSE').format(sql.Identifier(reachable_owner), sql.Identifier(config['admin_role'])))
            with self.assertRaises(ValueError):
                start_gateway._assemble_admin_knowledge({'connection_uri': dsn}, tenant=self.tenant, domain=self.domain)
        finally:
            with psycopg.connect(config['admin_app_dsn']) as owner:
                owner.execute(sql.SQL('ALTER TABLE knowledge_publications OWNER TO {}').format(sql.Identifier(owner_role)))
                owner.execute(sql.SQL('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {} TO {}').format(
                    sql.Identifier(config['schema']), sql.Identifier(config['admin_role'])))
                owner.execute(sql.SQL('REVOKE {} FROM {}').format(sql.Identifier(reachable_owner), sql.Identifier(config['admin_role'])))
                owner.execute(sql.SQL('DROP OWNED BY {}').format(sql.Identifier(reachable_owner)))
                owner.execute(sql.SQL('DROP ROLE {}').format(sql.Identifier(reachable_owner)))

    def test_conflicting_expected_governance_version_is_409(self):
        self._seed_source("pg-src-2")
        headers = self._auth()
        valid_until = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        body = {"source_version": "v1", "expected_governance_version": str(uuid4()),
                "ownership": "confirmed", "use": "contract-review",
                "audiences": ["legal"], "valid_until": valid_until, "basis": "b"}
        response = self.client.post("/api/admin/sources/pg-src-2/governance",
                                    headers=headers, json=body)
        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(response.json(),
                         {"error": {"code": "KNOWLEDGE_GOVERNANCE_VERSION_CONFLICT"}})



class AdminCapabilityAssemblyTests(unittest.TestCase):
    def setUp(self):
        from tests.gateway.test_runtime import RuntimeAssemblyTests
        self.runtime_fixture = RuntimeAssemblyTests('test_launcher_secret_file_and_ambiguous_sources')
        self.runtime_fixture.setUp()
        self.addCleanup(self.runtime_fixture.doCleanups)

    def test_optional_knowledge_failures_leave_model_factory_and_audit_assembled(self):
        import start_gateway
        fixture = self.runtime_fixture
        for error in (RuntimeError('connection unavailable'), KnowledgeSchemaError('schema mismatch')):
            with self.subTest(error=type(error).__name__), patch.dict('os.environ', dict(fixture.operator_env,
                GATEWAY_ADMIN_KNOWLEDGE_PG_DSN='synthetic-management-dsn'), clear=True), \
                patch.object(start_gateway, '_assemble_admin_knowledge', side_effect=error), \
                patch.object(start_gateway, 'create_runtime_app', return_value='model-app') as factory:
                self.assertEqual(start_gateway.build_app(providers_config_path=fixture.provider_file), 'model-app')
                arguments = factory.call_args.kwargs
                self.assertIsNotNone(arguments['audit_reader'])
                self.assertEqual(arguments['audit_builder']._batch_limit, 200)
                self.assertEqual(arguments['domain'], fixture.domain)
                self.assertTrue(arguments['dictionary'])
                governance = arguments['knowledge_governance']
                if isinstance(error, KnowledgeSchemaError):
                    self.assertIs(governance, error)
                    admin = KnowledgeApiFixture()
                    try:
                        with TestClientBridge(admin.app(governance)) as client:
                            response = client.get('/api/admin/sources', headers=write_headers(admin.token, None))
                            self.assertEqual(response.status_code, 503)
                            self.assertEqual(response.json(), {'error': {'code': 'KNOWLEDGE_SCHEMA_INCOMPATIBLE'}})
                    finally:
                        admin.cleanup()
                else:
                    self.assertIsNone(governance)

    def test_catalog_builder_runs_only_during_runtime_lifespan_and_stops(self):
        from unittest.mock import Mock
        from detection.detection_orchestrator import DetectionOrchestrator
        fixture = self.runtime_fixture
        built = threading.Event()
        builder = Mock()
        builder.build_once.side_effect = built.set
        # This check needs runtime resource/lifecycle assembly, without inference.
        with patch('gateway.runtime.DetectionOrchestrator', wraps=DetectionOrchestrator) as detector_factory:
            app = fixture.app(audit_builder=builder)
        self.assertFalse(built.is_set())
        from starlette.testclient import TestClient
        with TestClient(app):
            self.assertTrue(built.wait(5))
            self.assertIsNone(app.state.audit_catalog_error_code)
        count = builder.build_once.call_count
        self.assertTrue(app.state.runtime_closed)
        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
