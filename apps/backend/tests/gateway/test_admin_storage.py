"""Durable admin state: credentials, session lifecycle, throttles, restart behavior."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest

from gateway.admin_storage import (
    ABSOLUTE_TIMEOUT_SECONDS, IDLE_TIMEOUT_SECONDS, THROTTLE_MAX_FAILURES,
    THROTTLE_WINDOW_SECONDS, AdminStateAlreadyExists, AdminStateStore,
    AdminStorageUnavailable, SessionInvalid,
)

SRC = Path(__file__).resolve().parents[2] / "src"
SCRIPT_ENV = {**os.environ, "PYTHONPATH": str(SRC)}


def _digest(seed: bytes) -> str:
    return hashlib.sha256(seed).hexdigest()


class FakeClock:
    def __init__(self, start=1_700_000_000.0):
        self.moment = float(start)

    def __call__(self):
        return self.moment

    def advance(self, seconds):
        self.moment += seconds


class AdminStorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "state" / "admin"
        self.clock = FakeClock()
        self.store = AdminStateStore(self.directory, now=self.clock)

    def initialize(self):
        self.store.initialize(salt=b"s" * 16, derived_key=b"d" * 32,
                              scrypt_n=2 ** 17, scrypt_r=8, scrypt_p=1, dklen=32)

    def session(self, seed=b"synthetic-token", *, store=None):
        return (store or self.store).create_session(token_digest=_digest(seed))

    def test_initialize_persists_scrypt_material_with_secret_permissions(self):
        self.initialize()
        credentials = self.store.load_credentials()
        self.assertEqual(credentials.username, "admin")
        self.assertEqual(credentials.salt, b"s" * 16)
        self.assertEqual(credentials.derived_key, b"d" * 32)
        self.assertEqual((credentials.scrypt_n, credentials.scrypt_r, credentials.scrypt_p),
                         (2 ** 17, 8, 1))
        self.assertEqual(credentials.dklen, 32)
        self.assertEqual(len(bytes.fromhex(credentials.generation)), 16)
        mode = stat.S_IMODE
        self.assertEqual(mode(self.directory.stat().st_mode), 0o700)
        self.assertEqual(mode((self.directory / "admin.json").stat().st_mode), 0o600)

    def test_duplicate_initialize_refused_without_overwrite(self):
        self.initialize()
        before = (self.directory / "admin.json").read_bytes()
        with self.assertRaises(AdminStateAlreadyExists):
            self.store.initialize(salt=b"x" * 16, derived_key=b"y" * 32,
                                  scrypt_n=2 ** 17, scrypt_r=8, scrypt_p=1, dklen=32)
        self.assertEqual((self.directory / "admin.json").read_bytes(), before)

    def test_restart_reloads_state_without_reinitialization(self):
        self.initialize()
        record = self.session()
        restarted = AdminStateStore(self.directory, now=self.clock)
        self.assertEqual(restarted.load_credentials().derived_key, b"d" * 32)
        loaded = restarted.validate_session(record.digest, refresh_idle=False)
        self.assertEqual(loaded.digest, record.digest)

    def test_missing_or_corrupt_admin_state_is_unavailable(self):
        with self.assertRaises(AdminStorageUnavailable):
            self.store.load_credentials()
        self.initialize()
        valid = (self.directory / "admin.json").read_bytes()
        for damaged in (b"not-json",
                        json.dumps({**json.loads(valid), "unknown": 1}).encode(),
                        json.dumps({**json.loads(valid), "salt": "zz" * 16}).encode(),
                        json.dumps({**json.loads(valid), "scrypt_n": 2}).encode()):
            (self.directory / "admin.json").write_bytes(damaged)
            with self.assertRaises(AdminStorageUnavailable):
                self.store.load_credentials()
        (self.directory / "admin.json").write_bytes(valid)
        self.store.load_credentials()

    def test_symlinked_admin_directory_is_unavailable(self):
        target = Path(self.temp.name) / "real-admin"
        target.mkdir()
        link = Path(self.temp.name) / "linked-admin"
        try:
            link.symlink_to(target, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"symlink creation unavailable: {type(exc).__name__}")
        with self.assertRaises(AdminStorageUnavailable):
            AdminStateStore(link, now=self.clock)

    def test_refresh_extends_idle_deadline_poll_does_not(self):
        self.initialize()
        record = self.session()
        start = self.clock.moment
        self.assertEqual(record.idle_expires_at, start + IDLE_TIMEOUT_SECONDS)
        self.assertEqual(record.absolute_expires_at, start + ABSOLUTE_TIMEOUT_SECONDS)
        self.clock.advance(600)
        refreshed = self.store.validate_session(record.digest, refresh_idle=True)
        self.assertEqual(refreshed.idle_expires_at, self.clock.moment + IDLE_TIMEOUT_SECONDS)
        self.assertEqual(refreshed.absolute_expires_at, start + ABSOLUTE_TIMEOUT_SECONDS)
        self.clock.advance(600)
        polled = self.store.validate_session(record.digest, refresh_idle=False)
        self.assertEqual(polled.idle_expires_at, refreshed.idle_expires_at)
        still = self.store.validate_session(record.digest, refresh_idle=False)
        self.assertEqual(still.idle_expires_at, refreshed.idle_expires_at)

    def test_idle_timeout_rejects_after_thirty_minutes_without_refresh(self):
        self.initialize()
        record = self.session()
        for _ in range(7):
            self.clock.advance(IDLE_TIMEOUT_SECONDS - 120)
            self.store.validate_session(record.digest, refresh_idle=True)
        self.clock.advance(IDLE_TIMEOUT_SECONDS + 1)
        with self.assertRaises(SessionInvalid) as caught:
            self.store.validate_session(record.digest, refresh_idle=True)
        self.assertEqual(caught.exception.reason, "idle_expired")

    def test_absolute_timeout_rejects_despite_refresh(self):
        self.initialize()
        record = self.session()
        while self.clock.moment < record.absolute_expires_at - IDLE_TIMEOUT_SECONDS:
            self.clock.advance(IDLE_TIMEOUT_SECONDS - 60)
            self.store.validate_session(record.digest, refresh_idle=True)
        self.clock.advance(ABSOLUTE_TIMEOUT_SECONDS)
        with self.assertRaises(SessionInvalid) as caught:
            self.store.validate_session(record.digest, refresh_idle=True)
        self.assertEqual(caught.exception.reason, "absolute_expired")

    def test_revoke_is_durable_across_instances(self):
        self.initialize()
        record = self.session()
        self.store.revoke_session(record.digest)
        with self.assertRaises(SessionInvalid) as caught:
            self.store.validate_session(record.digest, refresh_idle=False)
        self.assertEqual(caught.exception.reason, "revoked")
        restarted = AdminStateStore(self.directory, now=self.clock)
        with self.assertRaises(SessionInvalid):
            restarted.validate_session(record.digest, refresh_idle=True)
        self.store.revoke_session(record.digest)  # idempotent tombstone

    def test_generation_rebuild_invalidates_prior_and_revoked_sessions(self):
        self.initialize()
        record = self.session()
        revoked = self.session(b"synthetic-token-revoked")
        self.store.revoke_session(revoked.digest)
        # Recovery semantics: re-initialization rebuilds the session generation.
        (self.directory / "admin.json").unlink()
        self.store.initialize(salt=b"s" * 16, derived_key=b"d" * 32,
                              scrypt_n=2 ** 17, scrypt_r=8, scrypt_p=1, dklen=32)
        for digest in (record.digest, revoked.digest):
            with self.assertRaises(SessionInvalid) as caught:
                self.store.validate_session(digest, refresh_idle=False)
            self.assertEqual(caught.exception.reason, "generation")

    def test_forged_malformed_and_corrupt_sessions_rejected(self):
        self.initialize()
        record = self.session()
        with self.assertRaises(SessionInvalid):
            self.store.validate_session(_digest(b"forged"), refresh_idle=False)
        for bad in ("", "zz" * 32, record.digest.upper(), record.digest[:-2]):
            with self.assertRaises(SessionInvalid) as caught:
                self.store.validate_session(bad, refresh_idle=False)
            self.assertEqual(caught.exception.reason, "malformed")
        path = self.directory / "sessions" / (record.digest + ".json")
        valid = path.read_bytes()
        for damaged in (b"garbage",
                        json.dumps({**json.loads(valid), "revoked": "no"}).encode(),
                        json.dumps({**json.loads(valid), "digest": _digest(b"other")}).encode()):
            path.write_bytes(damaged)
            with self.assertRaises(SessionInvalid) as caught:
                self.store.validate_session(record.digest, refresh_idle=False)
            self.assertEqual(caught.exception.reason, "corrupt")
        path.write_bytes(valid)
        self.store.validate_session(record.digest, refresh_idle=False)

    def test_session_quota_cleans_expired_and_refuses_when_full(self):
        small = AdminStateStore(Path(self.temp.name) / "quota", now=self.clock, max_sessions=2)
        small.initialize(salt=b"s" * 16, derived_key=b"d" * 32,
                         scrypt_n=2 ** 17, scrypt_r=8, scrypt_p=1, dklen=32)
        first = small.create_session(token_digest=_digest(b"one"))
        second = small.create_session(token_digest=_digest(b"two"))
        with self.assertRaises(AdminStorageUnavailable):
            small.create_session(token_digest=_digest(b"three"))
        # Expired sessions are cleaned so a new login can proceed.
        self.clock.advance(ABSOLUTE_TIMEOUT_SECONDS + 1)
        third = small.create_session(token_digest=_digest(b"three"))
        self.assertEqual(third.digest, _digest(b"three"))
        with self.assertRaises(SessionInvalid):
            small.validate_session(first.digest, refresh_idle=False)
        with self.assertRaises(SessionInvalid):
            small.validate_session(second.digest, refresh_idle=False)

    def test_throttle_window_persistence_and_reset(self):
        for _ in range(THROTTLE_MAX_FAILURES - 1):
            self.assertTrue(self.store.login_permitted("198.51.100.7"))
            self.store.register_login_failure("198.51.100.7")
        self.assertTrue(self.store.login_permitted("198.51.100.7"))
        self.store.register_login_failure("198.51.100.7")
        self.assertFalse(self.store.login_permitted("198.51.100.7"))
        restarted = AdminStateStore(self.directory, now=self.clock)
        self.assertFalse(restarted.login_permitted("198.51.100.7"))
        self.assertTrue(restarted.login_permitted("198.51.100.8"))
        restarted.reset_login_failures("198.51.100.7")
        self.assertTrue(restarted.login_permitted("198.51.100.7"))
        for _ in range(THROTTLE_MAX_FAILURES):
            restarted.register_login_failure("198.51.100.7")
        self.clock.advance(THROTTLE_WINDOW_SECONDS + 1)
        self.assertTrue(restarted.login_permitted("198.51.100.7"))

    def test_throttle_source_quota_is_fail_closed(self):
        small = AdminStateStore(Path(self.temp.name) / "throttle", now=self.clock,
                                max_throttle_sources=2)
        small.register_login_failure("198.51.100.1")
        small.register_login_failure("198.51.100.2")
        with self.assertRaises(AdminStorageUnavailable):
            small.register_login_failure("198.51.100.3")

    def test_auth_events_are_durable_without_secret_material(self):
        self.store.record_auth_event(event="login", outcome="refused", source="198.51.100.7",
                                     category="invalid_credentials")
        self.store.record_auth_event(event="login", outcome="success", source="198.51.100.7",
                                     session_reference=_digest(b"t")[:16])
        events = sorted((self.directory / "events").glob("*.json"))
        self.assertEqual(len(events), 2)
        records = [json.loads(path.read_bytes()) for path in events]
        refused = next(record for record in records if record["outcome"] == "refused")
        self.assertEqual(refused["event"], "login")
        self.assertEqual(refused["outcome"], "refused")
        self.assertEqual(refused["category"], "invalid_credentials")
        self.assertEqual(refused["source"], "198.51.100.7")
        self.assertIsInstance(refused["at"], (int, float))
        with self.assertRaises((ValueError, AdminStorageUnavailable)):
            self.store.record_auth_event(event="explore", outcome="success",
                                         source="198.51.100.7")

    def test_separate_process_reads_committed_state_through_os_lock(self):
        clock = FakeClock(time.time())
        store = AdminStateStore(self.directory, now=clock)
        store.initialize(salt=b"s" * 16, derived_key=b"d" * 32,
                         scrypt_n=2 ** 17, scrypt_r=8, scrypt_p=1, dklen=32)
        record = store.create_session(token_digest=_digest(b"cross-process"))
        script = (
            "from pathlib import Path; import sys; from gateway.admin_storage import "
            "AdminStateStore, SessionInvalid; "
            "store = AdminStateStore(Path(sys.argv[1])); "
            "store.validate_session(sys.argv[2], refresh_idle=False); "
            "store.revoke_session(sys.argv[2]); "
            "print('ok')"
        )
        result = subprocess.run([sys.executable, "-c", script, str(self.directory),
                                 record.digest], capture_output=True, text=True,
                                timeout=30, env=SCRIPT_ENV)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "ok")
        with self.assertRaises(SessionInvalid):
            store.validate_session(record.digest, refresh_idle=False)


if __name__ == "__main__":
    unittest.main()
