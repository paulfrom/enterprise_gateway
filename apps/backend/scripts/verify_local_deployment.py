"""Verify actual local HTTPS processes and an explicitly prepared remote PG schema.

No public supplier is contacted. The only simulated components are the finite
test classifier and the loopback supplier. Detection, encryption, storage,
gateway and worker use the ordinary deployment paths. Runtime secrets remain
in an ignored directory; sanitized execution evidence goes outside the repo.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import secrets
import socket
import ssl
import subprocess
import sys
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

import httpx
import psycopg
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from detection.dictionary import DictionaryEntry, compute_dictionary_hash
from infra.envelope_crypto import decrypt_record, parse_record
from infra.file_kms import FileKmsProvider
from infra.spool_relay import compute_dedup_key
from knowledge.knowledge import Role, TrustedActor
from knowledge.knowledge_events import ObservationEvent
from knowledge.storage import PostgresKnowledgeStorage
from tests.deployment.fixture_runtime import APPROVED_TEXT, LOCAL_TEXT, UNKNOWN_TEXT, TRUTHS


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_manifest():
    files = sorted((ROOT / "src").rglob("*.py")) + [
        ROOT / "scripts" / "verify_local_deployment.py", ROOT / "scripts" / "check_gateway_health.py",
        ROOT / "scripts" / "prepare_knowledge_database.py",
        ROOT / "tests" / "deployment" / "fixture_runtime.py", ROOT / "tests" / "deployment" / "test_fixture_runtime.py",
        ROOT / "start_gateway.py", ROOT / "start_knowledge_worker.py", ROOT / "pyproject.toml", ROOT / "uv.lock"]
    return [{"path": str(p), "sha256": digest(p)} for p in files]


def observation_semantics(event):
    """Compare actual governed content/scope without replay clock randomness."""
    payload = event.model_dump(mode="json")
    payload.pop("observed_at")
    payload.pop("retention_until")
    return json.dumps(payload, sort_keys=True, ensure_ascii=False)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def port_is_closed(port):
    # Windows tree termination precedes final kernel socket teardown. Require
    # the listener actually to disappear, within a finite time budget.
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        with socket.socket() as sock:
            sock.settimeout(1)
            if sock.connect_ex(("127.0.0.1", port)) != 0:
                return True
        time.sleep(.1)
    return False


def certificate_pair(directory):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Controlled deployment test CA")])
    start = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(start - timedelta(minutes=5)).not_valid_after(start + timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                                                       x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256()))
    certfile, keyfile = directory / "test-ca.pem", directory / "server.key"
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return certfile, keyfile


class Verification:
    def __init__(self, output):
        self.output = output
        self.processes = []
        self.result = {"task_id": "P-18/K-02/K-10-local-deployment", "run_id": output.parent.parent.name,
            "target_level": "L2", "achieved_level": None, "result": "fail", "started_at": now(),
            "environment": {"os": platform.platform(), "python": sys.version,
                            "docker": "not_run", "public_supplier": "not_called"},
            "commands": [], "assertions": [], "artifacts": [],
            "review": {"mode": "pending", "unresolved": []},
            "limitations": ["Synthetic finite classifier and loopback supplier; no production admission.",
                            "Native Windows processes; Docker and public supplier not verified."]}

    def check(self, name, condition, **observed):
        self.result["assertions"].append({"test": name, "result": "pass" if condition else "fail",
                                           "observed": observed})
        if not condition:
            raise AssertionError(name)

    def run(self, name, args, env, timeout=90):
        started = now()
        child = subprocess.run(args, cwd=ROOT, env=env, capture_output=True, timeout=timeout)
        log = self.output / (name + ".log")
        log.write_bytes(child.stdout + child.stderr)
        self.result["commands"].append({"kind": name, "cwd": str(ROOT), "argv": args,
              "started_at": started, "exit_code": child.returncode, "output": str(log)})
        return child

    def start(self, name, args, env):
        log = self.output / (name + ".log")
        handle = log.open("wb")
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        process = subprocess.Popen(args, cwd=ROOT, env=env, stdout=handle, stderr=handle,
                                   creationflags=flags)
        command = {"kind": name, "cwd": str(ROOT), "argv": list(args), "started_at": now(),
                   "pid": process.pid, "exit_code": None, "output": str(log)}
        self.result["commands"].append(command)
        item = (process, handle, command)
        self.processes.append(item)
        return item

    def stop(self, item):
        process, handle, command = item
        if handle.closed:
            return
        if process.poll() is None:
            if os.name == "nt":
                # A Windows venv redirector can launch a separate interpreter;
                # stop the entire owned tree, not merely its launcher PID.
                stopped = subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                                         capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
                command["tree_stop_exit_code"] = stopped.returncode
            else:
                process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        command["exit_code"] = process.returncode
        command["stopped_at"] = now()
        command["shutdown"] = "controlled_tree_termination" if os.name == "nt" else "controlled_termination"
        handle.close()

    def close(self):
        for item in reversed(self.processes):
            self.stop(item)


def wait_endpoint(client, url, process, code=200):
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("process exited before readiness")
        try:
            if client.get(url).status_code == code:
                return
        except httpx.HTTPError:
            pass
        time.sleep(.25)
    raise TimeoutError("readiness timeout")


def execute(verify, pg_config, runtime):
    initial_sources = source_manifest()
    verify.result["source_manifest_before"] = initial_sources
    runtime.mkdir(parents=True, exist_ok=False)
    cert, key = certificate_pair(runtime)
    bad_ca_dir = runtime / "wrong-ca"
    bad_ca_dir.mkdir()
    wrong_cert, _ = certificate_pair(bad_ca_dir)
    domain = "deployment-" + uuid4().hex
    tenant = "synthetic-local-deployment"
    subject = "controlled-deployment-worker"
    master = secrets.token_bytes(32)
    byok = ["synthetic-deployment-" + secrets.token_hex(16) for _ in range(2)]
    env = {k: v for k, v in os.environ.items() if not k.startswith("GATEWAY_")}
    env.update(PYTHONPATH=os.pathsep.join((str(ROOT / "src"), str(ROOT))), PYTHONIOENCODING="utf-8",
        GATEWAY_PROCESSING_DOMAIN=domain, GATEWAY_PROCESSING_TENANT=tenant,
        GATEWAY_STATE_DIR=str(runtime / "state"), GATEWAY_EVIDENCE_BUCKET="synthetic-evidence",
        GATEWAY_NER_PACKAGE_DIR=str(ROOT / "models" / "bert4ner-base-chinese-onnx"),
        GATEWAY_KNOWLEDGE_WORKER_SUBJECT=subject, SSL_CERT_FILE=str(cert),
        GATEWAY_SSL_CERTFILE=str(cert), GATEWAY_SSL_KEYFILE=str(key))
    secret_values = {"GATEWAY_KMS_MASTER_KEY": master.hex(), "GATEWAY_HMAC_KEY": secrets.token_hex(32),
                     "GATEWAY_SOURCE_CORRELATION_KEY": secrets.token_hex(32),
                     "GATEWAY_KNOWLEDGE_PG_DSN": pg_config["app_dsn"]}
    for name, value in secret_values.items():
        path = runtime / (name.lower() + ".key")
        path.write_text(value, encoding="ascii")
        env[name + "_FILE"] = str(path)
    dictionary = runtime / "dictionary.json"
    entries = tuple(DictionaryEntry(text=text, entity_type=kind)
                    for text, kind in (("甲公司", "ORG"), ("乙公司", "ORG"), ("张三", "PER")))
    dictionary.write_text(json.dumps({"dictionary_id": "deployment-dict", "version": "v1", "domain": domain,
        "entries": [e.model_dump() for e in entries],
        "sha256": compute_dictionary_hash("deployment-dict", "v1", domain, entries)}), encoding="utf-8")
    policy = runtime / "policy.json"
    policy.write_text(json.dumps({"version": "deployment-synthetic-v1", "rules": [
        {"category": "STANDARD", "label": "approved_external", "scope": domain},
        {"category": "LOCAL_ONLY", "label": "local_only", "scope": domain}]}), encoding="utf-8")
    env.update(GATEWAY_DICTIONARY_FILE=str(dictionary), GATEWAY_POLICY_FILE=str(policy))
    upstream_port, gateway_port = free_port(), free_port()
    providers = runtime / "providers.json"
    providers.write_text(json.dumps({"providers": [
        {"channel_id": "loopback-chat", "protocol": "deepseek-chat-completions",
         "url": f"https://127.0.0.1:{upstream_port}/v1/chat/completions", "models": ["chat-fixture"], "timeout_seconds": 20},
        {"channel_id": "loopback-claude", "protocol": "claude-messages", "credential_header": "x-api-key",
         "url": f"https://127.0.0.1:{upstream_port}/v1/messages", "models": ["claude-fixture"], "timeout_seconds": 20}
    ]}), encoding="utf-8")
    upstream_env = dict(env, DEPLOYMENT_SYNTHETIC_KEYS=json.dumps(byok))
    upstream = verify.start("loopback-supplier", [sys.executable, "-m", "uvicorn",
        "tests.deployment.fixture_runtime:app", "--host", "127.0.0.1", "--port", str(upstream_port),
        "--ssl-certfile", str(cert), "--ssl-keyfile", str(key), "--no-access-log"], upstream_env)
    base = f"https://127.0.0.1:{gateway_port}"
    upstream_base = f"https://127.0.0.1:{upstream_port}"
    client = httpx.Client(verify=ssl.create_default_context(cafile=str(cert)), trust_env=False, timeout=60)
    try:
        wait_endpoint(client, upstream_base + "/status", upstream[0])
        initialized = verify.run("provision-keys", [sys.executable, "start_gateway.py", "--provision-keys"], env)
        verify.check("explicit_persistent_key_provision", initialized.returncode == 0)
        gateway_args = [sys.executable, "start_gateway.py", "--host", "127.0.0.1", "--port", str(gateway_port),
                        "--config", str(providers)]
        gateway = verify.start("gateway-no-classifier", gateway_args, env)
        wait_endpoint(client, base + "/healthz", gateway[0])
        request = {"model": "chat-fixture", "messages": [{"role": "user", "content": APPROVED_TEXT}]}
        response = client.post(base + "/v1/chat/completions", json=request, headers={"Authorization": "Bearer " + byok[0]})
        verify.check("missing_classifier_alive_but_refuses", client.get(base + "/readyz").status_code == 503
                     and response.status_code == 503 and client.get(upstream_base + "/status").json()["calls"] == 0)
        verify.stop(gateway)
        verify.check("unclassified_gateway_process_tree_stopped", port_is_closed(gateway_port))
        gateway_args += ["--classifier", "tests.deployment.fixture_runtime:classify"]
        gateway = verify.start("gateway-classified", gateway_args, env)
        wait_endpoint(client, base + "/readyz", gateway[0])
        probe_env = dict(env, GATEWAY_PORT=str(gateway_port))
        probe = verify.run("health-probe", [sys.executable, "scripts/check_gateway_health.py"], probe_env)
        verify.check("operator_health_probe_supports_tls", probe.returncode == 0)
        refused_tls = False
        try:
            with httpx.Client(verify=ssl.create_default_context(cafile=str(wrong_cert)), trust_env=False) as untrusted:
                untrusted.get(base + "/healthz")
        except httpx.ConnectError:
            refused_tls = True
        verify.check("wrong_ca_refuses_tls", refused_tls)
        for index in range(2):
            response = client.post(base + "/v1/chat/completions", json=request,
                                   headers={"Authorization": "Bearer " + byok[index]})
            verify.check("nonstream_byok_" + str(index + 1), response.status_code == 200
                         and response.json()["choices"][0]["message"]["content"] == APPROVED_TEXT,
                         status_code=response.status_code)
        response = client.post(base + "/v1/chat/completions", json=dict(request, stream=True),
                               headers={"Authorization": "Bearer " + byok[0]})
        frames = [json.loads(line[6:]) for line in response.text.splitlines()
                  if line.startswith("data: ") and line != "data: [DONE]"] if response.status_code == 200 else []
        restored = "".join(f["choices"][0]["delta"].get("content", "") for f in frames)
        verify.check("sse_restores_original_after_complete_stream", response.status_code == 200
                     and restored == APPROVED_TEXT and "data: [DONE]" in response.text, status_code=response.status_code)
        claude = {"model": "claude-fixture", "max_tokens": 100,
                  "messages": [{"role": "user", "content": [{"type": "text", "text": APPROVED_TEXT}]}]}
        response = client.post(base + "/v1/messages", json=claude, headers={"x-api-key": byok[1]})
        verify.check("claude_key_header_and_restoration", response.status_code == 200
                     and response.json()["content"][0]["text"] == APPROVED_TEXT, status_code=response.status_code)
        for name, payload, headers in (
            ("missing_byok", request, {}),
            ("unknown_model", dict(request, model="not-admitted"), {"Authorization": "Bearer " + byok[0]}),
            ("unknown_field", dict(request, upstream_url="https://invalid.example"), {"Authorization": "Bearer " + byok[0]}),
            ("local_only", dict(request, messages=[{"role": "user", "content": LOCAL_TEXT}]), {"Authorization": "Bearer " + byok[0], "x-classification": "STANDARD"}),
            ("unknown_classification", dict(request, messages=[{"role": "user", "content": UNKNOWN_TEXT}]), {"Authorization": "Bearer " + byok[0], "x-classification": "STANDARD"}),
        ):
            before = client.get(upstream_base + "/status").json()["calls"]
            response = client.post(base + "/v1/chat/completions", json=payload, headers=headers)
            after = client.get(upstream_base + "/status").json()["calls"]
            verify.check(name + "_refuses_without_egress", response.status_code >= 400 and after == before,
                         status_code=response.status_code, upstream_count_delta=after-before)
        stats = client.get(upstream_base + "/status").json()
        verify.check("supplier_validates_masking_and_distinct_credentials", stats["calls"] == 4
                     and stats["masked_calls"] == 4 and stats["keys_seen"] == [1, 2]
                     and stats["stream_calls"] == 1 and stats["violations"] == 0, **stats)
        verify.stop(gateway)
        verify.check("classified_gateway_process_tree_stopped", port_is_closed(gateway_port))
        state = runtime / "state"
        kms = FileKmsProvider(state / "keys", master)
        spool = sorted((state / "spool").glob("*.env.json"))
        evidence = sorted((state / "evidence").glob("*.evidence.json"))
        events = [ObservationEvent.model_validate_json(decrypt_record(kms, parse_record(p.read_bytes()))) for p in spool]
        expected_dedup_keys = {compute_dedup_key(event) for event in events}
        distinct_observations = len(expected_dedup_keys)
        expected_semantics = {observation_semantics(event) for event in events}
        verify.check("fixture_has_four_independent_observations_and_two_byok_sources",
                     len(events) == 6 and distinct_observations == 4 and len(expected_semantics) == 4
                     and len({e.source_id for e in events if e.evidence_text == APPROVED_TEXT}) == 2,
                     spool_count=len(events), distinct_observation_count=distinct_observations)
        verify.check("durable_encrypted_evidence_and_local_observations", len(evidence) >= 4 and len(events) >= 4
                     and all(e.source_provenance == "unverified" and e.ownership_status == "unassigned" for e in events)
                     and {APPROVED_TEXT, LOCAL_TEXT, UNKNOWN_TEXT}.issubset({e.evidence_text for e in events}),
                     encrypted_evidence_count=len(evidence), spool_count=len(spool))
        verify.check("audit_ciphertexts_decrypt_after_gateway_exit", all(decrypt_record(kms, parse_record(p.read_bytes())) for p in evidence))
        saved_spool = [(p.name, p.read_bytes()) for p in spool]
        bad_dsn_path = runtime / "failed-pg.key"
        bad_dsn_path.write_text(make_conninfo(pg_config["app_dsn"], host="127.0.0.1", port=str(free_port()), connect_timeout="1"), encoding="ascii")
        failed_env = dict(env, GATEWAY_KNOWLEDGE_PG_DSN_FILE=str(bad_dsn_path))
        failed = verify.run("worker-pg-unavailable", [sys.executable, "start_knowledge_worker.py", "--once"], failed_env)
        verify.check("pg_outage_preserves_every_spool_record", failed.returncode != 0
                     and saved_spool == [(p.name, p.read_bytes()) for p in sorted((state / "spool").glob("*.env.json"))],
                     worker_exit_code=failed.returncode)
        readonly_path = runtime / "readonly-pg.key"
        options = conninfo_to_dict(pg_config["app_dsn"]).get("options", "")
        readonly_path.write_text(make_conninfo(pg_config["app_dsn"],
                                options=options + " -c default_transaction_read_only=on"), encoding="ascii")
        readonly_env = dict(env, GATEWAY_KNOWLEDGE_PG_DSN_FILE=str(readonly_path))
        rejected_transaction = verify.run("worker-pg-transaction-rejected",
                             [sys.executable, "start_knowledge_worker.py", "--once"], readonly_env)
        transaction_stats = {"failure_code": "RELAY_SUBMIT_FAILED"}
        rejected = not rejected_transaction.stdout.strip() and (
            rejected_transaction.stderr.strip() == b"knowledge worker pass rejected: RELAY_SUBMIT_FAILED")
        verify.check("real_pg_transaction_rejection_preserves_spool", rejected_transaction.returncode == 1
                     and rejected
                     and saved_spool == [(p.name, p.read_bytes()) for p in sorted((state / "spool").glob("*.env.json"))],
                     worker_exit_code=rejected_transaction.returncode, **transaction_stats)
        worker = verify.run("worker-pg-recovery", [sys.executable, "start_knowledge_worker.py", "--once"], env)
        recovery_stats = json.loads(worker.stdout) if worker.returncode == 0 else {}
        verify.check("independent_worker_commits_then_deletes_spool", worker.returncode == 0
                     and recovery_stats.get("submitted") == distinct_observations
                     and recovery_stats.get("skipped") == len(spool) - distinct_observations
                     and recovery_stats.get("failed") == 0 and recovery_stats.get("quarantined") == 0
                     and not list((state / "spool").glob("*.env.json")),
                     distinct_observation_count=distinct_observations, spool_count=len(spool), **recovery_stats)
        actor = TrustedActor(subject, tenant, domain, frozenset({Role.KNOWLEDGE_PROCESSOR}),
                             frozenset({"knowledge-accumulation"}))
        storage = PostgresKnowledgeStorage(pg_config["app_dsn"])
        tls_observations = []
        def counts():
            with psycopg.connect(pg_config["app_dsn"]) as conn:
                storage.set_session_identity(conn, actor, processing_acl=(domain + ":restricted-candidate",))
                tls_row = conn.execute("SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()").fetchone()
                verify.check("remote_pg_transport_observed", tls_row is not None and type(tls_row[0]) is bool)
                tls_observations.append(tls_row[0])
                rows = conn.execute("SELECT dedup_key,encrypted_observation FROM knowledge_observations").fetchall()
                candidates = conn.execute("SELECT count(*),bool_and(state='proposed') FROM knowledge_candidates").fetchone()
                published = conn.execute("SELECT count(*) FROM knowledge_publications").fetchone()[0]
                recovered = [ObservationEvent.model_validate_json(decrypt_record(FileKmsProvider(state / "keys", master), parse_record(row[1]))) for row in rows]
                verify.check("remote_pg_exact_observation_dedup_set", {row[0] for row in rows} == expected_dedup_keys,
                             expected_distinct_count=distinct_observations, actual_count=len(rows))
                verify.check("remote_pg_exact_governed_semantics_and_original_retention",
                             {observation_semantics(event) for event in recovered} == expected_semantics
                             and all(any(observation_semantics(event) == observation_semantics(original)
                                 and event.retention_until == original.retention_until for original in events)
                                 for event in recovered), exact_semantic_count=len(expected_semantics))
                verify.check("remote_pg_restricted_unassigned_unverified", len(rows) == distinct_observations
                             and candidates[0] > 0 and candidates[1] and published == 0
                             and all(e.source_provenance == "unverified" and e.ownership_status == "unassigned" for e in recovered),
                             observation_count=len(rows), candidate_count=candidates[0], publication_count=published)
                return len(rows), candidates[0]
        initial_counts = counts()
        for filename, content in saved_spool:
            (state / "spool" / filename).write_bytes(content)
        replay = verify.run("worker-replay-after-restart", [sys.executable, "start_knowledge_worker.py", "--once"], env)
        verify.check("replay_idempotent_and_acknowledged", replay.returncode == 0
                     and json.loads(replay.stdout)["skipped"] == len(spool)
                     and not list((state / "spool").glob("*.env.json")) and counts() == initial_counts)
        gateway = verify.start("gateway-persistent-restart", gateway_args, env)
        wait_endpoint(client, base + "/readyz", gateway[0])
        verify.check("gateway_restart_reopens_existing_keys", client.get(base + "/readyz").status_code == 200)
        verify.stop(gateway)
        verify.check("restarted_gateway_process_tree_stopped", port_is_closed(gateway_port))
        verify.result["remote_pg"] = {"schema": pg_config["schema"], "tls": all(tls_observations),
                                       "tls_session_observations": tls_observations,
                                       "existing_schema_modified": False, "database_persisted": True}
        verify.result["runtime_directory"] = str(runtime)
        verify.result["source_manifest"] = source_manifest()
        verify.check("runtime_sources_stable_during_verification", initial_sources == verify.result["source_manifest"],
                     files_compared=len(initial_sources))
        verify.result["asset_manifest"] = [{"path": str(p), "sha256": digest(p)} for p in
            [providers, dictionary, policy, cert, *sorted((ROOT / "models" / "bert4ner-base-chinese-onnx").iterdir())]]
    finally:
        client.close()
        verify.close()
    secret_needles = [value.encode() for value in secret_values.values()] + [v.encode() for v in byok]
    # A diagnostic may expose only a password rather than its complete DSN.
    # Check the parsed password independently without writing it into evidence.
    password = conninfo_to_dict(pg_config["app_dsn"]).get("password")
    if password:
        secret_needles.append(password.encode())
    truth_needles = [v.encode() for v in (*TRUTHS, APPROVED_TEXT, LOCAL_TEXT, UNKNOWN_TEXT)]
    logs = list(verify.output.glob("*.log"))
    disk = [p for p in (runtime / "state").rglob("*") if p.is_file()]
    verify.check("process_logs_do_not_leak_keys_dsn_or_canaries", all(not any(n in p.read_bytes()
                 for n in secret_needles + truth_needles) for p in logs), files_scanned=len(logs),
                 independent_pg_password_scanned=bool(password))
    verify.check("state_contains_no_plaintext_canaries_or_provider_credentials", all(not any(n in p.read_bytes()
                 for n in [v.encode() for v in byok] + truth_needles) for p in disk), files_scanned=len(disk))
    verify.check("all_started_processes_terminated", all(item[0].poll() is not None for item in verify.processes))
    verify.check("loopback_supplier_process_tree_stopped", port_is_closed(upstream_port))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--pg-config", type=Path, required=True)
    args = parser.parse_args()
    if not args.output_dir.is_absolute() or args.output_dir.resolve().is_relative_to(ROOT):
        parser.error("output-dir must be an absolute evidence directory outside the code repository")
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if (output / "result.json").exists():
        parser.error("refusing to overwrite an existing verification result")
    verify = Verification(output)
    try:
        config = json.loads(args.pg_config.read_text(encoding="utf-8-sig"))
        if not all(isinstance(config.get(key), str) and config[key] for key in ("app_dsn", "schema")):
            raise ValueError("invalid controlled PostgreSQL config")
        execute(verify, config, ROOT / ".runtime_state" / ("local-deploy-" + uuid4().hex))
        verify.result.update(result="pass", achieved_level="L2")
    except Exception as error:
        # Exception messages can contain DSNs/inputs; preserve only static type.
        verify.result["failure_type"] = type(error).__name__
    finally:
        verify.close()
        verify.result["finished_at"] = now()
        verify.result["artifacts"] = [{"path": str(p), "sha256": digest(p)} for p in output.glob("*.log")]
        (output / "result.json").write_text(json.dumps(verify.result, indent=2), encoding="utf-8")
    print(json.dumps({"result": verify.result["result"], "evidence": str(output / "result.json")}))
    return 0 if verify.result["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
