"""Standalone BYOK launcher with explicit operator assets and persistent keys.

The CLI has no default content classifier. An operator may import an approved
server callable; otherwise health is alive and model endpoints/readiness refuse.
No supplier credential is stored here.
"""
from __future__ import annotations

import argparse
from importlib import import_module
import inspect
import os
from pathlib import Path
import re
import ssl
import sys
from typing import Callable

ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR / "src") not in sys.path:
    sys.path.insert(0, str(ROOT_DIR / "src"))

import uvicorn

from audit.audit_watermark import WatermarkPolicy
from detection.dictionary import compile_dictionary
from gateway.runtime import create_runtime_app
from infra.envelope_crypto import KmsUnavailableError
from infra.errors import SafetyCode, SafetyError
from infra.file_kms import FileKmsProvider
from infra.strict_json import parse_strict_json
from policy.policy import load_policy


def _required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value or value.strip() != value:
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, f"required operator setting: {name}")
    return value


def _load_secret(name: str, *, exact_bytes: int | None = None) -> bytes:
    """Exactly one env value or secret file; never emit its contents."""
    value = os.environ.get(name)
    secret_file = os.environ.get(name + "_FILE")
    if (value is None) == (secret_file is None):
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, f"one explicit secret source: {name}")
    failed = False
    try:
        raw = Path(secret_file).read_text(encoding="ascii").strip() if secret_file is not None else value
    except (OSError, UnicodeError):
        failed = True
    if failed:
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "secret file unavailable") from None
    if not isinstance(raw, str) or re.fullmatch(r"[0-9a-f]+", raw) is None or len(raw) % 2:
        raise SafetyError(SafetyCode.INVALID_HMAC_KEY, "invalid operator key encoding")
    key = bytes.fromhex(raw)
    if (exact_bytes is not None and len(key) != exact_bytes) or len(key) < 32:
        raise SafetyError(SafetyCode.INVALID_HMAC_KEY, "invalid operator key size")
    return key


def _reject_asset(_kind):
    raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "invalid operator asset")


def _key_store():
    state = Path(_required("GATEWAY_STATE_DIR"))
    bucket = _required("GATEWAY_EVIDENCE_BUCKET")
    master = _load_secret("GATEWAY_KMS_MASTER_KEY", exact_bytes=32)
    return state, bucket, FileKmsProvider(state / "keys", master)


def _probe_keys(kms: FileKmsProvider, evidence_bucket: str) -> None:
    for purpose, bucket in (("model-query", evidence_bucket),
                            ("knowledge-accumulation:knowledge-spool", "standard-retention")):
        sample = os.urandom(32)
        wrapped = kms.wrap(sample, purpose=purpose, bucket=bucket)
        if kms.unwrap(wrapped, purpose=purpose, bucket=bucket) != sample:
            raise KmsUnavailableError("key readiness refused")


def provision_keys() -> None:
    """Explicit initialization; existing ciphertext must never trigger new keys."""
    state, bucket, kms = _key_store()
    has_records = any(path.exists() and any(path.iterdir())
                      for path in (state / "intents", state / "evidence", state / "spool"))
    if has_records:
        _probe_keys(kms, bucket)
        return
    kms.provision(purpose="model-query", bucket=bucket)
    kms.provision(purpose="knowledge-accumulation:knowledge-spool", bucket="standard-retention")


def build_app(*, providers_config_path: Path | None = None,
              classifier: Callable[[bytes], str] | None = None):
    """One assembly path; policies/dictionary are controlled files, not demos."""
    domain = _required("GATEWAY_PROCESSING_DOMAIN")
    tenant = _required("GATEWAY_PROCESSING_TENANT")
    state = Path(_required("GATEWAY_STATE_DIR"))
    evidence_bucket = _required("GATEWAY_EVIDENCE_BUCKET")
    hmac_key = _load_secret("GATEWAY_HMAC_KEY")
    correlation_key = _load_secret("GATEWAY_SOURCE_CORRELATION_KEY")
    dictionary_data = parse_strict_json(Path(_required("GATEWAY_DICTIONARY_FILE")).read_bytes(),
                                         reject=_reject_asset)
    dictionary = compile_dictionary(dictionary_data)
    policy = load_policy(Path(_required("GATEWAY_POLICY_FILE")).read_bytes())
    _, _, kms = _key_store()
    _probe_keys(kms, evidence_bucket)
    providers = providers_config_path or Path(os.environ.get("PROVIDERS_CONFIG", ROOT_DIR / "config" / "providers.json"))
    return create_runtime_app(provider_config_path=providers, domain=domain, tenant_id=tenant,
        correlation_key=correlation_key, hmac_key=hmac_key, kms=kms,
        dictionary=dictionary, ner_package_dir=Path(_required("GATEWAY_NER_PACKAGE_DIR")),
        state_directory=state, policy=policy, watermark_policy=WatermarkPolicy(),
        evidence_bucket=evidence_bucket, classifier=classifier)


def _load_classifier(reference: str | None) -> Callable[[bytes], str] | None:
    """Import only an operator-selected synchronous module:callable; never probe content."""
    if reference is None:
        return None
    identifier = r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*"
    if re.fullmatch(identifier + ":" + identifier, reference) is None:
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "invalid operator classifier reference")
    module_name, attribute = reference.split(":")
    classifier = import_module(module_name)
    for name in attribute.split("."):
        classifier = getattr(classifier, name)
    if (not callable(classifier) or inspect.isclass(classifier)
            or inspect.iscoroutinefunction(classifier) or inspect.isasyncgenfunction(classifier)
            or inspect.iscoroutinefunction(getattr(classifier, "__call__", None))
            or inspect.isasyncgenfunction(getattr(classifier, "__call__", None))):
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "synchronous operator classifier required")
    inspect.signature(classifier).bind(b"")
    return classifier


def _validate_tls(certfile: str | None, keyfile: str | None) -> None:
    """Validate the same TLS server certificate pair uvicorn will load, before assembly."""
    if certfile is None and keyfile is None:
        return
    if not certfile or not keyfile or certfile.strip() != certfile or keyfile.strip() != keyfile:
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "explicit TLS certificate pair required")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Empty callback prevents an unattended launch from prompting for encrypted keys.
    context.load_cert_chain(certfile=certfile, keyfile=keyfile, password=lambda: "")


def _parse_port(value: str) -> int:
    try:
        port = int(value)
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        raise argparse.ArgumentTypeError("port must be an integer between 1 and 65535") from None
    return port


def main():
    parser = argparse.ArgumentParser(description="Start BYOK privacy gateway")
    parser.add_argument("--host", default=os.environ.get("GATEWAY_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=_parse_port, default=os.environ.get("GATEWAY_PORT", "8080"))
    parser.add_argument("--config", type=Path, default=None)
    parser.add_argument("--classifier", default=os.environ.get("GATEWAY_CLASSIFIER") or None,
                        help="Trusted server classifier as module:callable; absent means no external classification")
    parser.add_argument("--ssl-certfile", default=os.environ.get("GATEWAY_SSL_CERTFILE") or None,
                        help="TLS server certificate PEM; requires --ssl-keyfile")
    parser.add_argument("--ssl-keyfile", default=os.environ.get("GATEWAY_SSL_KEYFILE") or None,
                        help="TLS server private key PEM; requires --ssl-certfile")
    parser.add_argument("--provision-keys", action="store_true",
                        help="Explicitly initialize KEKs in a state directory without records")
    args = parser.parse_args()
    try:
        if args.provision_keys:
            provision_keys()
            print("Controlled local key selectors initialized or verified.")
            return 0
        classifier = _load_classifier(args.classifier)
        _validate_tls(args.ssl_certfile, args.ssl_keyfile)
        app = build_app(providers_config_path=args.config, classifier=classifier)
        print("Gateway assembled; forwarding remains subject to classification and protection gates.")
        uvicorn.run(app, host=args.host, port=args.port, access_log=False,
                    ssl_certfile=args.ssl_certfile, ssl_keyfile=args.ssl_keyfile)
    except Exception:
        # Module imports, TLS loading and runtime assembly may carry operator secrets
        # in exception text. CLI reports only a fixed refusal, without traceback.
        print("Gateway startup refused: operator configuration, assets or keys are missing/invalid.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
