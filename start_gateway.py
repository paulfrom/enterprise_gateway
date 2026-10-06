"""Standalone Enterprise Privacy Gateway Launcher.

Features:
- Standalone operation: Direct upstream connection to model providers
- BYOK (Bring Your Own Key): Users supply their own model provider key; billing belongs to the user
- Multi-provider dynamic routing: Supports DeepSeek, OpenAI, Claude, and local models based on request model
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Add src to Python path
ROOT_DIR = Path(__file__).resolve().parent
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import uvicorn

from audit.audit_watermark import AuditWatermarkGuard, WatermarkPolicy
from audit.evidence_gate import EvidenceGate
from detection.detection_orchestrator import DetectionOrchestrator
from detection.dictionary import (
    DictionaryEntry,
    compile_dictionary,
    compute_dictionary_hash,
)
from detection.inference_executor import InferenceExecutor
from detection.recognizers import default_recognizers
from gateway.app import create_app
from gateway.provider_router import ProviderConfig, ProviderRouter, create_provider_pipeline
from infra.envelope_crypto import StaticTestKmsProvider
from infra.spool import SpoolWriter
from policy.policy import CategoryLabel, CategoryRule, ClassificationPolicy
from protocol.admission import AdmissionLimiter
from protocol.identity import TrustedIdentity


def build_app(
    *,
    host: str = "0.0.0.0",
    port: int = 8080,
    providers_config_path: Path | None = None,
    allow_byok: bool = True,
    token: str = "agent-corp-token",
):
    now = datetime.now(timezone.utc)
    domain = "corp-prod"

    # 1. Trusted identity bound to the token
    identity = TrustedIdentity(
        subject_id="workbuddy-agent",
        tenant_id="tenant-corp",
        domain=domain,
        roles=frozenset({"employee", "ai-assistant"}),
        purposes=frozenset({"model-query"}),
        source_acl=frozenset({"worker", "security", "business", "publisher", "reader", "steward"}),
        auth_source="enterprise-iam",
        authenticated_at=now - timedelta(minutes=5),
        expires_at=now + timedelta(days=365),
    )

    # 2. Enterprise dictionary
    entries = (
        DictionaryEntry(text="甲公司", entity_type="ORG"),
        DictionaryEntry(text="乙公司", entity_type="ORG"),
    )
    dictionary = compile_dictionary({
        "dictionary_id": "dict-local",
        "version": "v1",
        "domain": domain,
        "entries": [e.model_dump() for e in entries],
        "sha256": compute_dictionary_hash("dict-local", "v1", domain, entries),
    })

    # 3. Detector with local ONNX model
    ner_dir = ROOT_DIR / "models" / "bert4ner-base-chinese-onnx"
    executor = InferenceExecutor(max_workers=2)
    detector = DetectionOrchestrator(
        recognizers=default_recognizers(),
        dictionary=dictionary,
        ner_package_dir=ner_dir,
        executor=executor,
        ner_timeout=120.0,
    )

    # 4. State directories (runtime persistence)
    runtime_dir = ROOT_DIR / ".runtime_state"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    intents_dir = runtime_dir / "intents"
    evidence_dir = runtime_dir / "evidence"
    spool_dir = runtime_dir / "spool"
    for d in (intents_dir, evidence_dir, spool_dir):
        d.mkdir(parents=True, exist_ok=True)

    kms = StaticTestKmsProvider()
    watermark_guard = AuditWatermarkGuard(
        runtime_dir,
        WatermarkPolicy(0.90, 0.80, 1024),
        probe=lambda p: (1000 * 1024 * 1024, 100 * 1024 * 1024, 900 * 1024 * 1024),
    )
    evidence_gate = EvidenceGate(
        intent_directory=intents_dir,
        evidence_directory=evidence_dir,
        kms=kms,
    )
    spool_writer = SpoolWriter(directory=spool_dir, kms=kms)

    policy = ClassificationPolicy(
        version="v1",
        rules=(CategoryRule(category="STANDARD", label=CategoryLabel.APPROVED_EXTERNAL, scope=domain),),
    )
    limiter = AdmissionLimiter(max_body_bytes=10485760)

    # 5. Load multi-provider dynamic router
    cfg_file = providers_config_path or (ROOT_DIR / "config" / "providers.json")
    if not cfg_file.is_file():
        raise FileNotFoundError(f"Providers configuration not found at {cfg_file}")

    with open(cfg_file, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    pipelines_by_model = {}
    for prov in cfg.get("providers", []):
        prov_cfg = ProviderConfig(
            channel_id=prov["channel_id"],
            protocol=prov["protocol"],
            url=prov["url"],
            models=tuple(prov["models"]),
            credential=prov.get("credential"),
            credential_header=prov.get("credential_header", "authorization"),
            timeout_seconds=float(prov.get("timeout_seconds", 180.0)),
        )
        pipe = create_provider_pipeline(
            prov_cfg,
            domain=domain,
            policy=policy,
            detector=detector,
            admission_limiter=limiter,
            watermark_guard=watermark_guard,
            evidence_gate=evidence_gate,
            spool_writer=spool_writer,
        )
        for m in prov_cfg.models:
            pipelines_by_model[m] = pipe

    router = ProviderRouter(pipelines_by_model)
    app = create_app(
        router=router,
        allow_byok=allow_byok,
        enterprise_credentials={token: identity},
        hmac_key=b"enterprise-local-hmac-key-32bytes-secret!",
    )
    print(f"[Gateway] Started: MULTI-PROVIDER BYOK ROUTER ({len(pipelines_by_model)} models configured)")
    return app


def main():
    parser = argparse.ArgumentParser(description="Start Enterprise Privacy Gateway")
    parser.add_argument("--host", default=os.environ.get("GATEWAY_HOST", "0.0.0.0"), help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=int(os.environ.get("GATEWAY_PORT", "8080")), help="Bind port (default: 8080)")
    parser.add_argument("--config", default=os.environ.get("PROVIDERS_CONFIG"), help="Path to providers.json")
    parser.add_argument("--token", default=os.environ.get("ENTERPRISE_TOKEN", "agent-corp-token"), help="Default enterprise token")

    args = parser.parse_args()
    providers_path = Path(args.config) if args.config else None

    print("\n" + "=" * 65)
    print("      企业隐私脱敏网关服务启动中 (Enterprise Privacy Gateway)")
    print("=" * 65)
    print(f" 服务监听地址 (Base URL): http://{args.host}:{args.port}/v1")
    print(f" 运行模式:                 BYOK 多用户自带密钥 & 多供应商路由")
    print(f" 健康存活探针:             http://{args.host}:{args.port}/healthz")
    print("=" * 65 + "\n")

    app = build_app(
        host=args.host,
        port=args.port,
        providers_config_path=providers_path,
        allow_byok=True,
        token=args.token,
    )

    uvicorn.run(app, host=args.host, port=args.port, access_log=False)


if __name__ == "__main__":
    main()
