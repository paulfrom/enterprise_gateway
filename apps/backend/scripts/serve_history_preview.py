"""Serve synthetic history through real local detector/FileKMS/isolated PG.

This test-only process always uses MockTransport and binds to loopback. No real
supplier or business data is contacted. PostgreSQL role/schema are fresh and
are removed by pg_support on normal process exit. Runtime keys are transient.
The preview initializes the controlled admin state and signs in through the real
login route; browsing uses the admin session, never a standalone query key.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

import uvicorn


def seed(runtime):
    from starlette.testclient import TestClient
    from tests.request_history.test_local_e2e import admin_login, synthetic_requests
    # The fixture's TestClient adapter models disconnects correctly for the
    # gateway's cancellation checks. Do not enter lifespan here: uvicorn owns
    # detector/egress shutdown after serving the already seeded runtime.
    client = TestClient(runtime.app)
    try:
        for index, (path, headers, payload) in enumerate(synthetic_requests(preview=True)):
            response = client.post(path, headers=headers, json=payload)
            if (index < 3 and response.status_code != 200) or (index == 3 and response.status_code < 400):
                raise RuntimeError("Synthetic history seed failed")
            if "x-request-id" not in response.headers:
                raise RuntimeError("Synthetic history seed failed")
        admin_login(client)
        response = client.get("/api/admin/requests")
        if response.status_code != 200 or len(response.json()["items"]) != 4:
            raise RuntimeError("Synthetic history seed failed")
        if sorted(item["status"] for item in response.json()["items"]) != ["blocked", "completed", "completed", "completed"]:
            raise RuntimeError("Synthetic history seed failed")
    finally:
        client.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pg-config", type=Path, required=True, help="Private explicit isolated PostgreSQL test config")
    parser.add_argument("--port", type=int, default=8876)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        print(json.dumps({"started": False, "reason": "invalid_synthetic_preview_options"}))
        return 1
    phase = "configuration"
    try:
        from tests.request_history.test_local_e2e import synthetic_history_runtime
        if not args.pg_config.is_file():
            raise RuntimeError("Explicit PostgreSQL test config required")
        os.environ["GATEWAY_HISTORY_PG_CONFIG"] = str(args.pg_config.resolve())
        phase = "assembly"
        with synthetic_history_runtime() as runtime:
            phase = "seed"
            seed(runtime)
            print(json.dumps({"login_url": "http://127.0.0.1:" + str(args.port) + "/login",
                              "synthetic_only": True, "retention_days": 1,
                              "seeded_records": 4}), flush=True)
            phase = "serve"
            uvicorn.run(runtime.app, host="127.0.0.1", port=args.port, access_log=False, log_level="warning")
        return 0
    except Exception as error:
        frame = error.__traceback__
        while frame is not None and frame.tb_next is not None:
            frame = frame.tb_next
        print(json.dumps({"started": False, "reason": "synthetic_history_preview_failed",
                          "phase": phase, "exception_class": type(error).__name__,
                          "location": Path(frame.tb_frame.f_code.co_filename).name + ":" + str(frame.tb_lineno)
                          if frame is not None else None}), flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
