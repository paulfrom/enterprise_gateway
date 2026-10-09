"""Serve synthetic history through real local detector/FileKMS/isolated PG.

This test-only process always uses MockTransport and binds to loopback. No real
supplier or business data is contacted. PostgreSQL role/schema are fresh and
are removed by pg_support on normal process exit. Runtime keys are transient.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

import uvicorn

def write_private_key(path: Path, key: bytes):
    """Create a new transient Key file; never replace existing credentials."""
    identity = None
    try:
        with path.open("x", encoding="ascii") as output:
            stat = os.fstat(output.fileno())
            identity = (stat.st_dev, stat.st_ino)
            if os.name == "nt":
                startup = subprocess.STARTUPINFO()
                startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startup.wShowWindow = subprocess.SW_HIDE
                sid = subprocess.run(
                    ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                     "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value"],
                    check=True, capture_output=True, text=True, startupinfo=startup,
                ).stdout.strip()
                if not sid.startswith("S-1-"):
                    raise RuntimeError("Private Key file unavailable")
                subprocess.run(
                    ["icacls.exe", str(path), "/inheritance:r", "/grant:r",
                     "*" + sid + ":(F)", "*S-1-5-18:(F)"],
                    check=True, capture_output=True, startupinfo=startup,
                )
            else:
                os.fchmod(output.fileno(), 0o600)
            output.write(key.hex() + "\n")
            output.flush()
            os.fsync(output.fileno())
        return identity
    except Exception:
        if identity is not None:
            remove_owned_key(path, identity)
        raise RuntimeError("Private Key file unavailable") from None


def remove_owned_key(path, identity):
    try:
        stat = path.stat()
        if (stat.st_dev, stat.st_ino) == identity:
            path.unlink()
    except OSError:
        pass


def seed(runtime):
    from starlette.testclient import TestClient
    from tests.request_history.test_local_e2e import synthetic_requests
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
        response = client.get("/api/requests", headers={"Authorization": "Bearer " + runtime.read_key.hex()})
        if response.status_code != 200 or len(response.json()["items"]) != 4:
            raise RuntimeError("Synthetic history seed failed")
        if sorted(item["status"] for item in response.json()["items"]) != ["blocked", "completed", "completed", "completed"]:
            raise RuntimeError("Synthetic history seed failed")
    finally:
        client.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pg-config", type=Path, required=True, help="Private explicit isolated PostgreSQL test config")
    parser.add_argument("--key-file", type=Path, required=True, help="New transient private file under .pg-runtime")
    parser.add_argument("--port", type=int, default=8876)
    args = parser.parse_args(argv)
    key_path = args.key_file.resolve()
    if not 1 <= args.port <= 65535 or not key_path.is_relative_to((ROOT / ".pg-runtime").resolve()) or key_path.exists():
        print(json.dumps({"started": False, "reason": "invalid_synthetic_preview_options"}))
        return 1
    identity = None
    phase = "configuration"
    try:
        from tests.request_history.test_local_e2e import synthetic_history_runtime
        if not args.pg_config.is_file():
            raise RuntimeError("Explicit PostgreSQL test config required")
        os.environ["GATEWAY_HISTORY_PG_CONFIG"] = str(args.pg_config.resolve())
        key_path.parent.mkdir(parents=True, exist_ok=True)
        phase = "assembly"
        with synthetic_history_runtime() as runtime:
            phase = "seed"
            seed(runtime)
            phase = "private_key"
            identity = write_private_key(key_path, runtime.read_key)
            print(json.dumps({"history_url": "http://127.0.0.1:" + str(args.port) + "/history",
                              "key_file": str(key_path), "synthetic_only": True,
                              "retention_days": 1, "seeded_records": 4}), flush=True)
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
    finally:
        if identity is not None:
            remove_owned_key(key_path, identity)


if __name__ == "__main__":
    sys.exit(main())
