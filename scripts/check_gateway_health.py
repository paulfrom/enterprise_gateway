"""Probe the local listener; liveness is separate from readiness/admission.

For TLS, trust the explicitly mounted server certificate for this loopback-only
probe. The public service hostname is validated by actual clients, not here.
"""
from __future__ import annotations

import os
from pathlib import Path
import ssl
import sys
import urllib.request


def main() -> int:
    try:
        port = int(os.environ.get("GATEWAY_PORT", "8080"))
        if not 1 <= port <= 65535:
            raise ValueError("port")
        certificate = os.environ.get("GATEWAY_SSL_CERTFILE", "")
        private_key = os.environ.get("GATEWAY_SSL_KEYFILE", "")
        if bool(certificate) != bool(private_key):
            raise ValueError("TLS pair")
        context = None
        scheme = "http"
        if certificate:
            if not Path(private_key).is_file():
                raise ValueError("TLS key")
            context = ssl.create_default_context(cafile=certificate)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            # The configured leaf/chain is the explicit local trust anchor.
            # Keep certificate verification enabled without requiring the public
            # hostname to appear as 127.0.0.1 in its SAN.
            context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
            context.check_hostname = False
            scheme = "https"
        # Ignore inherited HTTP(S)_PROXY settings for the local probe.
        handlers = [urllib.request.ProxyHandler({})]
        if context is not None:
            handlers.append(urllib.request.HTTPSHandler(context=context))
        opener = urllib.request.build_opener(*handlers)
        with opener.open(f"{scheme}://127.0.0.1:{port}/healthz", timeout=3) as response:
            if response.status != 200:
                return 1
        return 0
    except Exception:
        print("Gateway liveness probe failed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
