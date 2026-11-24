"""End-to-end: start the localhost mock target in-process, then prove each
verifier fires on a real HTTP exchange (and stays silent on a benign case).

    python cnc418-redteam/tests/test_verify_against_mock.py
"""
from __future__ import annotations

import json
import pathlib
import sys
import threading
from http.server import ThreadingHTTPServer

_PKG_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PKG_ROOT))
sys.path.insert(0, str(_PKG_ROOT / "targets"))

from redteam.allowlist import Allowlist            # noqa: E402
from redteam.transport import Transport            # noqa: E402
from redteam import verify                          # noqa: E402
import mock_vuln_app                                # noqa: E402


def _start_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), mock_vuln_app.Handler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, f"http://127.0.0.1:{port}"


def main() -> int:
    server, base = _start_server()
    tx = Transport(Allowlist(), run_id="run-test-000000", min_interval_s=0.0)
    failures = 0
    try:
        checks = [
            ("reflected_xss", verify.verify_reflected_xss(tx, base)),
            ("boolean_sqli", verify.verify_boolean_sqli(tx, base)),
            ("time_sqli", verify.verify_time_sqli(tx, base)),
            ("idor", verify.verify_idor(tx, base)),
            ("prompt_injection", verify.verify_prompt_injection(tx, base)),
        ]
        for name, proof in checks:
            if proof is None:
                failures += 1
                print(f"FAIL {name}: expected a Proof, got None")
            else:
                print(f"PASS {name:16} method={proof.method:24} :: {proof.evidence[:60]}...")

        # Negative control: a benign chat message must NOT leak the canary.
        benign = tx.post(
            f"{base}/chat",
            headers={"Content-Type": "application/json"},
            body=json.dumps({"message": "what juice do you have?"}).encode(),
        )
        if "SYS-SECRET-" in benign.body:
            failures += 1
            print("FAIL negative: canary leaked on a benign message")
        else:
            print("PASS negative          benign chat did not leak the canary")

        print(f"\ntransport: sent={tx.stats.sent} blocked={tx.stats.blocked} errors={tx.stats.errors}")
    finally:
        server.shutdown()
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
