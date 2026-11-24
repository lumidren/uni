"""Bridge API smoke test: start the GRC API in-process and exercise the three
cross-course endpoints plus contract rejection.

    python cnc419-grc/tests/test_api.py
"""
from __future__ import annotations

import json
import pathlib
import sys
import threading
import urllib.request
from http.server import ThreadingHTTPServer

_PKG_ROOT = pathlib.Path(__file__).resolve().parents[1]
_REPO_ROOT = _PKG_ROOT.parent
sys.path.insert(0, str(_PKG_ROOT))
sys.path.insert(0, str(_REPO_ROOT))

from grc.api import Handler  # noqa: E402


def _req(method, url, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method,
                               headers={"Content-Type": "application/json",
                                        "X-Exercise-Run-ID": "run-test-grc"})
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def main() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    failures = 0
    try:
        # publish assets
        code, assets = _req("GET", f"{base}/api/v1/assets/profile")
        print(f"GET assets -> {code}, {len(assets)} profiles")
        failures += 0 if (code == 200 and len(assets) >= 1) else 1

        # ingest a verified finding
        finding = {
            "finding_id": "find-zzz111", "exercise_run_id": "run-test-grc",
            "target_asset": "asset-0007", "cwe_id": "CWE-89", "stride_category": "tampering",
            "mitre_technique_id": "T1190", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "exploit_status": "verified",
            "verified_poc": {"method": "boolean_blind_inference", "evidence": "row delta"},
        }
        code, ack = _req("POST", f"{base}/api/v1/findings", finding)
        print(f"POST finding -> {code}, updated_risks={ack.get('updated_risks')}")
        failures += 0 if (code == 201 and ack.get("updated_risks")) else 1

        # ingest an incident -> AAR + breach notification come back
        incident = {
            "incident_id": "inc-zzz222", "exercise_run_id": "run-test-grc",
            "target_asset": "asset-0007", "mitre_technique_id": "T1190",
            "mttd_sec": 14.2, "mttc_sec": 31.8, "mttr_sec": 95.0,
            "containment_action": "block_ip", "residual_status": "contained",
            "linked_finding_id": "find-zzz111",
        }
        code, ack = _req("POST", f"{base}/api/v1/incidents", incident)
        print(f"POST incident -> {code}, aar_lessons={len(ack.get('aar', {}).get('lessons_learned', []))}, "
              f"breach={list(ack.get('breach_notification', {}).get('notification_deadlines', {}).keys())}")
        failures += 0 if (code == 201 and "aar" in ack) else 1

        # malformed finding is rejected with 400
        code, err = _req("POST", f"{base}/api/v1/findings", {"finding_id": "bad"})
        print(f"POST bad finding -> {code} ({err.get('error')})")
        failures += 0 if code == 400 else 1

        print("\ntest_api:", "PASS" if not failures else f"FAIL ({failures})")
    finally:
        server.shutdown()
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
