"""Every emitted finding must satisfy the shared Finding contract, and a chained
finding must survive into SARIF as a codeFlow. Runs the real agent in-process.

    python cnc418-redteam/tests/test_report_schema.py
"""
from __future__ import annotations

import pathlib
import sys
import threading
from http.server import ThreadingHTTPServer

_PKG_ROOT = pathlib.Path(__file__).resolve().parents[1]
_REPO_ROOT = _PKG_ROOT.parent
sys.path.insert(0, str(_PKG_ROOT))
sys.path.insert(0, str(_PKG_ROOT / "targets"))
sys.path.insert(0, str(_REPO_ROOT))

from redteam.agent import RedTeamAgent        # noqa: E402
from redteam.allowlist import Allowlist       # noqa: E402
from redteam.transport import Transport       # noqa: E402
from redteam import report                     # noqa: E402
import mock_vuln_app                            # noqa: E402

from shared.contracts import AssetProfile, validate  # noqa: E402


def main() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", 0), mock_vuln_app.Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    failures = 0
    try:
        asset = AssetProfile(
            asset_id="asset-0001", ip_or_url=f"http://127.0.0.1:{port}",
            criticality_tier="tier1_critical", mtd_minutes=240, rpo_minutes=60,
            applicable_standards=["ISO_27001"],
        )
        tx = Transport(Allowlist(), run_id="run-test-schema", min_interval_s=0.0)
        result = RedTeamAgent(tx, "run-test-schema").run([asset])

        # 1. every finding validates against the shared contract
        for f in result.findings:
            try:
                validate("finding", f.to_dict())
            except Exception as exc:
                failures += 1
                print(f"FAIL schema: {f.cwe_id}: {exc}")
        print(f"OK   {len(result.findings)} findings validated against the Finding contract")

        # 2. at least one chained finding exists with >= 2 verified steps
        chains = [f for f in result.findings if f.chain]
        assert chains, "expected at least one chained finding"
        steps = chains[0].chain
        assert len(steps) >= 2, "chain must have >= 2 steps"
        assert all(s.exploit_status == "verified" for s in steps), "every chain step must be verified"
        print(f"OK   chain finding has {len(steps)} independently-verified steps")

        # 3. SARIF carries the chain as a codeFlow
        sarif = report.to_sarif(result.findings, "run-test-schema")
        assert sarif["version"] == "2.1.0"
        results = sarif["runs"][0]["results"]
        flows = [r for r in results if "codeFlows" in r]
        assert flows, "expected a SARIF codeFlow for the chained finding"
        locs = flows[0]["codeFlows"][0]["threadFlows"][0]["locations"]
        assert len(locs) >= 2, "codeFlow should list each chain step"
        print(f"OK   SARIF 2.1.0 ok; chain rendered as codeFlow with {len(locs)} steps")

        print(f"\nverified={result.verified_count} rejected={len(result.rejected)}")
    except AssertionError as exc:
        failures += 1
        print(f"FAIL {exc}")
    finally:
        server.shutdown()
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
