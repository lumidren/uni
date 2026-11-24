"""End-to-end Purple Team scenario — the three systems operating as ONE platform.

One `exercise_run_id` threads the whole exercise:

  1. GRC publishes asset criticality profiles.
  2. RED attacks a high-value asset on the allowlist, verifies exploits, and
     reports machine-readable findings (tagged with the run id).
  3. GRC ingests the verified findings  -> inherent risk rises.
  4. BLUE detects the correlated activity, explains it, contains it (with
     human-in-the-loop guardrails), and reports incident KPIs.
  5. GRC ingests the incidents -> residual risk falls; an AAR + breach clock
     are produced.
  6. We print the full traceability chain: asset -> finding -> incident -> risk.

Runs fully offline/in-process (the bridge API wire-protocol is proven separately
in cnc419-grc/tests/test_api.py). No Docker, no network, no API keys.
"""
from __future__ import annotations

import json
import pathlib
import sys
import threading
from http.server import ThreadingHTTPServer

_REPO = pathlib.Path(__file__).resolve().parents[1]
for p in [
    _REPO,
    _REPO / "cnc418-redteam", _REPO / "cnc418-redteam" / "targets",
    _REPO / "cnc411-blueteam", _REPO / "cnc411-blueteam" / "data",
    _REPO / "cnc419-grc",
]:
    sys.path.insert(0, str(p))

from redteam.allowlist import Allowlist        # noqa: E402
from redteam.transport import Transport        # noqa: E402
from redteam.agent import RedTeamAgent          # noqa: E402
import mock_vuln_app                             # noqa: E402

from blueteam.detect import Detector            # noqa: E402
from blueteam.soar import SoarEngine            # noqa: E402
from blueteam.correlate import RedFindingIndex  # noqa: E402
from blueteam.pipeline import BlueTeamPipeline   # noqa: E402
import gen_dataset                               # noqa: E402

from grc.state import GrcState                  # noqa: E402
from shared.contracts import new_exercise_run_id  # noqa: E402


def _hdr(t):
    print("\n" + "=" * 72 + f"\n {t}\n" + "=" * 72)


def main() -> int:
    run_id = new_exercise_run_id()
    print(f"PURPLE TEAM EXERCISE  exercise_run_id = {run_id}")

    # ---------- GRC establishes context ----------
    _hdr("1. GRC publishes asset criticality profiles")
    grc = GrcState(_REPO / "cnc419-grc" / "data" / "assets.json")
    for a in grc.assets:
        print(f"   {a.asset_id:16} {a.criticality_tier:16} {a.ip_or_url}")
    web = grc.asset_by_id("asset-0007")            # the target Red will exercise
    r001_before = grc.register.risks["R-001"]
    print(f"   seed risk R-001 (asset-0007 SQLi): inherent={r001_before.inherent_score} "
          f"residual={r001_before.residual_score}")

    # ---------- RED attacks on the allowlist ----------
    _hdr("2. RED exercises asset-0007 (loopback target) and verifies exploits")
    server = ThreadingHTTPServer(("127.0.0.1", 3000), mock_vuln_app.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        tx = Transport(Allowlist(), run_id=run_id)
        red = RedTeamAgent(tx, run_id)
        red_result = red.run([web])
        print(f"   verified findings: {red_result.verified_count}  (incl. "
              f"{sum(1 for f in red_result.findings if f.chain)} chain)")
        for f in red_result.findings:
            tag = f"chain[{len(f.chain)}]" if f.chain else "single"
            print(f"     {f.finding_id} {f.cwe_id:8} {f.mitre_technique_id:10} {f.exploit_status} {tag}")

        # ---------- GRC ingests verified findings ----------
        _hdr("3. GRC ingests verified RED findings -> inherent risk rises")
        for f in red_result.findings:
            grc.ingest_finding(f.to_dict())
        # also ingest the correlated AD-campaign finding (Red's credential module)
        ad_findings = json.loads((_REPO / "cnc411-blueteam" / "data" / "mock_red_findings.json").read_text())
        for af in ad_findings:
            af["exercise_run_id"] = run_id
            grc.ingest_finding(af)
        print(f"   R-001 inherent {r001_before.inherent_score} "
              f"(raised from seed by verified web finding)")
        r003 = grc.register.risks["R-003"]
        print(f"   R-003 inherent {r003.inherent_score} (raised by AD credential finding)")

        # ---------- BLUE detects, explains, contains ----------
        _hdr("4. BLUE detects the correlated activity, explains, and contains")
        red_index = RedFindingIndex([f.to_dict() for f in red_result.findings] + ad_findings)
        asset_index = {a.asset_id: a for a in grc.assets}
        blue = BlueTeamPipeline(Detector().train(gen_dataset.generate()),
                                SoarEngine(), asset_index, red_index, approver=None)

        stages = [
            # web-tier telemetry of the SQLi burst Red just ran (correlated -> auto-contained)
            {"target_asset": "asset-0007", "asset_os": "linux", "mitre_hint": "T1190",
             "exercise_run_id": run_id, "src_ip": "10.10.9.21", "containment_target": "10.10.9.21",
             "fw_vendor": "fortigate", "detect_latency_s": 11.0, "contain_latency_s": 5.0,
             "recover_latency_s": 65.0,
             "features": {"auth_failures_5m": 9, "distinct_targets_5m": 10, "off_hours": 1,
                          "kerberos_ticket_rate": 0, "dns_query_entropy": 2.0, "dns_bytes_out_kb": 1.0,
                          "sudo_cmd_anomaly": 0, "lateral_conn_count": 3, "new_account_flag": 0}},
            # AD credential attack (high-impact on tier1 -> held for human approval)
            {"target_asset": "asset-ad-dc01", "asset_os": "windows", "mitre_hint": "T1558.003",
             "exercise_run_id": run_id, "containment_target": "svc-sql",
             "detect_latency_s": 22.0, "contain_latency_s": 9.0, "recover_latency_s": 110.0,
             "features": {"auth_failures_5m": 3, "distinct_targets_5m": 10, "off_hours": 1,
                          "kerberos_ticket_rate": 16, "dns_query_entropy": 2.0, "dns_bytes_out_kb": 1.0,
                          "sudo_cmd_anomaly": 0, "lateral_conn_count": 3, "new_account_flag": 0}},
        ]
        blue_incidents = []
        for st in stages:
            res = blue.process_stage(st)
            if res.detected:
                inc = res.incident
                blue_incidents.append(inc)
                held = " [HELD]" if res.held_for_approval else ""
                print(f"   {inc.target_asset:16} {inc.mitre_technique_id:10} -> "
                      f"{inc.containment_action:22} MTTD={inc.mttd_sec}s [{inc.residual_status}]{held}")

        # ---------- GRC ingests incidents ----------
        _hdr("5. GRC ingests BLUE incidents -> residual risk falls; AAR produced")
        for inc in blue_incidents:
            ack = grc.ingest_incident(inc.to_dict())
        print(f"   R-001 (asset-0007) residual now {grc.register.risks['R-001'].residual_score} "
              f"(web attack contained)")
        print(f"   R-003 (asset-ad-dc01) residual now {grc.register.risks['R-003'].residual_score} "
              f"(containment pending human approval -> unchanged)")

        # ---------- traceability ----------
        _hdr("6. Traceability (one exercise_run_id end to end)")
        web_finding = next((f for f in red_result.findings if f.chain), red_result.findings[0])
        web_incident = next((i for i in blue_incidents if i.target_asset == "asset-0007"), None)
        print(f"   asset-0007")
        print(f"     -> RED finding   {web_finding.finding_id} ({web_finding.cwe_id}, verified, "
              f"chain={len(web_finding.chain)})")
        if web_incident:
            print(f"     -> BLUE incident {web_incident.incident_id} "
                  f"({web_incident.containment_action}, {web_incident.residual_status})")
        print(f"     -> GRC risk      R-001 inherent={grc.register.risks['R-001'].inherent_score} "
              f"residual={grc.register.risks['R-001'].residual_score}")
        print(f"     -> run id        {run_id} tags every record above")

        out = _REPO / "integration" / "out"
        out.mkdir(parents=True, exist_ok=True)
        (out / f"exercise_{run_id}.json").write_text(json.dumps({
            "exercise_run_id": run_id,
            "assets": grc.asset_profiles(),
            "red_findings": [f.to_dict() for f in red_result.findings],
            "blue_incidents": [i.to_dict() for i in blue_incidents],
            "risk_register": grc.risk_snapshot(),
            "aars": grc.aars,
        }, indent=2), encoding="utf-8")
        print(f"\n   wrote correlated exercise record -> integration/out/exercise_{run_id}.json")
    finally:
        server.shutdown()
    print("\nDONE — three systems operated as one, with full traceability.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
