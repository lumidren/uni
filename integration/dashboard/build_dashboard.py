"""Generate a self-contained Purple Team dashboard (dashboard.html).

Runs the three systems in-process, collects the correlated exercise data plus the
Blue detector's confusion matrix and the GRC conflict set, and writes a single
HTML file with the data embedded (no server, no build step, opens by itself).

    python integration/dashboard/build_dashboard.py
"""
from __future__ import annotations

import datetime as _dt
import json
import pathlib
import sys
import threading
from http.server import ThreadingHTTPServer

_REPO = pathlib.Path(__file__).resolve().parents[2]
for p in [
    _REPO,
    _REPO / "cnc418-redteam", _REPO / "cnc418-redteam" / "targets",
    _REPO / "cnc411-blueteam", _REPO / "cnc411-blueteam" / "data",
    _REPO / "cnc419-grc",
]:
    sys.path.insert(0, str(p))

from redteam.allowlist import Allowlist            # noqa: E402
from redteam.transport import Transport            # noqa: E402
from redteam.agent import RedTeamAgent              # noqa: E402
import mock_vuln_app                                # noqa: E402

from blueteam.detect import Detector               # noqa: E402
from blueteam.soar import SoarEngine               # noqa: E402
from blueteam.correlate import RedFindingIndex     # noqa: E402
from blueteam.pipeline import BlueTeamPipeline      # noqa: E402
import gen_dataset                                  # noqa: E402

from grc.state import GrcState                     # noqa: E402
from grc.mapping import MappingEngine              # noqa: E402
from grc.frameworks import REQUIREMENTS, CONTROLS  # noqa: E402
from shared.contracts import new_exercise_run_id   # noqa: E402

_HERE = pathlib.Path(__file__).resolve().parent


def collect() -> dict:
    run_id = new_exercise_run_id()
    grc = GrcState(_REPO / "cnc419-grc" / "data" / "assets.json")

    # ---- Red ----
    server = ThreadingHTTPServer(("127.0.0.1", 3000), mock_vuln_app.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        web = grc.asset_by_id("asset-0007")
        tx = Transport(Allowlist(), run_id=run_id)
        red = RedTeamAgent(tx, run_id).run([web])
    finally:
        server.shutdown()

    for f in red.findings:
        grc.ingest_finding(f.to_dict())
    ad_findings = json.loads((_REPO / "cnc411-blueteam" / "data" / "mock_red_findings.json").read_text())
    for af in ad_findings:
        af["exercise_run_id"] = run_id
        grc.ingest_finding(af)

    # ---- Blue ----
    detector = Detector().train(gen_dataset.generate())
    red_index = RedFindingIndex([f.to_dict() for f in red.findings] + ad_findings)
    asset_index = {a.asset_id: a for a in grc.assets}
    blue = BlueTeamPipeline(detector, SoarEngine(), asset_index, red_index, approver=None)
    stages = [
        {"target_asset": "asset-0007", "asset_os": "linux", "mitre_hint": "T1190",
         "exercise_run_id": run_id, "containment_target": "10.10.9.21", "fw_vendor": "fortigate",
         "detect_latency_s": 11.0, "contain_latency_s": 5.0, "recover_latency_s": 65.0,
         "features": {"auth_failures_5m": 9, "distinct_targets_5m": 10, "off_hours": 1,
                      "kerberos_ticket_rate": 0, "dns_query_entropy": 2.0, "dns_bytes_out_kb": 1.0,
                      "sudo_cmd_anomaly": 0, "lateral_conn_count": 3, "new_account_flag": 0}},
        {"target_asset": "asset-ad-dc01", "asset_os": "windows", "mitre_hint": "T1558.003",
         "exercise_run_id": run_id, "containment_target": "svc-sql",
         "detect_latency_s": 22.0, "contain_latency_s": 9.0, "recover_latency_s": 110.0,
         "features": {"auth_failures_5m": 3, "distinct_targets_5m": 10, "off_hours": 1,
                      "kerberos_ticket_rate": 16, "dns_query_entropy": 2.0, "dns_bytes_out_kb": 1.0,
                      "sudo_cmd_anomaly": 0, "lateral_conn_count": 3, "new_account_flag": 0}},
        {"target_asset": "asset-lin-web01", "asset_os": "linux", "mitre_hint": "T1071.004",
         "exercise_run_id": run_id, "containment_target": "10.10.9.21", "fw_vendor": "cisco_asa",
         "detect_latency_s": 16.0, "contain_latency_s": 4.0, "recover_latency_s": 50.0,
         "features": {"auth_failures_5m": 1, "distinct_targets_5m": 1, "off_hours": 0,
                      "kerberos_ticket_rate": 0, "dns_query_entropy": 4.2, "dns_bytes_out_kb": 90,
                      "sudo_cmd_anomaly": 0, "lateral_conn_count": 2, "new_account_flag": 0}},
    ]
    incidents = []
    for st in stages:
        res = blue.process_stage(st)
        if res.detected:
            inc = res.incident
            incidents.append({
                "incident_id": inc.incident_id, "asset": inc.target_asset,
                "mitre": inc.mitre_technique_id, "action": inc.containment_action,
                "mttd": inc.mttd_sec, "mttc": inc.mttc_sec, "mttr": inc.mttr_sec,
                "residual": inc.residual_status, "held": res.held_for_approval,
                "rationale": (inc.explanation or {}).get("rationale", ""),
            })
            grc.ingest_incident(inc.to_dict())

    # ---- detector confusion matrix ----
    _, test = gen_dataset.split(gen_dataset.generate())
    cm = detector.evaluate(test).report()

    # ---- GRC mapping / conflicts ----
    engine = MappingEngine(REQUIREMENTS, CONTROLS)
    mappings = engine.map_all()
    conflicts = engine.detect_conflicts()

    # ---- assemble ----
    findings = []
    for f in red.findings:
        findings.append({
            "finding_id": f.finding_id, "cwe": f.cwe_id, "mitre": f.mitre_technique_id,
            "stride": f.stride_category, "status": f.exploit_status,
            "chain": [{"step": s.step, "name": s.name, "mitre": s.mitre_technique_id,
                       "status": s.exploit_status} for s in f.chain],
        })

    risks = [{"risk_id": r.risk_id, "asset": r.asset_id, "threat": r.threat,
              "inherent": r.inherent_score, "inherent_level": r.inherent_level,
              "residual": r.residual_score, "residual_level": r.residual_level}
             for r in grc.register.risks.values()]

    mttds = [i["mttd"] for i in incidents if i["mttd"] > 0]
    web_f = next((f for f in findings if f["chain"]), findings[0] if findings else None)
    web_i = next((i for i in incidents if i["asset"] == "asset-0007"), None)
    r001 = grc.register.risks["R-001"]

    return {
        "run_id": run_id,
        "generated_at": _dt.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "kpis": {
            "verified_findings": red.verified_count,
            "rejected": len(red.rejected),
            "incidents": len(incidents),
            "risks_tracked": len(risks),
            "conflicts": len(conflicts),
            "mappings": len(mappings),
            "mean_mttd": round(sum(mttds) / len(mttds), 1) if mttds else 0,
            "detector_f1": cm["f1"],
        },
        "assets": [{"asset_id": a.asset_id, "tier": a.criticality_tier,
                    "standards": a.applicable_standards, "mtd": a.mtd_minutes, "rpo": a.rpo_minutes}
                   for a in grc.assets],
        "red_findings": findings,
        "blue_incidents": incidents,
        "risks": risks,
        "conflicts": [{"a": c.req_a, "b": c.req_b, "fa": c.framework_a, "fb": c.framework_b,
                       "domain": c.domain, "oa": c.obligation_a, "ob": c.obligation_b}
                      for c in conflicts],
        "detection": cm,
        "traceability": {
            "asset": "asset-0007",
            "finding": web_f["finding_id"] if web_f else "-",
            "chain_len": len(web_f["chain"]) if web_f else 0,
            "incident": web_i["incident_id"] if web_i else "-",
            "action": web_i["action"] if web_i else "-",
            "inherent": r001.inherent_score, "residual": r001.residual_score,
        },
    }


def main() -> int:
    data = collect()
    template = (_HERE / "template.html").read_text(encoding="utf-8")
    html = template.replace("/*__DATA__*/", "const DATA = " + json.dumps(data) + ";")
    out = _HERE / "dashboard.html"
    out.write_text(html, encoding="utf-8")
    print(f"wrote {out}")
    print(f"  run_id={data['run_id']}  findings={data['kpis']['verified_findings']} "
          f"incidents={data['kpis']['incidents']}  F1={data['kpis']['detector_f1']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
