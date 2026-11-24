"""CNC 419 GRC platform — demo entrypoint (offline, no installs).

    python cnc419-grc/cli.py            # run the full governance walkthrough
    python cnc419-grc/cli.py --serve    # start the bridge API on 127.0.0.1:4190

The walkthrough exercises every pillar: cross-framework mapping + conflicts,
unseen-document ingestion, pluggable ISRM risk + SPOFs, dynamic risk updates from
Red/Blue, budget optimisation, BIA validation, human sign-off, and AAR.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

_PKG_ROOT = pathlib.Path(__file__).resolve().parent
_REPO_ROOT = _PKG_ROOT.parent
sys.path.insert(0, str(_PKG_ROOT))
sys.path.insert(0, str(_REPO_ROOT))

from grc.frameworks import REQUIREMENTS, CONTROLS           # noqa: E402
from grc.mapping import MappingEngine                        # noqa: E402
from grc.ingest import ingest_document                       # noqa: E402
from grc.risk import find_spofs                              # noqa: E402
from grc.optimizer import Safeguard, optimize                # noqa: E402
from grc.bia import BIA, recommend_resumption, audit_sla     # noqa: E402
from grc.state import GrcState                               # noqa: E402

_DATA = _PKG_ROOT / "data"


def _hdr(title: str) -> None:
    print("\n" + "=" * 70 + f"\n {title}\n" + "=" * 70)


def walkthrough() -> dict:
    state = GrcState(_DATA / "assets.json")
    engine = MappingEngine(REQUIREMENTS, CONTROLS)
    out = {}

    # 1 ---- cross-framework mapping ----
    _hdr("1. Cross-framework mapping & compliance intelligence")
    mappings = engine.map_all()
    conflicts = engine.detect_conflicts()
    gaps = engine.coverage_gaps()
    print(f"requirements={len(REQUIREMENTS)}  mappings={len(mappings)}  "
          f"conflicts={len(conflicts)}  coverage_gaps={len(gaps)}")
    equivalents = [m for m in mappings if m.relationship == "equivalent"][:3]
    for m in equivalents:
        print(f"  EQUIVALENT {m.source_req} <-> {m.target_req}  tags={m.shared_tags}  terms={m.evidence_terms[:3]}")
    for c in conflicts:
        print(f"  CONFLICT   {c.req_a} ({c.obligation_a}) vs {c.req_b} ({c.obligation_b}) in '{c.domain}'")
    for g in gaps:
        print(f"  GAP        {g.req_id}: {g.gap_reason}")
    out["mappings"] = len(mappings)
    out["conflicts"] = [c.explanation for c in conflicts]

    # 2 ---- ingest an unseen regulation ----
    _hdr("2. Standard-neutral ingestion of an UNSEEN document (LDPD)")
    text = (_DATA / "sample_regulation.md").read_text(encoding="utf-8")
    res = ingest_document(text, "LDPD")
    print("summary:", json.dumps(res.summary()))
    for c in res.conflicts:
        print(f"  NEW CONFLICT {c.req_a} ({c.obligation_a}) vs {c.req_b} ({c.obligation_b}) in '{c.domain}'")
    for cov in res.coverage:
        if not cov.covered:
            print(f"  NEW GAP {cov.req_id}: {cov.gap_reason}")
    out["ingest"] = res.summary()

    # 3 ---- pluggable ISRM risk + SPOF ----
    _hdr("3. Pluggable ISRM risk register + SPOF detection")
    for r in list(state.register.risks.values())[:4]:
        print(f"  {r.risk_id} {r.asset_id:16} inherent={r.inherent_score}({r.inherent_level}) "
              f"residual={r.residual_score}({r.residual_level}) [{r.methodology}]")
    deps = {
        "asset-0007": ["asset-ad-dc01"],
        "asset-lin-web01": ["asset-ad-dc01"],
        "asset-ad-dc01": ["asset-fw-edge"],
        "payments-svc": ["asset-0007", "asset-lin-web01"],
    }
    spofs = find_spofs(deps)
    print(f"  SPOFs: {spofs}")
    out["spofs"] = spofs

    # 4 ---- dynamic updates from Red + Blue ----
    _hdr("4. Dynamic inherent/residual updates from Red findings + Blue incidents")
    r001 = state.register.risks["R-001"]
    print(f"  before: R-001 inherent={r001.inherent_score} residual={r001.residual_score}")
    finding = {
        "finding_id": "find-a1b2c3", "exercise_run_id": "run-20261124-9f8e7d",
        "target_asset": "asset-0007", "cwe_id": "CWE-89", "stride_category": "tampering",
        "mitre_technique_id": "T1190", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "exploit_status": "verified",
        "verified_poc": {"method": "boolean_blind_inference", "evidence": "row-count delta"},
    }
    print("  ingest Red finding ->", state.ingest_finding(finding)["updated_risks"])
    print(f"  after Red: R-001 inherent={r001.inherent_score} (likelihood raised)")
    incident = {
        "incident_id": "inc-7h6g5f", "exercise_run_id": "run-20261124-9f8e7d",
        "target_asset": "asset-0007", "mitre_technique_id": "T1190",
        "mttd_sec": 14.2, "mttc_sec": 31.8, "mttr_sec": 95.0,
        "containment_action": "block_ip", "residual_status": "contained",
        "linked_finding_id": "find-a1b2c3",
        "explanation": {"rationale": "SQLi burst correlated to verified Red PoC", "confidence": 0.93},
    }
    ack = state.ingest_incident(incident)
    print("  ingest Blue incident ->", ack["updated_risks"])
    print(f"  after Blue: R-001 residual={r001.residual_score} (containment lowered residual)")
    print(f"  AAR lessons: {ack['aar']['lessons_learned']}")
    print(f"  breach deadlines: {list(ack['breach_notification']['notification_deadlines'].keys())}")
    out["aar"] = ack["aar"]

    # 5 ---- budget-constrained optimiser ----
    _hdr("5. Budget-constrained safeguard optimiser (0/1 knapsack)")
    safeguards = [
        Safeguard("SG-1", "MFA everywhere", 5000, 8, ("R-003",)),
        Safeguard("SG-2", "Web application firewall", 3000, 6, ("R-001", "R-002")),
        Safeguard("SG-3", "DNS egress filtering", 2000, 4, ("R-006",)),
        Safeguard("SG-4", "Privileged access management", 6000, 7, ("R-005",)),
        Safeguard("SG-5", "gMSA service accounts", 1500, 3, ("R-004",)),
    ]
    result = optimize(safeguards, budget=8000)
    print("  " + json.dumps(result.report()))
    out["optimizer"] = result.report()

    # 6 ---- BIA validation ----
    _hdr("6. BIA validation (RTO + WRT <= MTD; RPO independent)")
    # Proposed recovery design (RTO, WRT) per asset — note the DC is over-budget.
    recovery_design = {
        "asset-0007": (120, 60),
        "asset-ad-dc01": (90, 45),      # 135 > MTD 120 -> must FAIL
        "asset-lin-web01": (90, 30),
        "asset-fw-edge": (180, 120),
    }
    for asset in state.assets:
        rto, wrt = recovery_design.get(asset.asset_id, (asset.mtd_minutes * 0.5, asset.mtd_minutes * 0.25))
        bia = BIA(asset.asset_id, rto, wrt, asset.mtd_minutes, asset.rpo_minutes)
        v = bia.validate()
        strat = recommend_resumption(asset.mtd_minutes, rto)
        flag = "" if v["verdict"] == "PASS" else "   <-- recovery design exceeds MTD"
        print(f"  {asset.asset_id:16} RTO+WRT={v['rto_plus_wrt']} MTD={v['mtd_minutes']} "
              f"-> {v['verdict']}  resumption={strat}{flag}")
    sla = {"vendor": "CloudCo", "recovery_time_minutes": 600, "availability": "best effort"}
    print("  SLA audit:", json.dumps(audit_sla(sla, rto_minutes=240)))

    # 7 ---- human-in-the-loop sign-off ----
    _hdr("7. Human-in-the-loop governance (AI recommends, human authorises)")
    so = state.ledger.recommend("risk_acceptance", "Accept residual on R-007 (perimeter) this quarter", "R-007")
    print(f"  AI recommendation {so.decision_id} status={so.status} (cannot self-approve)")
    try:
        state.ledger.authorize(so.decision_id, approver="analyst@lab", approver_role="Analyst")
    except PermissionError as exc:
        print(f"  blocked: {exc}")
    approved = state.ledger.authorize(so.decision_id, approver="ciso@lab", approver_role="CISO")
    print(f"  after CISO sign-off: status={approved.status} approver={approved.approver}")

    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="CNC 419 GRC platform.")
    ap.add_argument("--serve", action="store_true", help="Start the bridge API instead of the walkthrough.")
    ap.add_argument("--port", type=int, default=4190)
    ap.add_argument("--out", default=str(_PKG_ROOT / "out"))
    args = ap.parse_args(argv)

    if args.serve:
        from grc.api import serve
        serve(args.port)
        return 0

    out = walkthrough()
    outdir = pathlib.Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "grc_walkthrough.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"\nwrote summary -> {outdir / 'grc_walkthrough.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
