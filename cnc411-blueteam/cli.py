"""CNC 411 Blue Team pipeline — command-line entrypoint.

Offline demo (no installs, no network):

    python cnc411-blueteam/cli.py

Trains the detector, replays the bundled multi-stage attack scenarios, and for
each alert runs detect -> triage -> correlate(Red) -> contain -> Incident, then
writes incident records (MTTD/MTTC/MTTR + explanation) to ./out/.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

_PKG_ROOT = pathlib.Path(__file__).resolve().parent
_REPO_ROOT = _PKG_ROOT.parent
sys.path.insert(0, str(_PKG_ROOT))
sys.path.insert(0, str(_PKG_ROOT / "data"))
sys.path.insert(0, str(_REPO_ROOT))

from blueteam.detect import Detector                 # noqa: E402
from blueteam.soar import SoarEngine                 # noqa: E402
from blueteam.correlate import RedFindingIndex       # noqa: E402
from blueteam.pipeline import BlueTeamPipeline        # noqa: E402
from blueteam.grc_client import load_asset_index     # noqa: E402
import gen_dataset                                    # noqa: E402

from shared.contracts import AssetProfile            # noqa: E402

# Default synthetic asset index (used if no GRC feed is supplied).
_DEFAULT_ASSETS = {
    "asset-ad-dc01": AssetProfile("asset-ad-dc01", "10.10.5.10", "tier1_critical", 120, 30, ["ISO_27001"]),
    "asset-lin-web01": AssetProfile("asset-lin-web01", "10.10.9.20", "tier2_high", 240, 60, ["PCI_DSS"]),
    "asset-fw-edge": AssetProfile("asset-fw-edge", "10.10.0.1", "tier3_moderate", 480, 120, ["ISO_27001"]),
}


def _publish(incidents, grc_url, tx_post):  # pragma: no cover - needs a live GRC
    pass


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="CNC 411 vendor-agnostic Blue Team pipeline.")
    ap.add_argument("--scenarios", default=str(_PKG_ROOT / "data" / "scenarios.json"))
    ap.add_argument("--red-findings", default=str(_PKG_ROOT / "data" / "mock_red_findings.json"))
    ap.add_argument("--grc-assets", default=None, help="GRC asset-profile JSON (else a default index is used).")
    ap.add_argument("--approver", default=None, help="If set (e.g. ciso@lab), approve held high-impact actions.")
    ap.add_argument("--out", default=str(_PKG_ROOT / "out"))
    args = ap.parse_args(argv)

    # train detector
    det = Detector(threshold=0.5).train(gen_dataset.generate())

    # red findings for correlation
    red_index = None
    rf = pathlib.Path(args.red_findings)
    if rf.exists():
        red_index = RedFindingIndex(json.loads(rf.read_text(encoding="utf-8")))

    # asset index (GRC feed or default)
    asset_index = load_asset_index(args.grc_assets) or _DEFAULT_ASSETS

    pipeline = BlueTeamPipeline(
        detector=det, soar=SoarEngine(), asset_index=asset_index,
        red_index=red_index, approver=args.approver,
    )

    data = json.loads(pathlib.Path(args.scenarios).read_text(encoding="utf-8"))
    run_id = data.get("exercise_run_id", "")
    all_incidents = []

    print(f"[cli] run_id={run_id}  scenarios={len(data['scenarios'])}  approver={args.approver or '(none, will hold)'}\n")
    for scenario in data["scenarios"]:
        print(f"### scenario: {scenario['name']}")
        for stage in scenario["stages"]:
            stage.setdefault("exercise_run_id", run_id)
            res = pipeline.process_stage(stage)
            if not res.detected:
                print(f"  - {stage['mitre_hint']:10} MISS ({res.narrative})")
                continue
            inc = res.incident
            held = "  [HELD for approval]" if res.held_for_approval else ""
            print(f"  - {inc.mitre_technique_id:10} -> {inc.containment_action:22} "
                  f"MTTD={inc.mttd_sec}s MTTC={inc.mttc_sec}s MTTR={inc.mttr_sec}s "
                  f"[{inc.residual_status}]{held}")
            print(f"      why: {res.narrative[:110]}")
            all_incidents.append(inc.to_dict())
        print()

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    inc_path = out / f"incidents_{run_id}.json"
    inc_path.write_text(json.dumps(all_incidents, indent=2), encoding="utf-8")

    print("=== SOAR audit log (simulated, vendor-neutral) ===")
    for line in pipeline.soar.audit_log:
        print("  " + line)
    print(f"\nwrote {len(all_incidents)} incidents -> {inc_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
