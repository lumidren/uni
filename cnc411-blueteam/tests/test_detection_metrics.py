"""Train the detector and report the mandatory confusion-matrix metrics, then
probe the concept-drift blind spot. Runs offline, deterministic.

    python cnc411-blueteam/tests/test_detection_metrics.py
"""
from __future__ import annotations

import json
import pathlib
import sys

_PKG_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PKG_ROOT))
sys.path.insert(0, str(_PKG_ROOT / "data"))

from blueteam.detect import Detector      # noqa: E402
import gen_dataset                          # noqa: E402


def main() -> int:
    train_rows, test_rows = gen_dataset.split(gen_dataset.generate())
    det = Detector(threshold=0.5).train(train_rows)
    cm = det.evaluate(test_rows)
    rep = cm.report()

    print("=== DETECTION PERFORMANCE (held-out test set) ===")
    print(json.dumps(rep, indent=2))

    failures = 0
    # Reasonable bar for a separable synthetic set; keeps the test meaningful.
    if rep["accuracy"] < 0.85:
        failures += 1
        print(f"FAIL accuracy {rep['accuracy']} < 0.85")
    if rep["recall"] < 0.80:
        failures += 1
        print(f"FAIL recall {rep['recall']} < 0.80")

    # Show an evidence-backed explanation (XAI), not just a score.
    spray = {"auth_failures_5m": 30, "distinct_targets_5m": 20, "off_hours": 1,
             "kerberos_ticket_rate": 0.5, "dns_query_entropy": 2.0, "dns_bytes_out_kb": 1.0,
             "sudo_cmd_anomaly": 0.0, "lateral_conn_count": 1.0, "new_account_flag": 0}
    d = det.predict(spray)
    print("\n=== XAI sample (password-spray-like event) ===")
    print(f"is_attack={d.is_attack} score={d.score}")
    for e in d.top_evidence:
        print(f"  {e['feature']:22} value={e['value']:>7} contribution={e['contribution']:>8}  ({e['description']})")

    # Concept-drift stretch: a low-and-slow spray the model never trained on.
    drift = gen_dataset.drift_variant()
    caught = sum(1 for r in drift if det.predict(r).is_attack)
    print(f"\n=== Concept drift (low-and-slow spray, {len(drift)} samples, unseen) ===")
    print(f"caught {caught}/{len(drift)} -> blind spot = {len(drift) - caught} missed")
    print("Interpretation: low failure counts pull the score down; this is the "
          "model's blind spot and why a low-confidence band must fail safe rather "
          "than auto-contain.")

    print(f"\n{'PASS' if not failures else 'FAIL'} overall")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
