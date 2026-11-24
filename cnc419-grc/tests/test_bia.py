"""BIA maths: RTO + WRT <= MTD, with RPO as an independent constraint.

    python cnc419-grc/tests/test_bia.py
"""
from __future__ import annotations

import pathlib
import sys

_PKG_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PKG_ROOT))

from grc.bia import BIA, recommend_resumption, audit_sla  # noqa: E402


def _run():
    failures = 0

    # valid: 120 + 60 <= 240
    ok = BIA("a1", 120, 60, 240, 30).validate()
    failures += 0 if (ok["timeline_valid"] and ok["verdict"] == "PASS") else 1

    # invalid: 90 + 45 > 120
    bad = BIA("a2", 90, 45, 120, 30).validate()
    failures += 0 if (not bad["timeline_valid"] and bad["verdict"] == "FAIL") else 1

    # RPO is independent: a huge RPO does not change the timeline verdict
    big_rpo = BIA("a3", 100, 50, 240, 9999).validate()
    failures += 0 if (big_rpo["timeline_valid"] and big_rpo["rpo_valid"]) else 1

    # boundary: exactly equal passes (<=)
    eq = BIA("a4", 100, 100, 200, 10).validate()
    failures += 0 if eq["timeline_valid"] else 1

    # resumption tiers vary with RTO
    fast = recommend_resumption(60, 10)     # 10min RTO -> mirrored/hot
    slow = recommend_resumption(2880, 1440)  # 24h RTO -> cold
    failures += 0 if (fast in {"mirrored", "hot"} and slow == "cold") else 1

    # SLA audit flags a vague, over-budget SLA
    audit = audit_sla({"vendor": "X", "recovery_time_minutes": 600, "availability": "best effort"}, 240)
    failures += 0 if (not audit["enforceable"] and len(audit["issues"]) >= 2) else 1

    print("test_bia:", "PASS" if not failures else f"FAIL ({failures})")
    return failures


if __name__ == "__main__":
    raise SystemExit(1 if _run() else 0)
