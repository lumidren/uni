"""Business Impact Analysis validation with the CORRECTED relationship.

    RTO + WRT <= MTD

where RTO = Recovery Time Objective, WRT = Work Recovery Time and MTD = Maximum
Tolerable Downtime. RPO (Recovery Point Objective) is an INDEPENDENT constraint
bounding tolerable *data loss* measured backward from the failure — it is NOT
part of the RTO/WRT/MTD timeline. Both constraints are validated explicitly;
neither is left as a placeholder.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

# Off-site resumption strategies ordered by recovery speed (and cost).
_RESUMPTION = [
    ("mirrored", 0.0, 0.25),    # near-zero RTO, highest cost
    ("hot", 0.25, 2.0),
    ("warm", 2.0, 24.0),
    ("cold", 24.0, 1e9),        # cheapest, slowest
]


@dataclass
class BIA:
    asset_id: str
    rto_minutes: float
    wrt_minutes: float
    mtd_minutes: float
    rpo_minutes: float

    @property
    def recovery_total(self) -> float:
        return self.rto_minutes + self.wrt_minutes

    @property
    def timeline_valid(self) -> bool:
        return self.recovery_total <= self.mtd_minutes

    @property
    def rpo_valid(self) -> bool:
        # RPO must be a real, non-negative bound. It is independent of the
        # RTO/WRT/MTD timeline, so it is validated on its own.
        return self.rpo_minutes >= 0

    def validate(self) -> dict:
        slack = self.mtd_minutes - self.recovery_total
        return {
            "asset_id": self.asset_id,
            "rto_minutes": self.rto_minutes,
            "wrt_minutes": self.wrt_minutes,
            "mtd_minutes": self.mtd_minutes,
            "rpo_minutes": self.rpo_minutes,
            "rto_plus_wrt": self.recovery_total,
            "timeline_constraint": "RTO + WRT <= MTD",
            "timeline_valid": self.timeline_valid,
            "timeline_slack_minutes": round(slack, 2),
            "rpo_constraint": "independent data-loss bound",
            "rpo_valid": self.rpo_valid,
            "verdict": "PASS" if (self.timeline_valid and self.rpo_valid) else "FAIL",
        }


def recommend_resumption(mtd_minutes: float, rto_minutes: float) -> str:
    """Pick the cheapest off-site strategy whose achievable recovery still fits
    inside the RTO. Tiers are ordered fast->slow; we choose the slowest (cheapest)
    tier whose recovery band contains the RTO."""
    rto_hours = rto_minutes / 60.0
    for name, lo_h, hi_h in _RESUMPTION:
        if lo_h <= rto_hours < hi_h:
            return name
    return "cold"


def audit_sla(sla: dict, rto_minutes: float) -> dict:
    """Flag a third-party SLA that is vague or cannot meet the RTO."""
    issues = []
    recovery = sla.get("recovery_time_minutes")
    if recovery is None:
        issues.append("no quantified recovery time (vague/unenforceable)")
    elif recovery > rto_minutes:
        issues.append(f"SLA recovery {recovery}m exceeds required RTO {rto_minutes}m")
    if not sla.get("penalty_clause"):
        issues.append("no penalty clause for missed recovery")
    if str(sla.get("availability", "")).lower() in {"", "best effort", "reasonable"}:
        issues.append("availability term is vague ('best effort')")
    return {"vendor": sla.get("vendor", "unknown"), "issues": issues,
            "enforceable": not issues}
