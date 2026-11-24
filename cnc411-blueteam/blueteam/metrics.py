"""Incident KPIs: MTTD / MTTC / MTTR, computed from a timeline of timestamps.

These are the numbers the Blue Team publishes back to GRC. Keeping the maths in
one tiny, testable place means the KPI definitions can be defended precisely:

  * MTTD = detect_ts  - first_malicious_ts   (how long until we noticed)
  * MTTC = contain_ts - detect_ts            (how long until we stopped it)
  * MTTR = recover_ts - detect_ts            (how long until safe state restored)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class IncidentTimeline:
    first_malicious_ts: float
    detect_ts: float
    contain_ts: Optional[float] = None
    recover_ts: Optional[float] = None

    @property
    def mttd_sec(self) -> float:
        return max(0.0, self.detect_ts - self.first_malicious_ts)

    @property
    def mttc_sec(self) -> float:
        if self.contain_ts is None:
            return 0.0
        return max(0.0, self.contain_ts - self.detect_ts)

    @property
    def mttr_sec(self) -> float:
        if self.recover_ts is None:
            return 0.0
        return max(0.0, self.recover_ts - self.detect_ts)

    def kpis(self) -> dict[str, float]:
        return {
            "mttd_sec": round(self.mttd_sec, 2),
            "mttc_sec": round(self.mttc_sec, 2),
            "mttr_sec": round(self.mttr_sec, 2),
        }
