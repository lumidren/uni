"""Correlate Blue Team detections with Red Team activity via the shared
``exercise_run_id`` (the same value Red stamps on traffic as X-Exercise-Run-ID).

When a detection lines up with a *verified* Red finding, we (a) raise confidence,
(b) link the ``finding_id`` into the incident, and (c) treat the Red PoC as
ground-truth validation of the detection. An un-verified or absent Red finding
does not get that boost — we never let a hallucinated finding validate anything.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class Correlation:
    matched: bool
    linked_finding_id: Optional[str] = None
    red_verified: bool = False
    note: str = ""


class RedFindingIndex:
    """Index of Red Team findings for fast correlation by run id + technique."""

    def __init__(self, findings: list[dict]):
        self._by_run: dict[str, list[dict]] = {}
        for f in findings:
            self._by_run.setdefault(f.get("exercise_run_id", ""), []).append(f)

    @staticmethod
    def _techniques(finding: dict) -> set[str]:
        techs = {finding.get("mitre_technique_id", "")}
        for step in finding.get("chain", []) or []:
            techs.add(step.get("mitre_technique_id", ""))
        return {t for t in techs if t}

    def correlate(self, exercise_run_id: str, technique: str) -> Correlation:
        candidates = self._by_run.get(exercise_run_id, [])
        if not candidates:
            return Correlation(matched=False, note="no Red activity for this run id")

        # Prefer a technique match; fall back to same-run correlation.
        for f in candidates:
            if technique in self._techniques(f):
                verified = f.get("exploit_status") == "verified"
                return Correlation(
                    matched=True,
                    linked_finding_id=f.get("finding_id"),
                    red_verified=verified,
                    note=("validated against verified Red PoC" if verified
                          else "correlated but Red finding not verified"),
                )
        f = candidates[0]
        return Correlation(
            matched=True,
            linked_finding_id=f.get("finding_id"),
            red_verified=f.get("exploit_status") == "verified",
            note="same-run correlation (technique differs)",
        )
