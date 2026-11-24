"""Pluggable ISRM risk engine + dynamic inherent/residual updates.

An analyst selects a scoring methodology (ISO 27005 / NIST SP 800-30 likelihood x
impact, or an OCTAVE-Allegro-style impact-weighted model). Risks carry inherent
and residual scores; residual falls as safeguards are applied. The register is
*live*: verified Red findings raise likelihood (and flag compliance drift), and
Blue containment/remediation lowers residual risk.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

STRIDE = ("spoofing", "tampering", "repudiation", "information_disclosure",
          "denial_of_service", "elevation_of_privilege")


def _level(score: float) -> str:
    if score >= 17:
        return "critical"
    if score >= 10:
        return "high"
    if score >= 5:
        return "medium"
    return "low"


# -- scoring methodologies (pluggable) -------------------------------------- #
def iso27005(likelihood: float, impact: float) -> float:
    return likelihood * impact                      # classic 1-5 x 1-5 matrix


def nist_800_30(likelihood: float, impact: float) -> float:
    return likelihood * impact                      # same matrix, NIST labelling


def octave_allegro(likelihood: float, impact: float) -> float:
    # Impact-weighted: OCTAVE emphasises consequence over raw probability.
    return (0.4 * likelihood + 0.6 * impact) * 5.0 / 3.0


METHODOLOGIES: dict[str, Callable[[float, float], float]] = {
    "iso27005": iso27005,
    "nist_800_30": nist_800_30,
    "octave_allegro": octave_allegro,
}


@dataclass
class Risk:
    risk_id: str
    asset_id: str
    threat: str
    stride: str
    likelihood: float               # 1..5
    impact: float                   # 1..5
    methodology: str = "iso27005"
    residual_reduction: float = 0.0  # 0..1 fraction removed by safeguards
    notes: list[str] = field(default_factory=list)

    def _score_fn(self):
        return METHODOLOGIES.get(self.methodology, iso27005)

    @property
    def inherent_score(self) -> float:
        return round(self._score_fn()(self.likelihood, self.impact), 2)

    @property
    def residual_score(self) -> float:
        return round(self.inherent_score * (1 - self.residual_reduction), 2)

    @property
    def inherent_level(self) -> str:
        return _level(self.inherent_score)

    @property
    def residual_level(self) -> str:
        return _level(self.residual_score)

    def to_dict(self) -> dict:
        return {
            "risk_id": self.risk_id, "asset_id": self.asset_id, "threat": self.threat,
            "stride": self.stride, "likelihood": self.likelihood, "impact": self.impact,
            "methodology": self.methodology,
            "inherent_score": self.inherent_score, "inherent_level": self.inherent_level,
            "residual_score": self.residual_score, "residual_level": self.residual_level,
            "notes": self.notes,
        }


class RiskRegister:
    def __init__(self, risks: Optional[list[Risk]] = None):
        self.risks: dict[str, Risk] = {r.risk_id: r for r in (risks or [])}

    def add(self, risk: Risk) -> None:
        self.risks[risk.risk_id] = risk

    def by_asset(self, asset_id: str) -> list[Risk]:
        return [r for r in self.risks.values() if r.asset_id == asset_id]

    # -- dynamic updates from the ecosystem -------------------------------- #
    def apply_red_finding(self, finding: dict) -> list[str]:
        """A verified Red finding raises likelihood on the target asset and
        flags compliance drift. Unverified findings are ignored."""
        touched = []
        if finding.get("exploit_status") != "verified":
            return touched
        asset = finding.get("target_asset")
        for r in self.by_asset(asset):
            r.likelihood = min(5.0, r.likelihood + 1.0)
            r.notes.append(f"likelihood raised by verified Red finding {finding.get('finding_id')} "
                           f"({finding.get('cwe_id')}); compliance drift flagged")
            touched.append(r.risk_id)
        return touched

    def apply_blue_incident(self, incident: dict) -> list[str]:
        """Blue containment lowers residual risk; an open incident does not."""
        touched = []
        asset = incident.get("target_asset")
        status = incident.get("residual_status")
        for r in self.by_asset(asset):
            if status in {"contained", "mitigated"}:
                r.residual_reduction = min(0.9, r.residual_reduction + 0.4)
                r.notes.append(f"residual lowered by Blue incident {incident.get('incident_id')} "
                               f"({incident.get('containment_action')}, {status})")
            else:
                r.notes.append(f"incident {incident.get('incident_id')} status={status}: residual unchanged")
            touched.append(r.risk_id)
        return touched


# -- SPOF detection from a dependency graph --------------------------------- #
def find_spofs(dependencies: dict[str, list[str]]) -> list[str]:
    """A service that others depend on with no alternative provider is a Single
    Point of Failure. ``dependencies[x] = [providers...]`` ; a provider that is
    the *sole* provider for >=2 dependents (or any critical dependent) is a SPOF."""
    provider_dependents: dict[str, list[str]] = {}
    for dependent, providers in dependencies.items():
        for p in providers:
            provider_dependents.setdefault(p, []).append(dependent)
    spofs = []
    for provider, dependents in provider_dependents.items():
        # sole provider = no dependent has an alternative for this provider's role
        sole = all(len(dependencies.get(d, [])) == 1 for d in dependents)
        if sole and len(dependents) >= 1:
            spofs.append(provider)
    return sorted(set(spofs))
