"""Typed, zero-dependency models for the three cross-course records.

These dataclasses mirror ``shared/schemas/*.schema.json`` one-to-one. They are
stdlib-only on purpose: the Red, Blue and GRC subsystems can all import them
without agreeing on a web framework or an ORM, and nobody has to install
anything to read a payload.

Each model offers:
  * ``to_dict()``  -> plain JSON-serialisable dict (the wire format).
  * ``from_dict()``-> parse + light validation (raises ``ValueError``).

Deep schema validation (enums, patterns, required keys) lives in
``validate.py`` so these stay small.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Optional

CRITICALITY_TIERS = ("tier1_critical", "tier2_high", "tier3_moderate", "tier4_low")
STRIDE = (
    "spoofing",
    "tampering",
    "repudiation",
    "information_disclosure",
    "denial_of_service",
    "elevation_of_privilege",
)
EXPLOIT_STATUS = ("verified", "rejected", "suspected")
CONTAINMENT_ACTIONS = (
    "block_ip",
    "isolate_host",
    "disable_account",
    "kill_session",
    "quarantine_file",
    "none",
    "pending_human_approval",
)
RESIDUAL_STATUS = ("contained", "mitigated", "partially_contained", "escalated", "open")


# --------------------------------------------------------------------------- #
# GRC  ->  Red & Blue
# --------------------------------------------------------------------------- #
@dataclass
class AssetProfile:
    asset_id: str
    ip_or_url: str
    criticality_tier: str
    mtd_minutes: int
    rpo_minutes: int
    applicable_standards: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AssetProfile":
        try:
            return cls(
                asset_id=str(d["asset_id"]),
                ip_or_url=str(d["ip_or_url"]),
                criticality_tier=str(d["criticality_tier"]),
                mtd_minutes=int(d["mtd_minutes"]),
                rpo_minutes=int(d["rpo_minutes"]),
                applicable_standards=list(d["applicable_standards"]),
            )
        except KeyError as exc:
            raise ValueError(f"AssetProfile missing field: {exc}") from exc


# --------------------------------------------------------------------------- #
# Red  ->  Blue & GRC
# --------------------------------------------------------------------------- #
@dataclass
class ChainStep:
    step: int
    name: str
    mitre_technique_id: str
    exploit_status: str
    cwe_id: Optional[str] = None
    verified_poc: Optional[dict[str, Any]] = None
    enables: Optional[str] = None


@dataclass
class Finding:
    finding_id: str
    exercise_run_id: str
    target_asset: str
    cwe_id: str
    stride_category: str
    mitre_technique_id: str
    cvss_vector: str
    exploit_status: str
    verified_poc: dict[str, Any]
    chain: list[ChainStep] = field(default_factory=list)

    @property
    def is_chain(self) -> bool:
        return len(self.chain) > 1

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if not self.chain:
            d.pop("chain", None)
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        try:
            steps = [ChainStep(**s) for s in d.get("chain", [])]
            return cls(
                finding_id=str(d["finding_id"]),
                exercise_run_id=str(d["exercise_run_id"]),
                target_asset=str(d["target_asset"]),
                cwe_id=str(d["cwe_id"]),
                stride_category=str(d["stride_category"]),
                mitre_technique_id=str(d["mitre_technique_id"]),
                cvss_vector=str(d["cvss_vector"]),
                exploit_status=str(d["exploit_status"]),
                verified_poc=dict(d["verified_poc"]),
                chain=steps,
            )
        except KeyError as exc:
            raise ValueError(f"Finding missing field: {exc}") from exc


# --------------------------------------------------------------------------- #
# Blue  ->  GRC
# --------------------------------------------------------------------------- #
@dataclass
class Incident:
    incident_id: str
    exercise_run_id: str
    target_asset: str
    mitre_technique_id: str
    mttd_sec: float
    mttc_sec: float
    mttr_sec: float
    containment_action: str
    residual_status: str
    linked_finding_id: Optional[str] = None
    explanation: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return {k: v for k, v in d.items() if v is not None}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Incident":
        try:
            return cls(
                incident_id=str(d["incident_id"]),
                exercise_run_id=str(d["exercise_run_id"]),
                target_asset=str(d["target_asset"]),
                mitre_technique_id=str(d["mitre_technique_id"]),
                mttd_sec=float(d["mttd_sec"]),
                mttc_sec=float(d["mttc_sec"]),
                mttr_sec=float(d["mttr_sec"]),
                containment_action=str(d["containment_action"]),
                residual_status=str(d["residual_status"]),
                linked_finding_id=d.get("linked_finding_id"),
                explanation=d.get("explanation"),
            )
        except KeyError as exc:
            raise ValueError(f"Incident missing field: {exc}") from exc
