"""In-memory GRC state shared by the CLI demo and the bridge API.

Holds the asset register, a live risk register (seeded), the governance ledger,
and the stream of ingested Red findings / Blue incidents. Ingestion is where the
platform becomes *dynamic*: a verified Red finding raises inherent risk, and a
Blue containment lowers residual risk, both in real time.
"""
from __future__ import annotations

import json
import pathlib
from typing import Optional

from .ids_bridge import validate, ContractError
from .risk import Risk, RiskRegister
from .governance import GovernanceLedger
from .aar import after_action_review, breach_notification


def seed_risks() -> list[Risk]:
    return [
        Risk("R-001", "asset-0007", "SQL injection -> data exfiltration", "information_disclosure", 3, 5),
        Risk("R-002", "asset-0007", "Reflected XSS -> session theft", "tampering", 3, 3),
        Risk("R-003", "asset-ad-dc01", "Credential attack -> domain compromise", "elevation_of_privilege", 3, 5),
        Risk("R-004", "asset-ad-dc01", "Kerberoasting -> service-account crack", "information_disclosure", 3, 4),
        Risk("R-005", "asset-lin-web01", "Linux privilege escalation", "elevation_of_privilege", 2, 4),
        Risk("R-006", "asset-lin-web01", "DNS tunnelling -> covert exfil", "information_disclosure", 2, 4),
        Risk("R-007", "asset-fw-edge", "Perimeter misconfiguration", "tampering", 2, 3),
    ]


class GrcState:
    def __init__(self, assets_path: str | pathlib.Path):
        raw = json.loads(pathlib.Path(assets_path).read_text(encoding="utf-8"))
        self.assets = [validate("asset", a) for a in raw]
        self.register = RiskRegister(seed_risks())
        self.ledger = GovernanceLedger()
        self.findings: list[dict] = []
        self.incidents: list[dict] = []
        self.aars: list[dict] = []

    def asset_profiles(self) -> list[dict]:
        return [a.to_dict() for a in self.assets]

    def asset_by_id(self, asset_id: str):
        return next((a for a in self.assets if a.asset_id == asset_id), None)

    def ingest_finding(self, payload: dict) -> dict:
        validate("finding", payload)                      # raises ContractError if bad
        self.findings.append(payload)
        updated = self.register.apply_red_finding(payload)
        return {"status": "ingested", "finding_id": payload.get("finding_id"),
                "updated_risks": updated}

    def ingest_incident(self, payload: dict) -> dict:
        validate("incident", payload)
        self.incidents.append(payload)
        updated = self.register.apply_blue_incident(payload)
        finding = next((f for f in self.findings
                        if f.get("finding_id") == payload.get("linked_finding_id")), None)
        aar = after_action_review(payload, finding)
        self.aars.append(aar)
        asset = self.asset_by_id(payload.get("target_asset", ""))
        stds = asset.applicable_standards if asset else []
        notif = breach_notification(payload, stds)
        return {"status": "ingested", "incident_id": payload.get("incident_id"),
                "updated_risks": updated, "aar": aar, "breach_notification": notif}

    def risk_snapshot(self) -> list[dict]:
        return [r.to_dict() for r in self.register.risks.values()]
