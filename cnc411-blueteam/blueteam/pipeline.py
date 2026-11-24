"""The Blue Team pipeline: telemetry -> detect -> triage -> correlate -> contain
-> Incident. One `process_stage` call is the full journey for one alert, and it
emits a contract-valid Incident (with MTTD/MTTC/MTTR + explanation) for GRC.

Guardrails baked in:
  * low-confidence detections FAIL SAFE (no auto-containment).
  * high-impact actions on critical assets are HELD for human approval.
  * containment is always simulated via vendor connectors (never a real device).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .detect import Detector
from .soar import SoarEngine
from .correlate import RedFindingIndex, Correlation
from .triage import triage, narrate, confidence_band
from .metrics import IncidentTimeline
from .grc_client import severity_weight
from .ids_bridge import Incident, new_incident_id, validate


@dataclass
class StageResult:
    incident: Any                 # shared.contracts.Incident (or None if not detected)
    detected: bool
    narrative: str = ""
    held_for_approval: bool = False


@dataclass
class BlueTeamPipeline:
    detector: Detector
    soar: SoarEngine = field(default_factory=SoarEngine)
    asset_index: dict = field(default_factory=dict)
    red_index: Optional[RedFindingIndex] = None
    approver: Optional[str] = None       # e.g. "ciso@lab"; None => hold instead of approve

    def process_stage(self, stage: dict) -> StageResult:
        features = stage["features"]
        technique = stage.get("mitre_hint") or "T1078"
        run_id = stage.get("exercise_run_id", "")
        asset_id = stage.get("target_asset", "asset-unknown")
        asset_os = stage.get("asset_os", "windows")

        asset = self.asset_index.get(asset_id)
        tier = asset.criticality_tier if asset else "tier3_moderate"
        weight = severity_weight(tier)

        # 1. detect
        detection = self.detector.predict(features)
        if not detection.is_attack:
            return StageResult(incident=None, detected=False,
                               narrative=f"not flagged (score={detection.score}) — possible false negative")

        # 2. correlate with Red
        correlation = (self.red_index.correlate(run_id, technique)
                       if self.red_index else Correlation(matched=False))

        # 3. triage + explain
        summary = triage(detection, technique, correlation, tier, weight)
        band = summary["confidence_band"]

        # 4. decide containment
        target = stage.get("containment_target", stage.get("src_ip", asset_id))
        decision = self.soar.decide(
            technique, target, asset_tier=tier, asset_os=asset_os,
            explanation=summary["explanation"], fw_vendor=stage.get("fw_vendor"),
        )

        # 5. autonomy policy: the machine may contain on its OWN only when it is
        # highly confident OR the alert is corroborated by a verified Red PoC.
        # Anything else (incl. the concept-drift blind spot) fails safe -> HOLD,
        # rather than silently misclassifying or disruptively auto-containing.
        corroborated = correlation.matched and correlation.red_verified
        autonomous_ok = (band == "high") or corroborated
        if not autonomous_ok:
            decision.requires_approval = True

        held = False
        if decision.requires_approval:
            if self.approver:
                self.soar.execute(decision, approver=self.approver)
            else:
                self.soar.execute(decision)  # held
                held = True
                if not autonomous_ok:
                    self.soar.audit_log.append(
                        f"FAIL-SAFE hold ({band} confidence, uncorroborated): {decision.action} on {target}")
        else:
            self.soar.execute(decision)

        # 6. timeline / KPIs (measured during the exercise)
        tl = IncidentTimeline(
            first_malicious_ts=0.0,
            detect_ts=float(stage.get("detect_latency_s", 15.0)),
            contain_ts=(float(stage["detect_latency_s"]) + float(stage.get("contain_latency_s", 20.0)))
            if decision.executed else None,
            recover_ts=(float(stage["detect_latency_s"]) + float(stage.get("recover_latency_s", 90.0)))
            if decision.executed else None,
        )
        kpis = tl.kpis()

        incident = Incident(
            incident_id=new_incident_id(),
            exercise_run_id=run_id,
            target_asset=asset_id,
            mitre_technique_id=technique,
            mttd_sec=kpis["mttd_sec"],
            mttc_sec=kpis["mttc_sec"],
            mttr_sec=kpis["mttr_sec"],
            containment_action=decision.effective_action(),
            residual_status=decision.residual_status,
            linked_finding_id=correlation.linked_finding_id,
            explanation=summary["explanation"],
        )
        # fail loud if we ever build a malformed incident
        validate("incident", incident.to_dict())

        return StageResult(
            incident=incident,
            detected=True,
            narrative=narrate(summary),
            held_for_approval=held,
        )

    def run(self, stages: list[dict]) -> list[StageResult]:
        return [self.process_stage(s) for s in stages]
