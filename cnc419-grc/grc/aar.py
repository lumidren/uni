"""Automated post-incident governance: After-Action Reviews + breach-notification
timelines.

An AAR is built from the Blue Team incident (MTTD/MTTC/MTTR + explanation) and,
when available, the correlated Red finding (root cause). Breach-notification
deadlines are computed against each in-scope regulation (GDPR 72h, Egypt PDPL
72h), so the crisis workflow surfaces the regulatory clock, not just the tech.
"""
from __future__ import annotations

import datetime as _dt
from typing import Optional

# Statutory breach-notification windows (hours).
NOTIFICATION_WINDOWS_H = {
    "GDPR": 72,
    "EGYPT_PDPL": 72,
}


def after_action_review(incident: dict, finding: Optional[dict] = None) -> dict:
    """Structured AAR that can feed back into policy updates."""
    technique = incident.get("mitre_technique_id", "unknown")
    root_cause = "unknown"
    if finding:
        root_cause = (f"{finding.get('cwe_id')} ({finding.get('stride_category')}) "
                      f"proven by Red finding {finding.get('finding_id')}")

    kpis = {k: incident.get(k) for k in ("mttd_sec", "mttc_sec", "mttr_sec")}
    lessons = []
    if (incident.get("mttd_sec") or 0) > 30:
        lessons.append("detection latency high — tune detection content / telemetry coverage")
    if incident.get("containment_action") == "pending_human_approval":
        lessons.append("containment required manual approval — review approval SLAs for critical assets")
    if incident.get("residual_status") not in {"contained", "mitigated"}:
        lessons.append("threat not fully contained — schedule follow-up remediation")
    if not lessons:
        lessons.append("response within expected bounds — fold timings into the baseline")

    return {
        "incident_id": incident.get("incident_id"),
        "exercise_run_id": incident.get("exercise_run_id"),
        "target_asset": incident.get("target_asset"),
        "technique": technique,
        "root_cause": root_cause,
        "kpis": kpis,
        "residual_status": incident.get("residual_status"),
        "lessons_learned": lessons,
        "policy_update_candidates": [
            f"Add detection content for {technique}",
            "Review human-in-the-loop approval thresholds",
        ],
    }


def breach_notification(incident: dict, applicable_standards: list[str],
                        detected_at: Optional[str] = None) -> dict:
    """Compute notification deadlines for each in-scope regulation."""
    base = _dt.datetime.now(_dt.timezone.utc)
    if detected_at:
        try:
            base = _dt.datetime.fromisoformat(detected_at.replace("Z", "+00:00"))
        except ValueError:
            pass
    deadlines = {}
    for std in applicable_standards:
        hrs = NOTIFICATION_WINDOWS_H.get(std)
        if hrs:
            deadlines[std] = {
                "window_hours": hrs,
                "notify_by": (base + _dt.timedelta(hours=hrs)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
    return {
        "incident_id": incident.get("incident_id"),
        "detected_at": detected_at or base.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "notification_deadlines": deadlines,
        "note": "Notify the supervisory authority/Centre within the smallest applicable window.",
    }
