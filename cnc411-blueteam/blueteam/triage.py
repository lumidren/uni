"""Analyst augmentation: map an alert to MITRE ATT&CK and produce a unified,
*explained* incident summary — the XAI requirement.

Deterministic by design (a small curated ATT&CK knowledge base + the detector's
own feature contributions), so it runs with no LLM and every explanation is
reproducible. An LLM/RAG backend can be slotted in behind ``narrate()`` to phrase
the summary more fluently, but it never replaces the evidence: the structured
``explanation`` block is always built from real signals, and a bare confidence
score is never presented on its own.
"""
from __future__ import annotations

from typing import Optional

from .detect import Detection
from .correlate import Correlation

# Curated ATT&CK knowledge base for the scenarios in scope.
MITRE_KB = {
    "T1110.003": {"name": "Password Spraying", "tactic": "Credential Access",
                  "remediation": "Lock/alert on spray source, enforce MFA, review exposed accounts."},
    "T1558.003": {"name": "Kerberoasting", "tactic": "Credential Access",
                  "remediation": "Rotate service-account passwords, use gMSA, restrict SPNs."},
    "T1071.004": {"name": "DNS Tunnelling (C2 over DNS)", "tactic": "Command and Control",
                  "remediation": "Block egress DNS to resolver only, inspect high-entropy queries."},
    "T1548.003": {"name": "Sudo/Setuid Abuse", "tactic": "Privilege Escalation",
                  "remediation": "Audit sudoers, isolate host, review privileged commands."},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Persistence",
              "remediation": "Review cron/at and scheduled tasks on the host."},
    "T1557.002": {"name": "ARP Cache Poisoning", "tactic": "Collection/MITM",
                  "remediation": "Enable DAI/port security, quarantine the switch port."},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion",
              "remediation": "Disable/reset the account, review session tokens."},
}


def confidence_band(score: float) -> str:
    if score >= 0.80:
        return "high"
    if score >= 0.55:
        return "medium"
    return "low"


def triage(
    detection: Detection,
    mitre_hint: Optional[str],
    correlation: Correlation,
    asset_tier: str,
    asset_weight: float,
) -> dict:
    technique = mitre_hint or "T1078"
    kb = MITRE_KB.get(technique, {"name": "Unmapped", "tactic": "Unknown", "remediation": "Manual review."})

    # Confidence blends model score, asset criticality and Red corroboration,
    # but the EXPLANATION is always evidence-first.
    confidence = detection.score
    if correlation.matched and correlation.red_verified:
        confidence = min(1.0, confidence + 0.1)
    confidence = round(min(1.0, confidence * (0.85 + 0.15 * asset_weight)), 4)

    evidence = [
        f"{e['feature']}={e['value']} ({e['description']})"
        for e in detection.top_evidence if e["contribution"] > 0
    ][:3]
    if correlation.matched:
        evidence.append(f"correlated to Red finding {correlation.linked_finding_id} — {correlation.note}")

    rationale = (
        f"{kb['name']} ({kb['tactic']}) on a {asset_tier} asset. "
        f"Model score {detection.score}; "
        + ("corroborated by a verified Red PoC. " if correlation.red_verified else "")
        + f"Suggested remediation: {kb['remediation']}"
    )

    return {
        "technique": technique,
        "technique_name": kb["name"],
        "tactic": kb["tactic"],
        "confidence": confidence,
        "confidence_band": confidence_band(confidence),
        "explanation": {
            "top_features": [e["feature"] for e in detection.top_evidence],
            "evidence": evidence,
            "rationale": rationale,
            "confidence": confidence,
        },
    }


def narrate(summary: dict, llm=None) -> str:
    """Optional LLM phrasing hook. With no LLM, returns a deterministic sentence
    built from the structured summary (fluency never invents evidence)."""
    if llm is not None:  # pragma: no cover - external backend
        return llm.summarise(summary)
    return (f"[{summary['confidence_band'].upper()}] {summary['technique_name']} "
            f"({summary['technique']}) — {summary['explanation']['rationale']}")
