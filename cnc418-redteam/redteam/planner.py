"""Attack planning — decide WHICH vectors to run and in WHAT order.

The handout's key question is: "how will your AI engine decide which attack
vectors to prioritise after reconnaissance and after ingesting asset criticality
profiles, rather than blindly testing every payload on every parameter?"

Our answer is a **heuristic planner** that is deterministic (so it runs offline
with no API key and is 100% reproducible in the defence), with a documented hook
for an LLM planner to re-rank steps. Prioritisation uses:
  * asset criticality (tier1 assets get the high-impact server-side vectors first),
  * reconnaissance (only plan vectors whose endpoint was actually observed),
  * memory (never re-queue a (vector, target) that already failed).

It also adapts when it detects it is being blocked (WAF / rate-limit): instead of
hammering the same payload, it backs off and switches tactic (timing / encoding).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol

from .memory import AttackMemory

# Per-vector metadata. The verifier name maps to a function in redteam.verify.
VECTOR_CATALOG: dict[str, dict] = {
    "boolean_sqli": {
        "title": "Boolean-blind SQL injection",
        "domain": "web",
        "path": "/products", "param": "q",
        "cwe_id": "CWE-89", "mitre_technique_id": "T1190",
        "stride_category": "tampering",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "verifier": "verify_boolean_sqli", "base_priority": 10,
    },
    "time_sqli": {
        "title": "Time-blind SQL injection",
        "domain": "web",
        "path": "/products", "param": "q",
        "cwe_id": "CWE-89", "mitre_technique_id": "T1190",
        "stride_category": "tampering",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "verifier": "verify_time_sqli", "base_priority": 12,
    },
    "idor": {
        "title": "IDOR / broken object-level authorisation",
        "domain": "access_control",
        "path": "/api/basket/{id}", "param": None,
        "cwe_id": "CWE-639", "mitre_technique_id": "T1190",
        "stride_category": "information_disclosure",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "verifier": "verify_idor", "base_priority": 15,
    },
    "reflected_xss": {
        "title": "Reflected cross-site scripting",
        "domain": "web",
        "path": "/search", "param": "q",
        "cwe_id": "CWE-79", "mitre_technique_id": "T1059.007",
        "stride_category": "tampering",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "verifier": "verify_reflected_xss", "base_priority": 30,
    },
    "prompt_injection": {
        "title": "LLM prompt injection / system-prompt extraction (MITRE ATLAS AML.T0051)",
        "domain": "llm",
        "path": "/chat", "param": None,
        "cwe_id": "CWE-1427", "mitre_technique_id": "T1190",
        "stride_category": "information_disclosure",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "verifier": "verify_prompt_injection", "base_priority": 40,
    },
}

# Tier1/2 assets prioritise confidentiality/integrity-impacting server-side bugs.
_TIER_BONUS = {"tier1_critical": -8, "tier2_high": -4, "tier3_moderate": 0, "tier4_low": 4}


@dataclass
class ProbeStep:
    vector: str
    title: str
    domain: str
    path: str
    param: Optional[str]
    cwe_id: str
    mitre_technique_id: str
    stride_category: str
    cvss_vector: str
    verifier: str
    priority: float


class LLMPlanner(Protocol):
    """Optional hook: an LLM re-ranks/annotates the plan. Default is a no-op so
    the agent is fully deterministic without any API key."""
    def rerank(self, steps: list[ProbeStep], context: dict) -> list[ProbeStep]: ...


class NullLLMPlanner:
    def rerank(self, steps: list[ProbeStep], context: dict) -> list[ProbeStep]:
        return steps


class HeuristicPlanner:
    def __init__(self, llm: Optional[LLMPlanner] = None):
        self.llm = llm or NullLLMPlanner()

    def plan(
        self,
        criticality_tier: str,
        memory: AttackMemory,
        target: str,
        observed_endpoints: Optional[set[str]] = None,
    ) -> list[ProbeStep]:
        bonus = _TIER_BONUS.get(criticality_tier, 0)
        steps: list[ProbeStep] = []
        for vector, meta in VECTOR_CATALOG.items():
            # Recon gate: only plan a vector whose endpoint we actually saw.
            if observed_endpoints is not None:
                root = meta["path"].split("/{")[0]
                if root not in observed_endpoints:
                    continue
            # Memory gate: skip a (vector, target) we already tried.
            if memory.already_tried(vector, target):
                continue
            steps.append(
                ProbeStep(
                    vector=vector,
                    title=meta["title"],
                    domain=meta["domain"],
                    path=meta["path"],
                    param=meta["param"],
                    cwe_id=meta["cwe_id"],
                    mitre_technique_id=meta["mitre_technique_id"],
                    stride_category=meta["stride_category"],
                    cvss_vector=meta["cvss_vector"],
                    verifier=meta["verifier"],
                    priority=meta["base_priority"] + bonus,
                )
            )
        steps.sort(key=lambda s: s.priority)
        return self.llm.rerank(steps, {"criticality_tier": criticality_tier, "target": target})

    @staticmethod
    def detect_block(status: int, body: str) -> bool:
        """Heuristic: are we being blocked by a WAF / rate-limiter?"""
        if status in (403, 429):
            return True
        needles = ("request blocked", "access denied", "waf", "rate limit", "too many requests")
        low = body.lower()
        return any(n in low for n in needles)

    @staticmethod
    def adapt_on_block(step: ProbeStep, attempt: int) -> dict:
        """When blocked, don't repeat the payload — change timing/encoding/path.
        Returns a strategy hint the agent applies on the next try."""
        tactics = [
            {"tactic": "backoff", "delay_s": 1.0 * attempt},
            {"tactic": "url_encode_payload"},
            {"tactic": "case_vary_keywords"},
            {"tactic": "chunked_timing"},
        ]
        return tactics[min(attempt, len(tactics) - 1)]
