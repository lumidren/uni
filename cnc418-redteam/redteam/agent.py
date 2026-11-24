"""The Red Team agent loop — reconnaissance, prioritised planning, verified
exploitation, chain assembly, and reporting.

Flow per run:
  1. Ingest GRC asset profiles (already criticality-sorted).
  2. For each in-allowlist asset: recon which endpoints exist.
  3. Ask the planner for a prioritised probe list (tier1 => high-impact first).
  4. Run each probe through its verifier. Only a verified proof becomes a
     Finding; an unverifiable claim is rejected (anti-hallucination).
  5. Assemble at least one multi-step chain as a single chained Finding.
  6. Emit standardized JSON + SARIF, and optionally publish to Blue/GRC.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from . import verify
from .memory import AttackMemory
from .planner import HeuristicPlanner, ProbeStep
from .transport import Transport
from .ids_bridge import ChainStep, Finding, new_finding_id


@dataclass
class RunResult:
    run_id: str
    findings: list[Any] = field(default_factory=list)
    rejected: list[dict] = field(default_factory=list)
    memory: AttackMemory = field(default_factory=AttackMemory)

    @property
    def verified_count(self) -> int:
        return sum(1 for f in self.findings if f.exploit_status == "verified")


# Candidate endpoints probed during recon -> normalised roots the planner gates on.
_RECON_ENDPOINTS = {
    "/": "/",
    "/search?q=cnc418probe": "/search",
    "/products?q=cnc418probe": "/products",
    "/api/basket/1": "/api/basket",
    "/chat": "/chat",
}


class RedTeamAgent:
    def __init__(self, transport: Transport, run_id: str, planner: Optional[HeuristicPlanner] = None):
        self.tx = transport
        self.run_id = run_id
        self.planner = planner or HeuristicPlanner()

    # -- reconnaissance ----------------------------------------------------- #
    def recon(self, base_url: str, memory: AttackMemory) -> set[str]:
        observed: set[str] = set()
        for probe, root in _RECON_ENDPOINTS.items():
            try:
                resp = self.tx.get(f"{base_url}{probe}")
                if resp.status != 404:
                    observed.add(root)
            except Exception:
                continue
        memory.observe("endpoints", sorted(observed))
        return observed

    # -- single probe ------------------------------------------------------- #
    def _run_probe(self, step: ProbeStep, base_url: str, asset_id: str, memory: AttackMemory) -> Optional[Any]:
        memory.mark_tried(step.vector, asset_id)
        verifier = getattr(verify, step.verifier)
        proof = verifier(self.tx, base_url)
        if proof is None:
            # Could not prove it -> do NOT log a false positive. Record the rejection.
            return None
        return Finding(
            finding_id=new_finding_id(),
            exercise_run_id=self.run_id,
            target_asset=asset_id,
            cwe_id=step.cwe_id,
            stride_category=step.stride_category,
            mitre_technique_id=step.mitre_technique_id,
            cvss_vector=step.cvss_vector,
            exploit_status="verified",
            verified_poc=proof.as_poc(),
            chain=[],
        )

    # -- chain assembly ----------------------------------------------------- #
    def build_chain(self, base_url: str, asset_id: str) -> Optional[Any]:
        """A single Finding whose chain is SQLi -> IDOR, each step verified
        independently before it counts."""
        p1 = verify.verify_boolean_sqli(self.tx, base_url)
        p2 = verify.verify_idor(self.tx, base_url)
        if not (p1 and p2):
            return None
        chain = [
            ChainStep(
                step=1, name="Boolean-blind SQLi confirms an injectable, enumerable data store",
                mitre_technique_id="T1190", cwe_id="CWE-89", exploit_status="verified",
                verified_poc=p1.as_poc(), enables="confirmed injectable query context + enumerable object ids",
            ),
            ChainStep(
                step=2, name="IDOR reads another tenant's basket using an enumerable id",
                mitre_technique_id="T1190", cwe_id="CWE-639", exploit_status="verified",
                verified_poc=p2.as_poc(), enables="cross-tenant data read",
            ),
        ]
        return Finding(
            finding_id=new_finding_id(),
            exercise_run_id=self.run_id,
            target_asset=asset_id,
            cwe_id="CWE-89",
            stride_category="information_disclosure",
            mitre_technique_id="T1190",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            exploit_status="verified",
            verified_poc=p1.as_poc(),
            chain=chain,
        )

    # -- demonstrate the rejection path ------------------------------------- #
    def demo_rejection(self, base_url: str, asset_id: str) -> dict:
        """Run an XSS verifier against a JSON endpoint: the marker will NOT be
        reflected un-escaped, so the claim is rejected rather than logged. This
        is the anti-hallucination gate working, shown explicitly."""
        proof = verify.verify_reflected_xss(self.tx, base_url, path="/products", param="q")
        rejected = {
            "claimed_vector": "reflected_xss",
            "target_asset": asset_id,
            "exploit_status": "rejected",
            "reason": "verifier found no un-escaped reflection; apparent exploit could not be proven",
        }
        return rejected if proof is None else {"claimed_vector": "reflected_xss", "exploit_status": "verified"}

    # -- per-asset ---------------------------------------------------------- #
    def run_asset(self, asset: Any) -> RunResult:
        base_url = asset.ip_or_url
        result = RunResult(run_id=self.run_id)
        memory = result.memory

        observed = self.recon(base_url, memory)
        plan = self.planner.plan(asset.criticality_tier, memory, asset.asset_id, observed)

        for step in plan:
            finding = self._run_probe(step, base_url, asset.asset_id, memory)
            if finding is not None:
                result.findings.append(finding)
            else:
                result.rejected.append({
                    "claimed_vector": step.vector,
                    "target_asset": asset.asset_id,
                    "exploit_status": "rejected",
                    "reason": "verification returned no deterministic proof",
                })

        chain_finding = self.build_chain(base_url, asset.asset_id)
        if chain_finding is not None:
            result.findings.append(chain_finding)

        return result

    def run(self, assets: list[Any]) -> RunResult:
        combined = RunResult(run_id=self.run_id)
        for asset in assets:
            if not self.tx.allowlist.is_allowed(asset.ip_or_url):
                combined.rejected.append({
                    "target_asset": asset.asset_id,
                    "exploit_status": "rejected",
                    "reason": f"asset {asset.ip_or_url} is outside the allowlist; skipped",
                })
                continue
            r = self.run_asset(asset)
            combined.findings.extend(r.findings)
            combined.rejected.extend(r.rejected)
            combined.memory = r.memory
        return combined
