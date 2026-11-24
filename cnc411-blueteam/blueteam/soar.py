"""Vendor-neutral SOAR: one containment *decision* dispatches to whatever device
or OS actually needs to act — without the detection logic knowing the vendor.

The handout's question is: how can "Block Malicious IP" / "Isolate Host" run
across FortiGate, Cisco, Windows/AD and Linux without rewriting core logic? The
answer here is a thin `Connector` interface with per-vendor implementations, and
a `SoarEngine` that (a) chooses the action from the technique, (b) chooses the
connector from the asset context, and (c) forces **human approval** for
high-impact actions on high-criticality assets, surfacing the explanation at the
moment of approval.

All connectors are SIMULATED — they record what they *would* do. Nothing here
ever touches a production device; that is a hard safety boundary.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# Which technique maps to which containment verb (vendor-neutral).
_TECHNIQUE_ACTION = {
    "T1110.003": "block_ip",       # password spraying -> block source
    "T1558.003": "disable_account",  # kerberoasting -> disable targeted/service acct
    "T1071.004": "block_ip",       # DNS tunnelling -> block exfil channel
    "T1548.003": "isolate_host",   # linux sudo privesc -> isolate host
    "T1053": "isolate_host",
    "T1557.002": "block_ip",       # ARP poisoning -> block/quarantine port
    "T1078": "disable_account",
}

# Actions considered high-impact (need approval on critical assets).
_HIGH_IMPACT = {"isolate_host", "disable_account"}


@dataclass
class ContainmentDecision:
    action: str                 # block_ip | isolate_host | disable_account | none | pending_human_approval
    target: str                 # ip / host / account the action applies to
    vendor: str                 # which connector would execute it
    rationale: str
    requires_approval: bool = False
    approved: bool = False
    executed: bool = False
    residual_status: str = "open"

    def effective_action(self) -> str:
        if self.requires_approval and not self.approved:
            return "pending_human_approval"
        return self.action


# --------------------------------------------------------------------------- #
# simulated vendor connectors
# --------------------------------------------------------------------------- #
class Connector:
    vendor = "generic"

    def execute(self, action: str, target: str) -> str:
        # Returns a log line; never performs a real network/host change.
        return f"[SIMULATED {self.vendor}] {action} -> {target}"


class FortiGateConnector(Connector):
    vendor = "fortigate"


class CiscoConnector(Connector):
    vendor = "cisco_asa"


class ActiveDirectoryConnector(Connector):
    vendor = "windows_ad"


class LinuxEdrConnector(Connector):
    vendor = "linux_edr"


# choose a connector from the action + asset OS/vendor hint
def _pick_vendor(action: str, asset_os: str, fw_vendor: str) -> str:
    if action == "block_ip":
        return fw_vendor
    if action == "disable_account":
        return "windows_ad" if asset_os == "windows" else "linux_edr"
    if action == "isolate_host":
        return "windows_ad" if asset_os == "windows" else "linux_edr"
    return "generic"


class SoarEngine:
    def __init__(self, default_fw_vendor: str = "fortigate"):
        self.default_fw_vendor = default_fw_vendor
        self.connectors = {
            "fortigate": FortiGateConnector(),
            "cisco_asa": CiscoConnector(),
            "windows_ad": ActiveDirectoryConnector(),
            "linux_edr": LinuxEdrConnector(),
            "generic": Connector(),
        }
        self.audit_log: list[str] = []

    def decide(
        self,
        technique: str,
        target: str,
        *,
        asset_tier: str = "tier3_moderate",
        asset_os: str = "windows",
        explanation: Optional[dict] = None,
        fw_vendor: Optional[str] = None,
    ) -> ContainmentDecision:
        action = _TECHNIQUE_ACTION.get(technique, "none")
        vendor = _pick_vendor(action, asset_os, fw_vendor or self.default_fw_vendor)
        # Human-in-the-loop: high-impact action on a critical asset must be
        # approved by a person, and the explanation is attached for that review.
        high_impact = action in _HIGH_IMPACT
        critical = asset_tier in {"tier1_critical", "tier2_high"}
        requires_approval = high_impact and critical
        rationale = (
            f"technique {technique} -> {action} on {target} via {vendor}; "
            f"asset_tier={asset_tier}."
            + (" HIGH-IMPACT on critical asset: human approval required." if requires_approval else "")
        )
        return ContainmentDecision(
            action=action,
            target=target,
            vendor=vendor,
            rationale=rationale,
            requires_approval=requires_approval,
        )

    def execute(self, decision: ContainmentDecision, approver: Optional[str] = None) -> ContainmentDecision:
        if decision.action == "none":
            decision.residual_status = "open"
            return decision
        if decision.requires_approval and not approver:
            # Not approved yet: do NOT act. Fail safe.
            decision.residual_status = "partially_contained"
            self.audit_log.append(f"HELD for approval: {decision.rationale}")
            return decision
        if approver:
            decision.approved = True
        line = self.connectors[decision.vendor].execute(decision.action, decision.target)
        if approver:
            line += f"  (approved by {approver})"
        self.audit_log.append(line)
        decision.executed = True
        decision.residual_status = "contained"
        return decision
