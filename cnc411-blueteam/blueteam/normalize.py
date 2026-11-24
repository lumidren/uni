"""Vendor-agnostic log normalisation — the first pillar of the Blue Team.

Heterogeneous inputs (Windows Security events, Linux auth/syslog, multi-vendor
firewall records) are parsed into ONE ``NormalizedEvent`` schema so every
downstream stage — detection, correlation, SOAR — is written once and works
across the whole estate. New source types are added by writing one parser, not
by touching detection logic.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

# Windows Security Event IDs we care about (high signal-to-noise for our scenarios).
WINDOWS_EVENTS = {
    4625: ("failed_logon", None),
    4624: ("successful_logon", None),
    4769: ("kerberos_service_ticket", "T1558.003"),   # Kerberoasting
    4648: ("explicit_cred_logon", "T1078"),
    4672: ("special_privileges_assigned", "T1078"),
    4720: ("account_created", "T1136"),
}


@dataclass
class NormalizedEvent:
    ts: float
    source_type: str          # "windows" | "linux" | "firewall"
    host: str
    action: str               # normalised verb (failed_logon, sudo, deny, ...)
    user: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    event_code: Optional[str] = None
    message: str = ""
    mitre_hint: Optional[str] = None
    attrs: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Windows Security events (dict form, as a SIEM collector would deliver them)
# --------------------------------------------------------------------------- #
def parse_windows(evt: dict) -> NormalizedEvent:
    eid = int(evt.get("EventID", 0))
    action, mitre = WINDOWS_EVENTS.get(eid, ("windows_event", None))
    return NormalizedEvent(
        ts=float(evt.get("ts", 0.0)),
        source_type="windows",
        host=evt.get("Computer", "unknown"),
        action=action,
        user=evt.get("TargetUserName") or evt.get("SubjectUserName"),
        src_ip=evt.get("IpAddress"),
        event_code=f"EID-{eid}",
        message=evt.get("Message", ""),
        mitre_hint=mitre,
        attrs={k: v for k, v in evt.items() if k not in {"ts", "EventID", "Computer"}},
    )


# --------------------------------------------------------------------------- #
# Linux auth / syslog (raw text lines)
# --------------------------------------------------------------------------- #
_LINUX_FAIL = re.compile(r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
_LINUX_OK = re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>\S+)")
_LINUX_SUDO = re.compile(r"sudo:\s+(?P<user>\S+).*COMMAND=(?P<cmd>.+)")


def parse_linux(line: str, ts: float = 0.0, host: str = "linux-host") -> NormalizedEvent:
    if (m := _LINUX_FAIL.search(line)):
        return NormalizedEvent(ts, "linux", host, "failed_logon",
                               user=m.group("user"), src_ip=m.group("ip"),
                               message=line, mitre_hint="T1110.003")
    if (m := _LINUX_OK.search(line)):
        return NormalizedEvent(ts, "linux", host, "successful_logon",
                               user=m.group("user"), src_ip=m.group("ip"), message=line)
    if (m := _LINUX_SUDO.search(line)):
        return NormalizedEvent(ts, "linux", host, "sudo",
                               user=m.group("user"), message=line, mitre_hint="T1548.003",
                               attrs={"cmd": m.group("cmd")})
    return NormalizedEvent(ts, "linux", host, "syslog", message=line)


# --------------------------------------------------------------------------- #
# Firewall records (FortiGate / Cisco-ish key=val or dict)
# --------------------------------------------------------------------------- #
def parse_firewall(rec: dict, host: str = "perimeter-fw") -> NormalizedEvent:
    action = (rec.get("action") or "accept").lower()
    action = "deny" if action in {"deny", "drop", "block"} else "allow"
    mitre = None
    # DNS tunneling heuristic hint
    if str(rec.get("service", "")).lower() == "dns" and int(rec.get("bytes", 0)) > 2000:
        mitre = "T1071.004"
    return NormalizedEvent(
        ts=float(rec.get("ts", 0.0)),
        source_type="firewall",
        host=host,
        action=action,
        src_ip=rec.get("srcip"),
        dst_ip=rec.get("dstip"),
        event_code=rec.get("service"),
        message=str(rec),
        mitre_hint=mitre,
        attrs={k: v for k, v in rec.items() if k not in {"ts", "action", "srcip", "dstip"}},
    )


def normalize_any(source_type: str, record: Any, **kw) -> NormalizedEvent:
    if source_type == "windows":
        return parse_windows(record)
    if source_type == "linux":
        return parse_linux(record, **kw)
    if source_type == "firewall":
        return parse_firewall(record, **kw)
    raise ValueError(f"unknown source_type: {source_type!r}")
