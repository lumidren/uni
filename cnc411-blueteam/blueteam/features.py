"""Feature definitions shared by training and the live pipeline.

One canonical feature order so the dataset generator, the trained model, and the
real-time detector can never drift apart. Each feature is a behavioural signal
with high signal-to-noise for the attack scenarios in the handout
(Kerberoasting, password spraying, Linux priv-esc, DNS tunnelling, lateral
movement).
"""
from __future__ import annotations

import math
from collections import Counter
from typing import Iterable

FEATURE_NAMES = [
    "auth_failures_5m",      # brute force / password spray
    "distinct_targets_5m",   # spray breadth / kerberoast enumeration
    "off_hours",             # 1 if outside 08:00-18:00
    "kerberos_ticket_rate",  # 4769 bursts -> Kerberoasting
    "dns_query_entropy",     # high entropy subdomains -> DNS tunnelling
    "dns_bytes_out_kb",      # exfil volume over DNS
    "sudo_cmd_anomaly",      # unusual privileged command
    "lateral_conn_count",    # internal fan-out -> lateral movement
    "new_account_flag",      # account creation / persistence
]

# Human-readable descriptions used by the XAI explainer.
FEATURE_DESCRIPTIONS = {
    "auth_failures_5m": "failed authentications in the last 5 minutes",
    "distinct_targets_5m": "distinct accounts targeted in the last 5 minutes",
    "off_hours": "activity outside business hours",
    "kerberos_ticket_rate": "Kerberos service-ticket requests per minute (4769)",
    "dns_query_entropy": "Shannon entropy of DNS query labels",
    "dns_bytes_out_kb": "outbound DNS payload volume (KB)",
    "sudo_cmd_anomaly": "anomalous privileged-command score",
    "lateral_conn_count": "distinct internal hosts contacted",
    "new_account_flag": "a new account was created",
}


def vector_from_dict(d: dict) -> list[float]:
    """Project a feature dict onto the canonical ordered vector."""
    return [float(d.get(name, 0.0)) for name in FEATURE_NAMES]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def window_to_features(events: Iterable, now_hour: int = 12) -> dict:
    """Aggregate a window of NormalizedEvents into the feature dict used by the
    detector in the live pipeline."""
    events = list(events)
    auth_fail = sum(1 for e in events if e.action == "failed_logon")
    targets = {e.user for e in events if e.action == "failed_logon" and e.user}
    kerb = sum(1 for e in events if e.action == "kerberos_service_ticket")
    dns_events = [e for e in events if (e.event_code or "").lower() == "dns"]
    dns_bytes = sum(int(e.attrs.get("bytes", 0)) for e in dns_events)
    dns_ent = max((shannon_entropy(str(e.attrs.get("qname", ""))) for e in dns_events), default=0.0)
    sudo = sum(1 for e in events if e.action == "sudo")
    lateral = len({e.dst_ip for e in events if e.dst_ip})
    new_acct = 1.0 if any(e.action in {"account_created"} for e in events) else 0.0
    return {
        "auth_failures_5m": float(auth_fail),
        "distinct_targets_5m": float(len(targets)),
        "off_hours": 1.0 if (now_hour < 8 or now_hour >= 18) else 0.0,
        "kerberos_ticket_rate": float(kerb),
        "dns_query_entropy": float(dns_ent),
        "dns_bytes_out_kb": float(dns_bytes) / 1024.0,
        "sudo_cmd_anomaly": float(sudo),
        "lateral_conn_count": float(lateral),
        "new_account_flag": new_acct,
    }
