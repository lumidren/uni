"""Shared identifier helpers for the Red-Blue-GRC ecosystem.

Every artefact that crosses a course boundary is tied together by a single
``exercise_run_id``. The same value is also pinned onto the wire as the
``X-Exercise-Run-ID`` HTTP header so the Blue Team can correlate Red Team
traffic without parsing payloads.

The id scheme is deliberately boring and human-readable so that, during the
oral defence, any team member can point at a log line and say exactly which
exercise / finding / incident it belongs to.
"""
from __future__ import annotations

import datetime as _dt
import secrets

# Canonical header name used by every component on the wire.
EXERCISE_RUN_HEADER = "X-Exercise-Run-ID"

_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"


def _token(n: int = 6) -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(n))


def new_exercise_run_id() -> str:
    """A run id for one Purple Team exercise, e.g. ``run-20261124-a1b2c3``."""
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%d")
    return f"run-{stamp}-{_token(6)}"


def new_finding_id() -> str:
    """Red Team finding id, e.g. ``find-a1b2c3``."""
    return f"find-{_token(6)}"


def new_incident_id() -> str:
    """Blue Team incident id, e.g. ``inc-a1b2c3``."""
    return f"inc-{_token(6)}"


def new_asset_id(seq: int) -> str:
    """GRC asset id, e.g. ``asset-0007``."""
    return f"asset-{seq:04d}"


def utc_now_iso() -> str:
    """ISO-8601 UTC timestamp with a trailing Z, used across all records."""
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
