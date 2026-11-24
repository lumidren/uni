"""Adapter to the repo-root ``shared.contracts`` for the Blue Team package."""
from __future__ import annotations

import datetime as _dt
import pathlib
import sys

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

try:
    from shared.contracts import (  # type: ignore  # noqa: F401
        AssetProfile,
        Finding,
        Incident,
        validate,
        ContractError,
        EXERCISE_RUN_HEADER,
        new_incident_id,
        utc_now_iso,
    )
except Exception:  # pragma: no cover
    EXERCISE_RUN_HEADER = "X-Exercise-Run-ID"
    AssetProfile = Finding = Incident = None  # type: ignore

    def utc_now_iso() -> str:
        return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    import secrets as _secrets

    def new_incident_id() -> str:
        return "inc-" + "".join(_secrets.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(6))
