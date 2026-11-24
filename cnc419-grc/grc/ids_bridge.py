"""Adapter to the repo-root ``shared.contracts`` for the GRC package."""
from __future__ import annotations

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
    )
except Exception:  # pragma: no cover
    AssetProfile = Finding = Incident = None  # type: ignore
    EXERCISE_RUN_HEADER = "X-Exercise-Run-ID"

    class ContractError(Exception):
        pass

    def validate(kind, payload):  # type: ignore
        return payload
