"""Adapter so the Red Team package can reuse the repo-root ``shared.contracts``.

In the monorepo, ``shared/`` lives two levels up from this package. We add the
repo root to ``sys.path`` once and re-export the handful of helpers we need. If
the package is ever vendored on its own (outside the monorepo), a tiny local
fallback keeps it working.
"""
from __future__ import annotations

import datetime as _dt
import pathlib
import sys

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

try:  # preferred: the shared contracts
    from shared.contracts import (  # type: ignore  # noqa: F401
        EXERCISE_RUN_HEADER,
        Finding,
        ChainStep,
        new_exercise_run_id,
        new_finding_id,
        utc_now_iso,
    )
except Exception:  # pragma: no cover - standalone fallback
    EXERCISE_RUN_HEADER = "X-Exercise-Run-ID"

    def utc_now_iso() -> str:
        return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    import secrets as _secrets

    def _tok(n: int = 6) -> str:
        return "".join(_secrets.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))

    def new_exercise_run_id() -> str:
        return f"run-{_dt.datetime.now().strftime('%Y%m%d')}-{_tok()}"

    def new_finding_id() -> str:
        return f"find-{_tok()}"

    Finding = None  # type: ignore
    ChainStep = None  # type: ignore
