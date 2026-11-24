"""Inbound GRC context for the Blue Team: asset criticality weights alert
severity and decides whether containment needs human approval."""
from __future__ import annotations

import json
import pathlib
from typing import Optional

from .ids_bridge import _REPO_ROOT  # noqa: F401  (puts repo root on sys.path)

try:
    from shared.contracts import AssetProfile, validate  # type: ignore
except Exception:  # pragma: no cover
    AssetProfile = None  # type: ignore
    validate = None  # type: ignore

_SEVERITY_WEIGHT = {
    "tier1_critical": 1.0,
    "tier2_high": 0.75,
    "tier3_moderate": 0.5,
    "tier4_low": 0.25,
}


def severity_weight(tier: str) -> float:
    return _SEVERITY_WEIGHT.get(tier, 0.5)


def load_asset_index(mock_path: Optional[str]) -> dict[str, "AssetProfile"]:
    """Map asset_id -> AssetProfile from a GRC mock payload (or empty)."""
    if not mock_path or not pathlib.Path(mock_path).exists():
        return {}
    raw = json.loads(pathlib.Path(mock_path).read_text(encoding="utf-8"))
    items = raw if isinstance(raw, list) else raw.get("assets", [])
    index = {}
    for item in items:
        try:
            profile = validate("asset", item) if validate else AssetProfile.from_dict(item)
            index[profile.asset_id] = profile
        except Exception:
            continue
    return index
