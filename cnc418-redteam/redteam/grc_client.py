"""Inbound GRC context: pull asset criticality profiles so the agent attacks
high-value assets first instead of spraying every payload everywhere.

Tries the live GRC API (``GET /api/v1/assets/profile``). If that is not up
(e.g. running the Red Team standalone), it falls back to a local mock payload so
the pipeline still works. Every profile is run through the shared contract
validator before the agent trusts it.
"""
from __future__ import annotations

import json
import pathlib
from typing import Optional

from .transport import Transport
from .ids_bridge import _REPO_ROOT  # noqa: F401  (ensures repo root on sys.path)

try:
    from shared.contracts import AssetProfile, validate  # type: ignore
except Exception:  # pragma: no cover
    AssetProfile = None  # type: ignore
    validate = None  # type: ignore

# Criticality order used to prioritise targets.
_TIER_RANK = {
    "tier1_critical": 0,
    "tier2_high": 1,
    "tier3_moderate": 2,
    "tier4_low": 3,
}


def _load_mock(path: Optional[str]) -> list[dict]:
    if path and pathlib.Path(path).exists():
        return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    return []


def fetch_asset_profiles(
    grc_base_url: Optional[str] = None,
    *,
    transport: Optional[Transport] = None,
    mock_path: Optional[str] = None,
) -> list["AssetProfile"]:
    """Return asset profiles sorted by descending criticality.

    Order of preference: live GRC API -> local mock JSON -> empty list.
    """
    raw: list[dict] = []

    if grc_base_url and transport is not None:
        try:
            resp = transport.get(f"{grc_base_url}/api/v1/assets/profile")
            if resp.status == 200:
                data = json.loads(resp.body)
                raw = data if isinstance(data, list) else data.get("assets", [])
        except Exception:
            raw = []

    if not raw:
        raw = _load_mock(mock_path)

    profiles = []
    for item in raw:
        if validate is not None:
            try:
                profiles.append(validate("asset", item))
            except Exception:
                continue
        elif AssetProfile is not None:
            profiles.append(AssetProfile.from_dict(item))

    profiles.sort(key=lambda p: _TIER_RANK.get(p.criticality_tier, 9))
    return profiles
