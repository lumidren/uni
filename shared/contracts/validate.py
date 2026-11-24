"""Lightweight payload validation shared by all three subsystems.

Why not just use ``jsonschema``? We support it when it is installed (full
draft-2020-12 validation against ``shared/schemas/*.json``), but we also ship a
dependency-free fallback so the contracts can be enforced on a bare Python
install. The integration layer calls :func:`validate` at every boundary so a
malformed, duplicated or out-of-order event is rejected loudly instead of
silently corrupting the enterprise record.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from . import models

_SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schemas"

_T_PATTERN = re.compile(r"^T[0-9]{4}(\.[0-9]{3})?$")
_CWE_PATTERN = re.compile(r"^CWE-[0-9]+$")
_CVSS_PATTERN = re.compile(r"^CVSS:3\.1/.*")


class ContractError(ValueError):
    """Raised when a cross-course payload violates its contract."""


def _load_schema(name: str) -> dict[str, Any]:
    with open(_SCHEMA_DIR / name, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _try_jsonschema(payload: dict[str, Any], schema_file: str) -> bool:
    """Return True if validated with the real jsonschema lib, else False."""
    try:
        import jsonschema  # type: ignore
    except Exception:
        return False
    schema = _load_schema(schema_file)
    try:
        jsonschema.validate(payload, schema)
    except jsonschema.ValidationError as exc:  # pragma: no cover - lib path
        raise ContractError(f"{schema_file}: {exc.message}") from exc
    return True


def _require(payload: dict[str, Any], keys: list[str], label: str) -> None:
    missing = [k for k in keys if k not in payload]
    if missing:
        raise ContractError(f"{label}: missing required field(s): {missing}")


def _enum(value: Any, allowed: tuple[str, ...], label: str) -> None:
    if value not in allowed:
        raise ContractError(f"{label}: {value!r} not in {allowed}")


def validate_asset_profile(payload: dict[str, Any]) -> models.AssetProfile:
    if _try_jsonschema(payload, "asset_profile.schema.json"):
        return models.AssetProfile.from_dict(payload)
    _require(
        payload,
        ["asset_id", "ip_or_url", "criticality_tier", "mtd_minutes", "rpo_minutes", "applicable_standards"],
        "AssetProfile",
    )
    _enum(payload["criticality_tier"], models.CRITICALITY_TIERS, "AssetProfile.criticality_tier")
    if int(payload["mtd_minutes"]) < 0 or int(payload["rpo_minutes"]) < 0:
        raise ContractError("AssetProfile: mtd_minutes/rpo_minutes must be >= 0")
    if not payload["applicable_standards"]:
        raise ContractError("AssetProfile: applicable_standards must be non-empty")
    return models.AssetProfile.from_dict(payload)


def validate_finding(payload: dict[str, Any]) -> models.Finding:
    if _try_jsonschema(payload, "finding.schema.json"):
        return models.Finding.from_dict(payload)
    _require(
        payload,
        ["finding_id", "exercise_run_id", "target_asset", "cwe_id", "stride_category",
         "mitre_technique_id", "cvss_vector", "exploit_status", "verified_poc"],
        "Finding",
    )
    _enum(payload["stride_category"], models.STRIDE, "Finding.stride_category")
    _enum(payload["exploit_status"], models.EXPLOIT_STATUS, "Finding.exploit_status")
    if not _CWE_PATTERN.match(payload["cwe_id"]):
        raise ContractError(f"Finding.cwe_id bad format: {payload['cwe_id']}")
    if not _T_PATTERN.match(payload["mitre_technique_id"]):
        raise ContractError(f"Finding.mitre_technique_id bad format: {payload['mitre_technique_id']}")
    if not _CVSS_PATTERN.match(payload["cvss_vector"]):
        raise ContractError(f"Finding.cvss_vector bad format: {payload['cvss_vector']}")
    if not isinstance(payload["verified_poc"], dict) or "method" not in payload["verified_poc"]:
        raise ContractError("Finding.verified_poc must be an object with a 'method'")
    return models.Finding.from_dict(payload)


def validate_incident(payload: dict[str, Any]) -> models.Incident:
    if _try_jsonschema(payload, "incident.schema.json"):
        return models.Incident.from_dict(payload)
    _require(
        payload,
        ["incident_id", "exercise_run_id", "target_asset", "mitre_technique_id",
         "mttd_sec", "mttc_sec", "mttr_sec", "containment_action", "residual_status"],
        "Incident",
    )
    _enum(payload["containment_action"], models.CONTAINMENT_ACTIONS, "Incident.containment_action")
    _enum(payload["residual_status"], models.RESIDUAL_STATUS, "Incident.residual_status")
    if not _T_PATTERN.match(payload["mitre_technique_id"]):
        raise ContractError(f"Incident.mitre_technique_id bad format: {payload['mitre_technique_id']}")
    for k in ("mttd_sec", "mttc_sec", "mttr_sec"):
        if float(payload[k]) < 0:
            raise ContractError(f"Incident.{k} must be >= 0")
    return models.Incident.from_dict(payload)


def validate(kind: str, payload: dict[str, Any]) -> Any:
    """Dispatch by record kind: 'asset' | 'finding' | 'incident'."""
    if kind == "asset":
        return validate_asset_profile(payload)
    if kind == "finding":
        return validate_finding(payload)
    if kind == "incident":
        return validate_incident(payload)
    raise ContractError(f"unknown record kind: {kind!r}")
