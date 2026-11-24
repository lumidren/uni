"""Shared cross-course contracts for the Red-Blue-GRC capstone ecosystem.

Import surface kept deliberately small::

    from shared.contracts import (
        AssetProfile, Finding, ChainStep, Incident,
        validate, ContractError,
        new_exercise_run_id, EXERCISE_RUN_HEADER,
    )
"""
from .models import AssetProfile, ChainStep, Finding, Incident
from .validate import (
    ContractError,
    validate,
    validate_asset_profile,
    validate_finding,
    validate_incident,
)
from .ids import (
    EXERCISE_RUN_HEADER,
    new_asset_id,
    new_exercise_run_id,
    new_finding_id,
    new_incident_id,
    utc_now_iso,
)

__all__ = [
    "AssetProfile",
    "ChainStep",
    "Finding",
    "Incident",
    "validate",
    "validate_asset_profile",
    "validate_finding",
    "validate_incident",
    "ContractError",
    "EXERCISE_RUN_HEADER",
    "new_asset_id",
    "new_exercise_run_id",
    "new_finding_id",
    "new_incident_id",
    "utc_now_iso",
]
