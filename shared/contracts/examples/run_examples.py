"""Smoke check: load every example payload and validate it against the contracts.

Runnable with a bare interpreter (no pytest needed):

    python shared/contracts/examples/run_examples.py

Exits non-zero if any example violates its schema.
"""
from __future__ import annotations

import json
import pathlib
import sys

# Make the repo root importable when run directly.
_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_REPO_ROOT))

from shared.contracts import (  # noqa: E402
    EXERCISE_RUN_HEADER,
    ContractError,
    new_exercise_run_id,
    validate,
)

_HERE = pathlib.Path(__file__).resolve().parent
_CASES = [
    ("asset", "asset_profile.example.json"),
    ("finding", "finding.example.json"),
    ("incident", "incident.example.json"),
]


def main() -> int:
    failures = 0
    for kind, filename in _CASES:
        payload = json.loads((_HERE / filename).read_text(encoding="utf-8"))
        try:
            obj = validate(kind, payload)
            print("OK   {:8} -> {}".format(kind, type(obj).__name__))
        except ContractError as exc:
            failures += 1
            print("FAIL {:8} -> {}".format(kind, exc))

    finding = validate(
        "finding",
        json.loads((_HERE / "finding.example.json").read_text(encoding="utf-8")),
    )
    print("chain? {}  steps: {}".format(finding.is_chain, len(finding.chain)))
    print("header: {}  sample run id: {}".format(EXERCISE_RUN_HEADER, new_exercise_run_id()))

    # Negative test: a bad enum must be rejected.
    try:
        validate("finding", {**payload, "exploit_status": "totally-made-up"})
        print("FAIL negative -> bad enum was accepted")
        failures += 1
    except ContractError:
        print("OK   negative -> bad enum rejected as expected")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
