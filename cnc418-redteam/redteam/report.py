"""Machine-readable reporting: standardized JSON + SARIF 2.1.0.

Two consumers:
  * the Blue Team and GRC platform ingest the **JSON** findings, and
  * tooling / CI ingests the **SARIF 2.1.0** document.

A multi-step finding is NOT flattened: the JSON keeps its ordered ``chain[]`` and
the SARIF represents the sequence as a ``codeFlow`` (one threadFlow location per
step), so the sequence of steps survives into both formats.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

_TOOL_NAME = "cnc418-redteam"
_TOOL_URI = "https://github.com/lumidren/uni/tree/main/cnc418-redteam"


def findings_to_json(findings: Iterable[Any]) -> list[dict]:
    """Canonical JSON array of Finding records (each is schema-valid)."""
    return [f.to_dict() for f in findings]


def _rules_from(findings: list[dict]) -> list[dict]:
    rules: dict[str, dict] = {}
    for f in findings:
        rid = f["cwe_id"]
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": rid.replace("-", "_"),
                "shortDescription": {"text": f"{rid} ({f['stride_category']})"},
                "properties": {
                    "cwe": rid,
                    "mitre_technique_id": f["mitre_technique_id"],
                    "stride": f["stride_category"],
                },
            }
    return list(rules.values())


def _code_flow(chain: list[dict]) -> dict:
    """Represent an ordered attack chain as a SARIF codeFlow."""
    locations = []
    for step in chain:
        locations.append({
            "location": {
                "message": {
                    "text": f"step {step['step']}: {step['name']} "
                            f"[{step.get('mitre_technique_id', '')}] -> enables {step.get('enables', 'n/a')}"
                }
            }
        })
    return {"threadFlows": [{"locations": locations}]}


def to_sarif(findings: Iterable[Any], run_id: str, tool_version: str = "1.0.0") -> dict:
    recs = findings_to_json(findings)
    results = []
    for f in recs:
        result = {
            "ruleId": f["cwe_id"],
            "level": "error" if f["exploit_status"] == "verified" else "warning",
            "message": {
                "text": f"{f['cwe_id']} on {f['target_asset']} "
                        f"(status={f['exploit_status']}, mitre={f['mitre_technique_id']})"
            },
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": f["target_asset"]}}
            }],
            "properties": {
                "finding_id": f["finding_id"],
                "exercise_run_id": f["exercise_run_id"],
                "stride_category": f["stride_category"],
                "mitre_technique_id": f["mitre_technique_id"],
                "cvss_vector": f["cvss_vector"],
                "exploit_status": f["exploit_status"],
                "verified_poc": f["verified_poc"],
            },
        }
        if f.get("chain"):
            result["codeFlows"] = [_code_flow(f["chain"])]
        results.append(result)

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": _TOOL_NAME,
                "version": tool_version,
                "informationUri": _TOOL_URI,
                "rules": _rules_from(recs),
            }},
            "results": results,
            "properties": {"exercise_run_id": run_id},
        }],
    }


def write_reports(findings: Iterable[Any], run_id: str, out_dir: str | Path) -> dict[str, str]:
    findings = list(findings)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / f"findings_{run_id}.json"
    sarif_path = out / f"findings_{run_id}.sarif.json"
    json_path.write_text(json.dumps(findings_to_json(findings), indent=2), encoding="utf-8")
    sarif_path.write_text(json.dumps(to_sarif(findings, run_id), indent=2), encoding="utf-8")
    return {"json": str(json_path), "sarif": str(sarif_path)}
