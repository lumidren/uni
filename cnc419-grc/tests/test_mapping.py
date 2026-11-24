"""Cross-framework mapping + conflict detection + ingestion.

    python cnc419-grc/tests/test_mapping.py
"""
from __future__ import annotations

import pathlib
import sys

_PKG_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PKG_ROOT))

from grc.frameworks import REQUIREMENTS, CONTROLS            # noqa: E402
from grc.mapping import MappingEngine                         # noqa: E402
from grc.ingest import ingest_document, extract_requirements  # noqa: E402


def _run():
    failures = 0
    engine = MappingEngine(REQUIREMENTS, CONTROLS)

    mappings = engine.map_all()
    conflicts = engine.detect_conflicts()

    # 1. equivalence across frameworks (ISO least-privilege <-> NIST AC-6)
    eqs = {(m.source_req, m.target_req) for m in mappings if m.relationship == "equivalent"}
    has_iso_nist = any({"ISO27001-A.9.2", "NIST-AC-6"} == set(pair) for pair in eqs)
    failures += 0 if has_iso_nist else 1

    # 2. the GDPR(transfer) vs PDPL(localize) conflict is detected
    movement = [c for c in conflicts if c.domain == "data_movement"]
    failures += 0 if movement else 1

    # 3. a retain-vs-delete lifecycle conflict is detected
    lifecycle = [c for c in conflicts if c.domain == "data_lifecycle"]
    failures += 0 if lifecycle else 1

    # 4. the data-residency requirement is a coverage gap (no control)
    gaps = {g.req_id for g in engine.coverage_gaps()}
    failures += 0 if "PDPL-Art14" in gaps else 1

    # 5. mapping evidence is structural (shared tags), not text-only
    tagged = [m for m in mappings if m.shared_tags]
    failures += 0 if tagged else 1

    # 6. ingestion of an unseen doc extracts clauses and flags a conflict
    doc = ("Article 1. Encrypt all data at rest.\n"
           "Article 2. Retain audit logs for seven years.\n"
           "Article 3. Personal data must be stored within the country and not transferred abroad.\n")
    res = ingest_document(doc, "TESTREG")
    failures += 0 if res.summary()["extracted_requirements"] == 3 else 1
    failures += 0 if res.summary()["conflicts"] >= 1 else 1

    print("test_mapping:", "PASS" if not failures else f"FAIL ({failures})")
    return failures


if __name__ == "__main__":
    raise SystemExit(1 if _run() else 0)
