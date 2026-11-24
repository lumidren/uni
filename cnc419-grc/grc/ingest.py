"""Standard-neutral ingestion: upload ANY regulatory document and immediately
extract its requirements, then map them against the preloaded frameworks.

Extraction is deterministic and keyword-driven (tags + obligation type), so it
runs with no LLM and every inference is explainable. An LLM/RAG backend can
replace ``_infer_tags`` / ``_infer_obligation`` for messier documents without
touching the mapping engine — the output contract (``Requirement``) is the same.
"""
from __future__ import annotations

import re
from typing import Optional

from .frameworks import Requirement, REQUIREMENTS, CONTROLS
from .mapping import MappingEngine, Mapping, Conflict, ControlCoverage

# keyword -> (tags, obligation)
_TAG_RULES = [
    (re.compile(r"encrypt|cryptograph|cipher", re.I), ("encryption", "data_protection"), "protect"),
    (re.compile(r"least privilege|access control|authenticat|multi-?factor|\bmfa\b", re.I),
     ("access_control", "identity"), "protect"),
    (re.compile(r"\blog(s|ging)?\b|audit|monitor", re.I), ("logging", "monitoring"), "retain"),
    (re.compile(r"retain|retention|keep .*(year|month|period)", re.I), ("data_retention",), "retain"),
    (re.compile(r"eras(e|ure)|delete|deletion|right to be forgotten", re.I),
     ("data_deletion", "data_subject_rights"), "delete"),
    (re.compile(r"portab|transmit .* controller|transfer .* subject", re.I),
     ("data_portability", "data_subject_rights"), "transfer"),
    (re.compile(r"cross-?border|outside the|within the country|residen|localiz|data localisation", re.I),
     ("data_residency", "cross_border"), "localize"),
    (re.compile(r"breach|notif(y|ication)", re.I), ("breach_notification", "incident_response"), "general"),
    (re.compile(r"consent", re.I), ("consent", "data_subject_rights"), "delete"),
    (re.compile(r"incident|response|containment", re.I), ("incident_response",), "general"),
]

_CLAUSE = re.compile(r"^\s*(?:(?:art(?:icle)?|section|clause|§)\s*)?(\d+(?:\.\d+)*)[\).:\-\s]+(.*)", re.I)


def _infer(text: str) -> tuple[tuple[str, ...], str]:
    tags: list[str] = []
    obligation = "general"
    for rx, tg, obl in _TAG_RULES:
        if rx.search(text):
            tags.extend(tg)
            if obligation == "general":
                obligation = obl
    if not tags:
        tags = ["general"]
    # de-dup, keep order
    seen = []
    for t in tags:
        if t not in seen:
            seen.append(t)
    return tuple(seen), obligation


def _make_req(framework: str, num: str, body: str) -> Requirement:
    tags, obligation = _infer(body)
    return Requirement(
        req_id=f"{framework}-{num}",
        framework=framework,
        title=body.split(".")[0][:60],
        text=body,
        control_tags=tags,
        obligation_type=obligation,
    )


def extract_requirements(text: str, framework: str) -> list[Requirement]:
    """Build Requirements from a document.

    Prefer explicitly-numbered clauses (Article/Section/§/N.). Markdown headings
    and intro prose are skipped so they do not become spurious requirements. If
    the document has no numbered clauses at all, fall back to splitting its
    substantial sentences.
    """
    reqs: list[Requirement] = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("#") or len(line) < 20:
            continue
        m = _CLAUSE.match(line)
        if m:
            reqs.append(_make_req(framework, m.group(1), m.group(2)))
    if reqs:
        return reqs

    # Fallback: no clause markers -> treat substantial sentences as clauses.
    sentences = [s.strip() for s in re.split(r"(?<=[.])\s+", text) if len(s.strip()) >= 25]
    return [_make_req(framework, str(i + 1), s) for i, s in enumerate(sentences)]


class IngestResult:
    def __init__(self, requirements, mappings, conflicts, coverage):
        self.requirements: list[Requirement] = requirements
        self.mappings: list[Mapping] = mappings
        self.conflicts: list[Conflict] = conflicts
        self.coverage: list[ControlCoverage] = coverage

    def summary(self) -> dict:
        return {
            "extracted_requirements": len(self.requirements),
            "mappings": len(self.mappings),
            "conflicts": len(self.conflicts),
            "coverage_gaps": sum(1 for c in self.coverage if not c.covered),
        }


def ingest_document(text: str, framework: str,
                    base_requirements: Optional[list[Requirement]] = None) -> IngestResult:
    """Full pipeline: extract -> map against existing frameworks -> conflicts -> gaps."""
    base = base_requirements if base_requirements is not None else REQUIREMENTS
    new_reqs = extract_requirements(text, framework)
    engine = MappingEngine(base + new_reqs, CONTROLS)

    mappings = []
    for r in new_reqs:
        mappings.extend(engine.map_requirement(r))

    new_ids = {r.req_id for r in new_reqs}
    conflicts = [c for c in engine.detect_conflicts()
                 if c.req_a in new_ids or c.req_b in new_ids]
    coverage = [engine.control_coverage(r) for r in new_reqs]
    return IngestResult(new_reqs, mappings, conflicts, coverage)
