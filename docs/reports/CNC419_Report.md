# CNC 419 — IT Security and Risk Management
## Standard-Neutral, AI-Powered GRC & Resilience Platform

**Technical Project Report**

| | |
|---|---|
| **Course** | CNC 419 — IT Security and Risk Management |
| **Project title** | Standard-Neutral GRC & Resilience Platform (governance nerve centre of the Integrated Red–Blue–GRC Platform) |
| **Team** | `<Team number / name>` |
| **Members (name — ID)** | `<Name — ID>`; `<Name — ID>`; `<Name — ID>`; `<Name — ID>`; `<Name — ID>` |
| **Instructor** | Dr. Muhammad Hataba |
| **Repository** | https://github.com/lumidren/uni (`cnc419-grc/`) |
| **Date** | 2026-11-24 |

---

## 1. Overview & Strategic Vision

GRC is no longer a spreadsheet exercise — it is the decision hub that aligns the
business with live security telemetry. Our platform is **standard-neutral**: it
ingests *any* uploaded regulation, maps controls across frameworks (and flags
genuine conflicts), runs a **pluggable** ISRM risk engine that updates in real
time from Red/Blue activity, optimises safeguards under a budget, validates
resilience, and enforces human sign-off on risk acceptance.

It is the **governance nerve centre** of the integrated platform: it publishes
asset criticality profiles to Red and Blue, and ingests their verified findings
and incidents to keep the risk register live.

```
   any regulation (PDF/MD) ---> ingest.py (TF-IDF RAG) ---> requirements
                                             |
         frameworks.py (ISO/PCI/NIST/GDPR/PDPL) + org controls
                                             |
                               mapping.py (equivalent/overlap/partial/gap + CONFLICT)
                                             |
   risk.py (ISO27005/NIST/OCTAVE) <----+----> optimizer.py (budget knapsack)
         ^            ^                        bia.py (RTO+WRT<=MTD) · governance.py
         |            |                        aar.py (AAR + breach clock)
   Red findings   Blue incidents
         \            /
          api.py  (GET /assets/profile · POST /findings · POST /incidents)
```

## 2. Tools, Models & Frameworks

- **Runtime:** Python 3.10+; **stdlib-only** core. The RAG backbone is a
  **dependency-free TF-IDF retriever** (`retrieval.py`) — documents and queries
  become sparse term vectors ranked by cosine similarity. Dense embeddings +
  a vector DB (Chroma/FAISS) are a documented drop-in behind the same interface;
  an LLM backend is optional for extraction/narration.
- **Preloaded standards:** ISO/IEC 27001, PCI-DSS v4.0, NIST SP 800-53, GDPR, and
  Egypt PDPL (Law 151/2020), plus organisational controls (`frameworks.py`).
- **ISRM methodologies:** ISO 27005 / NIST SP 800-30 (likelihood × impact) and an
  OCTAVE-Allegro-style impact-weighted model, selectable per risk.
- **Optimisation:** exact 0/1 knapsack (`optimizer.py`).

## 3. Cross-Framework Mapping & Compliance Intelligence (handout §3)

This is an independently-graded engine (`mapping.py`). For each requirement it
finds related requirements in **other** frameworks and labels the relationship:
**equivalent / overlapping / partial / framework-specific**, supporting
**many-to-many** control relationships. Crucially, equivalence is **never** claimed
from text alone — each mapping cites **structural evidence** (shared control
*tags*) plus the shared high-IDF *terms*.

**Conflict detection.** Each requirement carries an `obligation_type`
(retain / delete / localize / transfer / protect / general). When two requirements
share a topic **domain** but hold **contradictory obligations**, the engine flags a
genuine conflict for a human — it never hides the discrepancy in a score. On the
preloaded set it finds:

```
CONFLICT  PCI_DSS:PCI-3.1 (retain)  ✕  GDPR:GDPR-Art17 (delete)   — data_lifecycle
CONFLICT  PCI_DSS:PCI-3.1 (retain)  ✕  EGYPT_PDPL:PDPL-Art2 (delete) — data_lifecycle
CONFLICT  GDPR:GDPR-Art20 (transfer) ✕ EGYPT_PDPL:PDPL-Art14 (localize) — data_movement
GAP       PDPL-Art14: no organisational control covers [data_residency, cross_border]
```

The GDPR-portability-vs-PDPL-localization conflict is exactly the realistic
GDPR-vs-PDPL tension the brief asks for.

**Engineering challenge — ingest an unseen document.** `python cnc419-grc/cli.py`
ingests a fictional "Lab Data Protection Directive":

```
ingest summary: extracted_requirements=6, mappings=26, conflicts=3, coverage_gaps=1
  NEW CONFLICT GDPR-Art17 (delete)   ✕ LDPD-3 (retain)   — data_lifecycle  (retention-vs-erasure)
  NEW CONFLICT GDPR-Art20 (transfer) ✕ LDPD-4 (localize) — data_movement
```

Requirements are extracted, mapped against existing frameworks, and conflicts +
gaps are produced with an explainable rationale. Traceability is maintained from
requirement → tag → control → gap.

## 4. Pillars II–IV

**Pillar II — pluggable ISRM & dynamic threat modelling.** `risk.py` scores risks
by the selected methodology, tracks **inherent vs residual**, classifies by STRIDE,
and detects **Single Points of Failure** from a dependency graph (`find_spofs`).
The register is **live**: a *verified* Red finding raises likelihood (and flags
compliance drift); Blue containment lowers residual risk. Observed in the demo:

```
before:   R-001 (asset-0007 SQLi) inherent=15  residual=15
+ Red:    verified finding  -> inherent rises (likelihood +1, capped)  -> 25
+ Blue:   containment       -> residual falls (reduction 0.4)          -> 15
SPOFs: ['asset-ad-dc01', 'asset-fw-edge']
```

**Pillar III — budget-constrained treatment optimiser.** All four strategies
(Mitigate / Transfer / Avoid / Accept) are supported; `optimizer.py` solves an
**exact 0/1 knapsack** to pick the highest-risk-reduction safeguard set within a
budget. With a $8000 cap it selects `SG-1 (MFA)` + `SG-2 (WAF)` for 14 points of
reduction at $0 remaining. **Accept** and policy exceptions never pass through the
optimiser alone — they route to human sign-off.

**Pillar IV — BIA, contingency & post-incident governance.** `bia.py` validates
the corrected relationship **RTO + WRT ≤ MTD**, with **RPO** as an *independent*
data-loss bound — both are shown, never left blank:

```
asset-0007      RTO+WRT=180  MTD=240  -> PASS   resumption=warm
asset-ad-dc01   RTO+WRT=135  MTD=120  -> FAIL   (recovery design exceeds MTD)
```

It recommends off-site resumption tiers (cold/warm/hot/mirrored) by RTO and audits
third-party SLAs for vague/unenforceable terms. `aar.py` produces automated
After-Action Reviews from Blue incident timelines (MTTD/MTTC/MTTR) and computes
breach-notification deadlines (GDPR 72h / PDPL 72h).

## 5. Governance & Human-in-the-Loop

The AI may **recommend** risk acceptance or a policy exception, but can never
authorise one. `governance.py` records recommendations as **pending**; only a
**CISO** or **Risk Owner** can sign off, and the ledger is auditable:

```
AI recommendation gov-0001 status=pending (cannot self-approve)
blocked: role 'Analyst' cannot authorise risk_acceptance (requires CISO/RiskOwner)
after CISO sign-off: status=approved approver=ciso@lab
```

## 6. Cross-Course Bridge (handout §4) & Interop Results

The bridge API (`api.py`) exposes the three interfaces; every inbound payload is
validated against the shared contract and a malformed one is rejected with **400**
(the enterprise record is never silently corrupted):

| Interface | Direction | Payload |
|---|---|---|
| `GET /api/v1/assets/profile` | GRC → Red/Blue | `AssetProfile` |
| `POST /api/v1/findings` | Red → GRC | `Finding` (incl. chains) |
| `POST /api/v1/incidents` | Blue → GRC | `Incident` (MTTD/MTTC/MTTR) |

`python cnc419-grc/tests/test_api.py` confirms: assets published (4 profiles),
finding ingested (risks updated), incident ingested (AAR + breach deadlines
returned), and a malformed finding rejected (400).

## 7. Guardrails & Ethics

Synthetic/anonymised enterprise data only; real proprietary records are never sent
to external AI services. All AI-generated mappings, risk assessments and reviews
are **traceable to evidence** and material decisions require human sign-off.

## 8. Deployment & User Guide

```bash
python cnc419-grc/cli.py            # full governance walkthrough (offline)
python cnc419-grc/cli.py --serve    # bridge API on http://127.0.0.1:4190
python cnc419-grc/tests/test_bia.py
python cnc419-grc/tests/test_mapping.py
python cnc419-grc/tests/test_api.py
```

`.env`: `GRC_API_PORT`, `ASSETS_FILE`, `LLM_API_KEY`, `VECTOR_DB_URL`. The
platform publishes `GET /api/v1/assets/profile` and ingests findings/incidents.

## 9. Division of Work

| Member | Primary area | Files |
|---|---|---|
| `<Name 1>` | RAG ingestion & retrieval | `retrieval.py`, `ingest.py` |
| `<Name 2>` | Mapping & conflict engine | `mapping.py`, `frameworks.py`, `test_mapping.py` |
| `<Name 3>` | ISRM risk & optimiser | `risk.py`, `optimizer.py` |
| `<Name 4>` | BIA, governance, AAR | `bia.py`, `governance.py`, `aar.py`, `test_bia.py` |
| `<Name 5>` | Bridge API & integration | `api.py`, `state.py`, `cli.py`, `test_api.py`, report |

## 10. AI-Use Disclosure & References

AI coding assistants helped scaffold and draft parts of the code and this report;
all generated content was reviewed, tested and is understood by the team.

**References (IEEE).**
[1] ISO/IEC, "ISO/IEC 27001:2022," 2022.
[2] ISO/IEC, "ISO/IEC 27005:2022 — Information security risk management," 2022.
[3] ISO/IEC, "ISO/IEC 42001:2023 — AI management systems," 2023.
[4] NIST, "SP 800-30 Rev.1 — Guide for Conducting Risk Assessments," 2012.
[5] NIST, "SP 800-53 Rev.5," 2020.
[6] European Union, "GDPR (EU) 2016/679," 2016.
[7] Arab Republic of Egypt, "Personal Data Protection Law No. 151 of 2020," 2020.
[8] PCI SSC, "PCI-DSS v4.0," 2022.
[9] G. Caralli et al., "OCTAVE Allegro," CMU/SEI, 2007.
