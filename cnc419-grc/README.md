# CNC 419 — Standard-Neutral, AI-Powered GRC & Resilience Platform

The governance nerve centre of the ecosystem: it ingests *any* regulatory
document, maps controls across frameworks (and flags genuine conflicts), runs a
pluggable ISRM risk engine that updates live from Red/Blue activity, optimises
safeguards under a budget, validates recovery architectures, and enforces human
sign-off on risk acceptance.

## Run it (offline, no installs)

```bash
python cnc419-grc/cli.py          # full governance walkthrough
python cnc419-grc/cli.py --serve  # bridge API on http://127.0.0.1:4190
```

The walkthrough prints every pillar; highlights:

```
1. mapping: requirements=20 mappings=66 conflicts=3 coverage_gaps=1
   CONFLICT GDPR-Art20 (transfer) vs PDPL-Art14 (localize) in 'data_movement'
2. ingest unseen doc (LDPD): extracted=6, conflicts=3 (retention-vs-erasure, localize-vs-transfer)
4. Red finding raises R-001 inherent 15 -> 20; Blue containment lowers residual 20 -> 12
5. knapsack picks SG-1 + SG-2 within an 8000 budget
6. BIA: asset-ad-dc01 RTO+WRT=135 > MTD=120 -> FAIL
7. AI recommends risk acceptance (pending); Analyst blocked; CISO signs off -> approved
```

## Architecture (four pillars + the bridge)

```
   any regulation PDF/MD ---> ingest.py (TF-IDF RAG) ---> requirements
                                             |
         frameworks.py (ISO/PCI/NIST/GDPR/PDPL) + controls
                                             |
                               mapping.py (equivalent/overlap/partial/gap + CONFLICT)
                                             |
   risk.py (ISRM: ISO27005/NIST/OCTAVE) <----+----> optimizer.py (budget knapsack)
         ^            ^                                     bia.py (RTO+WRT<=MTD)
         |            |                                     governance.py (CISO sign-off)
   Red findings   Blue incidents                           aar.py (AAR + breach clock)
         \            /
          api.py  (GET /assets/profile, POST /findings, POST /incidents)
```

| Module | Pillar |
|---|---|
| `grc/retrieval.py` | Dependency-free TF-IDF retriever (RAG backbone). |
| `grc/ingest.py` | Standard-neutral ingestion of unseen documents. |
| `grc/frameworks.py` | Preloaded standards + organisational controls. |
| `grc/mapping.py` | Cross-framework mapping + conflict + gap engine. |
| `grc/risk.py` | Pluggable ISRM, inherent/residual, SPOFs, live updates. |
| `grc/optimizer.py` | Budget-constrained 0/1-knapsack safeguard optimiser. |
| `grc/bia.py` | BIA validation (RTO + WRT ≤ MTD; RPO independent), resumption, SLA audit. |
| `grc/governance.py` | Human-in-the-loop sign-off ledger. |
| `grc/aar.py` | Automated After-Action Review + breach-notification timelines. |
| `grc/api.py` | The Red–Blue–GRC bridge API. |

## How this answers the handout

- **Standard-neutral ingestion (Pillar I).** Upload any document; `ingest.py`
  extracts requirements and maps them immediately — the TF-IDF retriever is a
  drop-in for a dense vector DB.
- **Cross-framework mapping engine (§3).** Equivalent / overlapping / partial /
  gap relationships with *structural* evidence (shared tags + terms), many-to-many
  controls, and genuine CONFLICT detection (retention-vs-erasure, localize-vs-
  transfer) flagged to a human — never hidden in a score.
- **Pluggable ISRM (Pillar II).** ISO 27005 / NIST 800-30 / OCTAVE-Allegro scoring,
  STRIDE, SPOF detection, and dynamic inherent/residual updates from Red & Blue.
- **Budget optimiser (Pillar III).** Exact knapsack over safeguards; the four
  treatment strategies; Accept/exception routed to human sign-off.
- **BIA (Pillar IV).** Validates **RTO + WRT ≤ MTD** with **RPO** as an
  independent data-loss bound; recommends resumption tiers; audits SLAs.
- **Governance & post-incident.** CISO/Risk-Owner sign-off is mandatory for
  acceptance; AARs and GDPR/PDPL 72-hour breach clocks are automated.
- **Cross-course interop.** Publishes `AssetProfile`s and ingests `Finding`s
  (incl. chains) and `Incident`s to update the risk register in real time.

## Tests

```bash
python cnc419-grc/tests/test_bia.py       # RTO+WRT<=MTD, RPO independence
python cnc419-grc/tests/test_mapping.py   # equivalence, conflict, gap, ingestion
python cnc419-grc/tests/test_api.py       # bridge API + contract rejection
```

## Guardrails

Synthetic/anonymised data only; never send real records to external AI services.
AI output is traceable to evidence, and material decisions require human sign-off.
