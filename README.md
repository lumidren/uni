# The Integrated Red–Blue–GRC Enterprise Security Platform

> Think like attackers. Engineer like defenders. Decide like risk owners.

Three AI-driven security systems — an offensive **Red Team** agent, a defensive
**Blue Team** pipeline, and a **GRC** governance platform — built to stand alone
*and* to operate as one platform, wired together by a single `exercise_run_id`.
Integrated Cybersecurity Capstone (CNC 418 · CNC 411 · CNC 419).

**Everything runs offline with zero installs** — the core of every system is
Python-stdlib-only. No Docker, no network, no API keys required for the demos.

```bash
python integration/demo_scenario.py     # the whole platform, end to end
```

## The three systems

| Course | System | One-command demo | Headline result |
|---|---|---|---|
| **CNC 418** | [Red Team agent](cnc418-redteam/README.md) | `python cnc418-redteam/cli.py --start-mock` | 6 verified findings incl. a 2-step chain; 1 claim correctly **rejected** |
| **CNC 411** | [Blue Team pipeline](cnc411-blueteam/README.md) | `python cnc411-blueteam/cli.py` | **acc 0.976 · precision 1.00 · recall 0.95 · F1 0.975 · FPR 0.00** |
| **CNC 419** | [GRC platform](cnc419-grc/README.md) | `python cnc419-grc/cli.py` | 66 cross-framework mappings, 3 conflicts, live risk updates |
| **Bonus** | [Integration](integration/README.md) | `python integration/demo_scenario.py` | GRC→Red→Blue→GRC with full traceability |

## What makes it one platform

```
            ┌──────────────────────── exercise_run_id ────────────────────────┐
            │                                                                  │
   CNC 419 GRC ──AssetProfile──▶ CNC 418 RED ──Finding (verified)──▶ CNC 419 GRC
   (asset criticality,            (plan, exploit,     │  (JSON/SARIF)   (inherent
    risk register,                verify, chain)      │                 risk ▲)
    compliance)                                       ▼
            ▲                               CNC 411 BLUE ──Incident──▶ CNC 419 GRC
            │                               (detect, explain,  (MTTD/MTTC/MTTR)  (residual
            └──────── residual risk ▼ + AAR ◀── contain, guardrailed)            risk ▼)
```

Shared contracts live in [`shared/`](shared/README.md); every cross-course record
is validated at the boundary, and only **verified** findings move risk.

## Highlights worth defending

- **Anti-hallucination by construction (Red).** A finding is logged only with a
  deterministic proof (row-count/timing deltas, object-access delta, canary leak,
  un-escaped marker). Unprovable claims are rejected.
- **Safety as the core control (Red).** One HTTP choke point enforces a hard
  allowlist — loopback-only by default; globally-routable addresses refused
  unconditionally. Proven by a 7/7 test suite.
- **Explainability, not just scores (Blue).** A from-scratch logistic regression
  attaches evidence (top feature contributions) to every decision, and reports a
  real confusion matrix.
- **Fail safe (Blue).** Low-confidence / uncorroborated detections are held;
  high-impact actions on critical assets need human sign-off.
- **Genuine conflict detection (GRC).** Retention-vs-erasure and
  localization-vs-transfer conflicts are flagged to a human — never hidden in a
  confidence score.
- **Corrected BIA maths (GRC).** `RTO + WRT ≤ MTD`, with `RPO` as an independent
  data-loss bound — both validated, neither left blank.

## Repository layout

```
uni/
├── shared/            cross-course data contracts (schemas + stdlib models + validation)
├── cnc418-redteam/    AI red-team agent (allowlist, verifiers, chains, JSON/SARIF)
├── cnc411-blueteam/   SIEM/SOAR pipeline (normalise, ML+XAI, correlate, contain, KPIs)
├── cnc419-grc/        GRC platform (RAG ingest, mapping, ISRM, optimiser, BIA, API)
├── integration/       end-to-end Purple Team scenario + compose + bonus evidence
└── docs/paperwork/    submission templates (Step 1/2/3)
```

## Run the tests

```bash
python cnc418-redteam/tests/test_allowlist.py
python cnc418-redteam/tests/test_verify_against_mock.py
python cnc418-redteam/tests/test_report_schema.py
python cnc411-blueteam/tests/test_detection_metrics.py
python cnc419-grc/tests/test_bia.py
python cnc419-grc/tests/test_mapping.py
python cnc419-grc/tests/test_api.py
python shared/contracts/examples/run_examples.py
```

## Scope & ethics

Academic capstone, **lab-only**. All offensive activity is confined to localhost /
approved private lab subnets by a hard-coded allowlist; targets are intentionally
vulnerable training apps (OWASP Juice Shop, a bundled mock). Blue containment is
simulated; GRC uses synthetic data. Do not point any of this at systems you do not
own or have written authorisation to test.

## Submission paperwork

Templates for the three due documents (individual background, team contract,
proposal) are in [`docs/paperwork/`](docs/paperwork/README.md) — only identity
fields need completing.
