# Preliminary Proposal Report — Integrated Cybersecurity Capstone

> Submit one PDF per course (`TeamXX_CNC418_Proposal.pdf`, etc.). This single
> document covers all three tracks and the integration; for a per-course
> submission, keep the cover page, the shared sections, and that course's track
> section. Only the cover-page identity fields need completing.

---

## Cover Page

| | |
|---|---|
| **Project title** | The Integrated Red–Blue–GRC Enterprise Security Platform |
| **Team** | `<Team number / name>` |
| **Members (name — ID)** | `<Name — ID>`; `<Name — ID>`; `<Name — ID>`; `<Name — ID>`; `<Name — ID>` |
| **Course code(s)** | CNC 418 · CNC 411 · CNC 419 |
| **Instructor** | Dr. Muhammad Hataba |
| **Institution** | `<University / Faculty>` |
| **Submission date** | 2026-11-24 |

---

## 1. Project Description

**Problem space.** Modern security operations fail at the seams between offense,
defense and governance. Manual penetration testing does not scale and automated
scanners hallucinate; detection models fire without explanations analysts can
trust; and GRC is still spreadsheet-driven, disconnected from live telemetry.
Our project builds the three capabilities as *one* platform in which attack
evidence, defensive response and risk posture flow into each other.

**Motivation (integrated track).** We pursue all three mandatory tracks with a
single team and connect them through shared data contracts, so a verified Red
Team exploit measurably raises a governed risk, a Blue Team containment measurably
lowers it, and every record is traceable to the asset and exercise that produced
it.

**Specific aims.**
1. **CNC 418 (Red):** an agent that plans, executes and *programmatically
   verifies* multi-step attacks against lab targets, exporting JSON/SARIF.
2. **CNC 411 (Blue):** a vendor-agnostic detection + SOAR pipeline with
   explainable ML, a confusion-matrix evaluation, and guardrailed containment.
3. **CNC 419 (GRC):** a standard-neutral platform that ingests any regulation,
   maps controls across frameworks (flagging conflicts), runs a pluggable ISRM
   engine, optimises safeguards under budget, and validates resilience.
4. **Integration:** one `exercise_run_id` threading GRC → Red → Blue → GRC.

## 2. Model / Pipeline

**Shared bridge.** Three record types tie the systems together (full schemas in
`shared/schemas/`): `AssetProfile` (GRC→Red/Blue), `Finding` (Red→Blue/GRC),
`Incident` (Blue→GRC). Every request carries `X-Exercise-Run-ID`.

**CNC 418 — agent-orchestration & verification pipeline.**
```
GRC asset profiles → recon → heuristic planner (prioritised by criticality)
   → probe + proof-of-exploitation verifier → verified? → Finding (JSON/SARIF)
   verified==no → REJECTED (anti-hallucination); every request allowlist-gated + run-id tagged
```
Answers handout §4A (prioritised reasoning, cross-request state/memory, context
awareness), §4C (deterministic PoC verification, rate/noise control), §4D
(GRC ingest, telemetry tagging, SARIF export, chain representation).

**CNC 411 — telemetry-to-detection-to-containment pipeline.**
```
multi-vendor logs → unified schema → ML detector (+ XAI) → MITRE triage
   → correlate Red (run-id) → autonomy policy (high-confidence OR corroborated?)
   → SOAR containment (vendor-neutral, human-in-the-loop) → Incident (MTTD/MTTC/MTTR)
```
Answers §4A (unified schema, high-signal artefacts), §4B (behavioural ML, LLM/RAG
triage, FP control), §4C (vendor-neutral + OS-specific containment, HITL), §3 (XAI
+ confusion matrix + concept drift).

**CNC 419 — ingestion-to-risk-register pipeline.**
```
any regulation → TF-IDF RAG ingest → cross-framework mapping (+ conflicts, gaps)
   → pluggable ISRM (inherent/residual, SPOF) → budget knapsack optimiser
   → BIA (RTO+WRT≤MTD) → human sign-off → live updates from Red/Blue → AAR
```
Answers Pillars I–IV, §3 (mapping engine + conflict), and the cross-course bridge.

## 3. Development Environment

- **Language/runtime:** Python 3.10+ (developed on 3.12). Core logic is
  **stdlib-only** (urllib, http.server, dataclasses, ipaddress) so every demo is
  reproducible with zero installs; `jsonschema` is an optional strict-validation
  extra.
- **AI/ML:** a from-scratch logistic-regression detector (own implementation for
  full explainability); a dependency-free TF-IDF retriever as the RAG backbone.
  Pluggable hooks allow swapping in LLM backends (OpenAI/Anthropic) and dense
  vector stores (Chroma/FAISS) without changing interfaces.
- **Targets/lab:** OWASP Juice Shop (Dockerised, loopback-bound) for the graded
  Red demo; a bundled stdlib mock target for offline/CI runs. Synthetic,
  anonymised data only for Blue and GRC.
- **Tooling:** Git/GitHub, Docker/Docker-Compose (for the live wire-protocol),
  SARIF 2.1.0 for machine-readable findings.

## 4. Verification / Validation Scenarios

- **Red (anti-hallucination):** nothing is logged without a deterministic proof —
  boolean/time row-count & timing deltas for SQLi, cross object-access delta for
  IDOR, un-escaped HTML marker for XSS, canary leak for prompt injection. An
  XSS claim against a JSON endpoint is correctly **rejected**. A 7-test allowlist
  suite proves non-loopback targets (incl. the cloud-metadata IP) are blocked.
- **Blue (detection validation):** a labelled synthetic dataset drives a
  confusion matrix; three+ multi-stage scenarios (AD credential attack, Linux
  priv-esc, DNS exfil) are replayed; a concept-drift variant must fail safe.
- **GRC (mapping validation):** an *unseen* regulatory document is ingested, its
  requirements extracted and mapped, with conflicts and gaps flagged; BIA maths
  and human sign-off are unit-tested.
- **Integration:** `integration/demo_scenario.py` runs the full GRC→Red→Blue→GRC
  loop and asserts traceability by `exercise_run_id`.

## 5. Performance Analysis Plan

| Track | Metrics / experiments |
|---|---|
| **Red** | chain-success rate; verification rate (verified ÷ claimed); false-positive (rejected) count; requests-per-finding (noise). |
| **Blue** | confusion matrix → Precision, Recall, F1, Accuracy, FPR on held-out data; MTTD/MTTC/MTTR per scenario; drift detection rate. |
| **GRC** | mapping precision vs a hand-labelled key; conflict-detection recall; traceability completeness; optimiser optimality (vs brute force). |

*Current baseline from the built system:* Blue detector **accuracy 0.976,
precision 1.00, recall 0.95, F1 0.975, FPR 0.00**; Red **6 verified findings
incl. a 2-step chain, 1 correctly rejected**; GRC **66 cross-framework mappings,
3 conflicts, BIA FAIL correctly flagged**. Final numbers will be reported on the
held-out benchmark at submission.

## 6. Expected Outcomes

Mapped to each track's deliverables/rubric:
- **Red:** modular agent + allowlist guardrail, JSON/SARIF reports (incl. chains),
  8–10p report, 3–5min demo, reproducible repo.
- **Blue:** normalisation + explainable detector (confusion matrix) + vendor-neutral
  SOAR + incident KPIs, report/demo/repo.
- **GRC:** RAG mapping engine + ISRM + optimiser + BIA + HITL governance + bridge
  API, report/demo/repo.
- **Bonus:** one continuous Purple Team scenario with end-to-end traceability,
  documented API contracts, and failure-handling evidence.

## 7. References (IEEE)

[1] OWASP Foundation, "OWASP Top 10 – 2021," 2021.
[2] B. Kimminich, "OWASP Juice Shop," OWASP Project documentation, 2024.
[3] MITRE, "ATT&CK: Adversarial Tactics, Techniques, and Common Knowledge," 2024.
[4] MITRE, "ATLAS: Adversarial Threat Landscape for AI Systems," 2024.
[5] OASIS, "Static Analysis Results Interchange Format (SARIF) v2.1.0," 2020.
[6] ISO/IEC, "ISO/IEC 27001:2022 — Information security management systems," 2022.
[7] ISO/IEC, "ISO/IEC 27005:2022 — Information security risk management," 2022.
[8] NIST, "SP 800-30 Rev.1 — Guide for Conducting Risk Assessments," 2012.
[9] NIST, "SP 800-53 Rev.5 — Security and Privacy Controls," 2020.
[10] European Union, "General Data Protection Regulation (EU) 2016/679," 2016.
[11] Arab Republic of Egypt, "Personal Data Protection Law No. 151 of 2020," 2020.
[12] PCI SSC, "Payment Card Industry Data Security Standard v4.0," 2022.
[13] ISO/IEC, "ISO/IEC 42001:2023 — AI management systems," 2023.

## 8. AI-Use Disclosure

AI coding assistants were used to help scaffold and draft portions of the code
and this document. All generated code and analysis were reviewed, tested, and are
understood by the team; every team member can explain and defend any part of the
submission, consistent with the capstone's AI-accountability expectations.
