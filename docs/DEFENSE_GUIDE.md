# Defense Guide — How to Explain the Project to the TA

Read this before the oral defense. The rule is that **any** member can be asked
about **any** part, so everyone should be able to give the 20-second pitch, run a
demo, and answer the common questions below. Pick a system to own, but know all
three at the level of this guide.

---

## 1. The 20-second pitch (memorise this)

> "We built three AI security systems — a **Red Team** that attacks, a **Blue
> Team** that defends, and a **GRC** platform that governs risk. Each works on its
> own, but they also plug into one platform: GRC publishes which assets matter,
> Red attacks and **proves** its exploits, Blue **detects and contains** them, and
> GRC **updates the risk** — all tied together by one `exercise_run_id` so you can
> trace any risk back to the exact attack that caused it. Everything is
> Python-standard-library only, so it runs offline and we can explain every line."

## 2. One breath per system

- **Red (CNC 418):** an agent that plans attacks, runs them against a **localhost**
  lab target, and only logs a vulnerability when it can **prove** it worked.
- **Blue (CNC 411):** collects logs from Windows/Linux/firewalls, detects attacks
  with a machine-learning model that **explains** itself, and contains them —
  asking a human first for the dangerous actions.
- **GRC (CNC 419):** reads any regulation, maps rules across frameworks, flags
  **conflicts**, keeps a live risk register, and makes a human sign off on
  accepting risk.

## 3. Live-demo runbook

Open a terminal in the `uni/` folder. Everything below runs with plain `python`,
offline. Say the italic line *while* it runs.

**Demo A — the whole platform (best first demo):**
```bash
python integration/demo_scenario.py
```
*"Watch the run id at the top — it's on every record. GRC publishes the assets,
Red verifies 6 findings including a 2-step chain, GRC's risk goes up, Blue detects
and contains, the AD action is held for a human, and GRC's residual risk comes back
down. At the bottom: one asset traced through finding → incident → risk."*

**Demo B — Red Team:**
```bash
python cnc418-redteam/cli.py --start-mock
```
*"6 verified findings, and 1 **rejected** — that's the anti-hallucination gate: it
tried to claim an XSS it couldn't prove, so it refused to log it."*
Then: `python cnc418-redteam/tests/test_allowlist.py` → *"7/7 — it blocks anything
that isn't localhost, including the cloud-metadata IP."*

**Demo C — Blue Team:**
```bash
python cnc411-blueteam/tests/test_detection_metrics.py   # confusion matrix
python cnc411-blueteam/cli.py                             # scenarios + SOAR
```
*"Accuracy 0.976, precision 1.0, F1 0.975. In the scenarios, FortiGate and Cisco
blocks fire automatically, but disabling an AD account on a critical server is
**held for approval**, and the low-and-slow attack it isn't sure about **fails
safe**."*

**Demo D — GRC:**
```bash
python cnc419-grc/cli.py
```
*"It maps 66 controls across frameworks, flags 3 real conflicts — like GDPR 'you
must be able to transfer data' versus PDPL 'you can't send it abroad' — ingests a
regulation it's never seen, checks RTO+WRT ≤ MTD (the DC fails), and makes the CISO
sign off before any risk is accepted."*

**Demo E — the dashboard (the visual):**
```bash
python integration/dashboard/build_dashboard.py
# then open integration/dashboard/dashboard.html
```

## 4. The design decisions to defend (the "why")

These are the points that earn marks — lead with them.

| Decision | Why we did it |
|---|---|
| **Hard allowlist, loopback-only** (Red) | It's the safety rule; one choke point, refuses public IPs even if misconfigured, checks resolved IPs (stops DNS tricks). |
| **Proof-of-exploitation before logging** (Red) | LLMs hallucinate; we only log a finding with a deterministic signal (row-count/timing/object-access delta, canary leak, unescaped marker). |
| **We wrote the ML model ourselves** (Blue) | So every weight is ours to explain — the explanation is real feature contributions, not a black-box score. |
| **Autonomy policy: high-confidence OR corroborated** (Blue) | The machine only acts alone when it's sure or a verified Red PoC backs it; everything else waits for a human. |
| **Conflicts flagged, never auto-resolved** (GRC) | Two laws can genuinely contradict; the system surfaces it to a human instead of silently picking one. |
| **AI recommends, human authorises** (GRC) | Accepting risk is a governance act; only a CISO/Risk Owner can sign off. |
| **Standard library only** | Reproducible, auditable, and nothing hidden is doing the work for us. |

## 5. Q&A bank (likely TA questions + ready answers)

**General / integration**
- *"Isn't this just three dashboards behind one login?"* — No. Run
  `demo_scenario.py`: the same `exercise_run_id` is on the Red finding, the Blue
  incident, and the GRC risk update, and a verified finding **causes** the risk to
  rise, a containment **causes** it to fall. Information flows and changes state.
- *"Why no libraries?"* — So we understand and can defend everything, and so it
  reproduces anywhere with zero install. The intelligence is our code, not a
  wrapped tool.
- *"What's the shared contract?"* — Three JSON record types (`AssetProfile`,
  `Finding`, `Incident`) in `shared/`, validated at every boundary; a malformed
  event is rejected, not silently stored.

**Red Team**
- *"How do you know a finding is real?"* — `verify.py`. Each vector has a proof:
  boolean SQLi = `OR 1=1` returns more rows than `OR 1=2`; IDOR = two ids return two
  different owners with no auth; XSS = our marker comes back un-escaped **in HTML**;
  prompt injection = the model leaks a secret canary. No proof → `rejected`.
- *"What stops it hitting real sites?"* — The allowlist refuses anything that isn't
  loopback/approved-lab, and refuses globally-routable IPs unconditionally. Demo:
  `test_allowlist.py`.
- *"What makes it a *chain*?"* — Step 2 (IDOR) uses the enumerable ids step 1 (SQLi)
  revealed; each step is verified before it counts; it's one finding with an
  ordered `chain[]`, rendered as a SARIF codeFlow.
- *"How does it prioritise?"* — It reads GRC asset criticality and runs
  high-impact vectors on tier-1 assets first, and only tests a vector whose
  endpoint recon actually found — not every payload everywhere.

**Blue Team**
- *"Explain the confusion matrix."* — On held-out data: TP=98 (attacks caught),
  TN=109 (benign correct), FP=0 (no false alarms), FN=5 (missed). Precision = no
  false positives; recall = caught 95%.
- *"What is the explanation / XAI?"* — For each alert we list the top features and
  their contribution (weight × value) plus the evidence — e.g. "30 auth failures
  across 20 accounts." A confidence number alone is not accepted.
- *"What about an attack it's never seen?"* — The concept-drift scenario: a slow
  spray scores **low**; because it's low-confidence and uncorroborated it **holds**
  (fails safe) instead of mis-acting. We also report *why* (low failure counts).
- *"Vendor-agnostic how?"* — `normalize.py` turns Windows events, Linux auth logs
  and firewall records into one schema; one containment decision dispatches to
  FortiGate/Cisco/AD/Linux connectors.
- *"MTTD/MTTC/MTTR?"* — Mean time to **detect**, **contain**, **recover**; computed
  in `metrics.py` and sent to GRC.

**GRC**
- *"What's 'standard-neutral'?"* — Upload any regulation PDF/text; `ingest.py`
  extracts its requirements and maps them against the loaded frameworks. Not
  hardcoded to one law.
- *"How do you map rules without just matching keywords?"* — We use **shared
  control tags + obligation types** as structural evidence; TF-IDF only proposes
  candidates. We also show the shared terms as the rationale.
- *"Give a real conflict."* — GDPR Art.20 (transfer data out) vs PDPL Art.14
  (keep it in the country) — contradictory obligations in the same domain, flagged
  for a human. Also retention (PCI) vs erasure (GDPR/PDPL).
- *"Explain RTO + WRT ≤ MTD."* — Recovery Time + Work Recovery must fit inside Max
  Tolerable Downtime; **RPO** is a separate bound on data loss. The DC fails
  (135 > 120) — the engine catches it.
- *"Can the AI accept risk by itself?"* — No. It recommends; only a CISO/Risk Owner
  authorises. An Analyst is blocked. See the governance ledger in the demo.

**AI accountability (expect this one)**
- *"Did you use AI to build this?"* — Yes, and it's disclosed in the reports. We
  reviewed, tested and understand all of it — ask me to walk through any module.
  Then **do it**: open a file and explain it (the allowlist, a verifier, the
  logistic-regression `fit()`, or the conflict detector are all good choices).

## 6. If a demo breaks

- Everything is deterministic and offline, so re-run the command — ids/timestamps
  change but results don't.
- If a port is busy (3000/4190), another demo may still be running; close it.
- Worst case, show the committed outputs (`*/out/`, `integration/out/`,
  `docs/reports/`) and the dashboard HTML.

## 7. Vocabulary cheat-sheet (one line each)

- **`exercise_run_id` / `X-Exercise-Run-ID`** — the id that ties one exercise's
  records together across all three systems.
- **SARIF 2.1.0** — a standard JSON format for security findings.
- **STRIDE** — threat categories (spoofing, tampering, …).
- **Confusion matrix** — TP/TN/FP/FN; gives precision, recall, F1.
- **XAI** — explainable AI: showing *why*, with evidence, not just a score.
- **MTTD / MTTC / MTTR** — time to detect / contain / recover.
- **RTO + WRT ≤ MTD** — recovery must fit inside tolerable downtime; **RPO** bounds
  data loss separately.
- **ISRM** — information security risk management (ISO 27005 / NIST 800-30).
- **Inherent vs residual risk** — before vs after controls.
- **Human-in-the-loop** — a person must approve the high-impact / risk-acceptance
  actions.

## 8. Suggested per-member split

Each member leads one area but can answer the Q&A for all. Example for a team of 5:

1. Integration + the pitch + `exercise_run_id` / shared contracts
2. Red Team (allowlist, verifiers, chain)
3. Blue Team (normalisation, ML + XAI, SOAR)
4. GRC (mapping + conflicts, risk engine, BIA)
5. Governance, guardrails, AI accountability + the dashboard
