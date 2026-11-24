# CNC 411 — Fundamentals of Cybersecurity
## Vendor-Agnostic AI-Augmented Blue Team & Automated Defense Pipeline

**Technical Project Report**

| | |
|---|---|
| **Course** | CNC 411 — Fundamentals of Cybersecurity |
| **Project title** | Vendor-Agnostic Blue Team Defence Pipeline (part of the Integrated Red–Blue–GRC Platform) |
| **Team** | `<Team number / name>` |
| **Members (name — ID)** | `<Name — ID>`; `<Name — ID>`; `<Name — ID>`; `<Name — ID>`; `<Name — ID>` |
| **Instructor** | Dr. Muhammad Hataba |
| **Repository** | https://github.com/lumidren/uni (`cnc411-blueteam/`) |
| **Date** | 2026-11-24 |

---

## 1. Overview & System Architecture

Enterprise estates are heterogeneous — Windows/AD, Linux, and multi-vendor
perimeter gear (Fortinet, Cisco, open-source). Our Blue Team pipeline is
**vendor-agnostic**: it normalises telemetry from all of them into one schema,
detects attacks with an **explainable** ML model, correlates them to Red Team
activity, and contains them through **vendor-neutral** SOAR playbooks — with hard
guardrails so it never auto-disrupts a critical asset or acts on a low-confidence
guess.

As part of the integrated platform, it **ingests** GRC asset profiles (to weight
severity), **correlates** tagged Red traffic by `X-Exercise-Run-ID`, and
**publishes** incident KPIs (MTTD/MTTC/MTTR) back to GRC.

```
 raw logs (Windows / Linux / firewall)
        |  normalize.py  (one unified NormalizedEvent schema)
        v
   feature window  --->  Detector (logistic regression + XAI)  --->  score + evidence
                                                        |
                              correlate.py (Red X-Exercise-Run-ID)
                                                        |
                              triage.py (MITRE ATT&CK + explanation)
                                                        |
                       autonomy policy: high-confidence OR corroborated?
                               /                               \
                          yes: act                          no: HOLD (fail-safe)
                               |                                   |
                   soar.py (FortiGate / Cisco / AD / Linux, simulated)
                               |
                   metrics.py (MTTD/MTTC/MTTR)  --->  Incident  --->  GRC (CNC 419)
```

| Module | Responsibility |
|---|---|
| `blueteam/normalize.py` | Multi-vendor logs → one `NormalizedEvent` schema. |
| `blueteam/features.py` | Canonical behavioural feature set (shared training + live). |
| `blueteam/detect.py` | From-scratch logistic regression + confusion matrix + XAI. |
| `blueteam/triage.py` | MITRE ATT&CK mapping + evidence-backed explanation. |
| `blueteam/correlate.py` | Correlate detections to verified Red findings. |
| `blueteam/soar.py` | Vendor-neutral containment + human-in-the-loop. |
| `blueteam/metrics.py` | MTTD / MTTC / MTTR. |
| `blueteam/pipeline.py` | Orchestrator → contract-valid `Incident`. |
| `data/gen_dataset.py` | Deterministic labelled dataset across scenarios. |

## 2. Tools, Models & Frameworks

- **Runtime:** Python 3.10+; **stdlib-only** core (no installs). The detector is a
  **from-scratch logistic regression** (own `StandardScaler` + gradient descent in
  `detect.py`) chosen precisely so every weight — and therefore every
  explanation — is ours to defend. `scikit-learn` is an optional benchmarking
  extra only.
- **Triage:** a curated MITRE ATT&CK knowledge base drives deterministic triage;
  an LLM/RAG backend can be slotted behind `triage.narrate()` without replacing
  the structured, evidence-first explanation.
- **SOAR connectors:** simulated FortiGate, Cisco ASA, Windows AD and Linux EDR
  connectors behind one interface (no real device is ever touched).
- **Data:** synthetic, deterministic (seeded) labelled dataset across mixed OS /
  network scenarios.

## 3. Explainable AI & Measurable Detection Performance (handout §3)

**Confusion-matrix result (mandatory).** On a held-out test split of the labelled
dataset (`python cnc411-blueteam/tests/test_detection_metrics.py`):

```json
{ "confusion_matrix": {"tp": 98, "tn": 109, "fp": 0, "fn": 5},
  "accuracy": 0.9764, "precision": 1.0, "recall": 0.9515,
  "f1": 0.9751, "false_positive_rate": 0.0 }
```

Precision 1.00 / FPR 0.00 is the direct answer to the *self-DoS / false-positive*
concern: the model does not block legitimate users.

**Explainability, not just confidence.** Every detection carries an
evidence-backed explanation — the **top feature contributions** (`weight ×
standardised value`), not a bare score. Example (password-spray-like event):

```
is_attack=True score=0.9963
  auth_failures_5m      value=30.0  contribution=+3.86  (failed auth in last 5 min)
  distinct_targets_5m   value=20.0  contribution=+3.35  (distinct accounts targeted)
  sudo_cmd_anomaly      value= 0.0  contribution=-0.97
  lateral_conn_count    value= 1.0  contribution=-0.88
```

This XAI payload is attached to the `Incident.explanation` field and surfaced to
the human at the moment of any approval.

**Concept drift (stretch).** After training, a *modified* "low-and-slow" password
spray (few failures but still broad targeting) is injected. The detector scores it
**LOW confidence**; because it is low-confidence *and* uncorroborated, the pipeline
**fails safe and holds** the containment rather than silently misclassifying or
disruptively auto-blocking. The model's blind spot (low failure counts pull the
score down) is reported explicitly from the evaluation metrics.

## 4. Architectural Answers (handout §4)

**A. Vendor-agnostic telemetry & normalisation.** `normalize.py` parses Windows
Security events (e.g. 4625 failed logon, **4769 → Kerberoasting**), Linux
auth/syslog/sudo lines, and firewall records (incl. a DNS-tunnelling heuristic)
into a single `NormalizedEvent`. High-signal artefacts (auth failures, 4769 bursts,
auth-log patterns, DNS entropy/volume, sudo anomalies, lateral connections) become
the nine canonical features in `features.py`, so detection and SOAR are written
once and work across the whole estate.

**B. AI/ML detection & analyst augmentation.** Behavioural ML (the logistic model)
handles frequency/breadth/entropy signals; the MITRE knowledge base + correlation
handle deterministic attribution. `triage.py` reduces alert fatigue by mapping each
alert to an ATT&CK technique, tactic and remediation and emitting a unified,
explained incident summary. Thresholds and metrics (precision, recall, FPR) bound
false positives.

**C. Modular, multi-vendor containment (SOAR).** One decision —
`block_ip` / `isolate_host` / `disable_account` — is chosen from the technique and
then dispatched to the right connector by asset OS/vendor (`_pick_vendor`), so core
logic never rewrites per vendor. OS-specific containment differs (AD account
disable vs Linux host isolation). **Human-in-the-loop:** high-impact actions on
tier-1/tier-2 assets are **held** for approval, with the explanation surfaced; the
autonomy policy only lets the machine act alone when it is **high-confidence OR
corroborated by a verified Red PoC**.

**D. Adversarial testing & cross-course interop.** Scenarios are mapped to ATT&CK:
Password Spraying (T1110.003), Kerberoasting (T1558.003), Linux priv-esc
(T1548.003), DNS Tunnelling (T1071.004), plus Valid Accounts (T1078). The pipeline
(1) ingests GRC asset criticality to weight severity, (2) correlates tagged Red
traffic by `X-Exercise-Run-ID` and validates against verified Red PoCs, and (3)
exports `Incident` records (`incident_id`, `exercise_run_id`, `target_asset`,
`mitre_technique_id`, `mttd_sec`, `mttc_sec`, `mttr_sec`, `containment_action`,
`residual_status`) to GRC.

## 5. Results (telemetry artifacts)

`python cnc411-blueteam/cli.py` replays four multi-stage scenarios:

```
### scenario: ad_credential_attack
  - T1110.003  -> block_ip               MTTD=12.5s MTTC=6.0s MTTR=70.0s [contained]
  - T1558.003  -> pending_human_approval MTTD=22.0s MTTC=0.0s MTTR=0.0s [partially_contained] [HELD]
  - T1078      -> pending_human_approval                                 [partially_contained] [HELD]
### scenario: linux_privilege_escalation
  - T1110.003  -> block_ip               [contained]
  - T1548.003  -> pending_human_approval [partially_contained] [HELD]
### scenario: dns_tunnel_exfil
  - T1071.004  -> block_ip               [contained]
### scenario: concept_drift_low_and_slow_spray
  - T1110.003  -> pending_human_approval [LOW confidence -> FAIL-SAFE hold]

=== SOAR audit log (vendor-neutral) ===
  [SIMULATED fortigate] block_ip -> 10.10.5.66
  HELD for approval: T1558.003 -> disable_account via windows_ad (tier1_critical)
  [SIMULATED cisco_asa] block_ip -> 10.10.9.21
  FAIL-SAFE hold (low confidence, uncorroborated): block_ip -> 10.10.9.90
```

This demonstrates: vendor-neutral containment executing on FortiGate and Cisco; a
high-impact AD action **held** for a human; and a drift variant **failing safe**.
Incident records (with KPIs + explanation) are written to `out/incidents_<run>.json`.

## 6. Guardrails & Ethics

All attack simulations and containment run in an isolated lab; **containment is
simulated** through connectors and never bridged to a production network.
Containment has explicit safety boundaries: autonomy is restricted to
high-confidence or Red-corroborated alerts, high-impact actions require sign-off,
and the system avoids disrupting legitimate users (precision 1.0 / FPR 0.0).

## 7. Deployment & User Guide

```bash
python cnc411-blueteam/cli.py                      # offline demo
python cnc411-blueteam/cli.py --approver ciso@lab  # approve held actions
python cnc411-blueteam/data/gen_dataset.py         # regenerate the dataset
python cnc411-blueteam/tests/test_detection_metrics.py   # confusion matrix
```

`.env`: `GRC_API_URL`, `RED_FINDINGS`, `SCENARIOS`, `APPROVER`,
`GRC_INCIDENTS_URL`. Consumes `GET /api/v1/assets/profile`; publishes
`POST /api/v1/incidents`.

## 8. Division of Work

| Member | Primary area | Files |
|---|---|---|
| `<Name 1>` | Normalisation & features | `normalize.py`, `features.py` |
| `<Name 2>` | ML detector & metrics | `detect.py`, `data/gen_dataset.py`, `test_detection_metrics.py` |
| `<Name 3>` | Triage & correlation (XAI, MITRE) | `triage.py`, `correlate.py` |
| `<Name 4>` | SOAR & guardrails | `soar.py`, `metrics.py`, `grc_client.py` |
| `<Name 5>` | Pipeline & integration | `pipeline.py`, `cli.py`, scenarios, report |

## 9. AI-Use Disclosure & References

AI coding assistants helped scaffold and draft parts of the code and this report;
all generated content was reviewed, tested and is understood by the team.

**References (IEEE).**
[1] MITRE, "ATT&CK," 2024.
[2] NIST, "SP 800-61r2 — Computer Security Incident Handling Guide," 2012.
[3] Fortinet, "FortiOS REST API Reference," 2024.
[4] Cisco, "ASA/IOS CLI & API Reference," 2024.
[5] T. Fawcett, "An introduction to ROC analysis," *Pattern Recognition Letters*, 2006.
[6] D. W. Hosmer and S. Lemeshow, *Applied Logistic Regression*, Wiley, 2013.
[7] MITRE, "Common Weakness Enumeration (CWE)," 2024.
