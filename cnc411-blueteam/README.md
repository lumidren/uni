# CNC 411 — Vendor-Agnostic AI-Augmented Blue Team Pipeline

A defence pipeline that normalises heterogeneous telemetry, detects attacks with
an explainable ML model, correlates them to Red Team activity, and contains them
through vendor-neutral SOAR playbooks — with hard guardrails so it never
auto-disrupts a critical asset or acts on a low-confidence guess.

## Run it in one command (no installs, no network)

```bash
python cnc411-blueteam/cli.py
```

Trains the detector, replays four multi-stage scenarios, and writes contract-valid
incident records (MTTD/MTTC/MTTR + explanation) to `./out/`:

```
### scenario: ad_credential_attack
  - T1110.003  -> block_ip               MTTD=12.5s MTTC=6.0s MTTR=70.0s [contained]
  - T1558.003  -> pending_human_approval MTTD=22.0s MTTC=0.0s MTTR=0.0s [partially_contained] [HELD]
  - T1078      -> pending_human_approval ...                                              [HELD]
### scenario: concept_drift_low_and_slow_spray
  - T1110.003  -> pending_human_approval [LOW confidence -> FAIL-SAFE hold]
```

## Detection performance (mandatory confusion-matrix result)

```bash
python cnc411-blueteam/tests/test_detection_metrics.py
```

On the held-out synthetic test set: **accuracy 0.976, precision 1.00,
recall 0.95, F1 0.975, FPR 0.00**. The classifier is a from-scratch logistic
regression (`blueteam/detect.py`) so every weight — and therefore every
explanation — is ours to defend.

## Architecture

```
 raw logs (Windows / Linux / firewall)
        |  normalize.py  (one unified event schema)
        v
   feature window  --->  Detector (LR + XAI)  --->  score + top evidence
                                                        |
                              correlate.py (Red X-Exercise-Run-ID)
                                                        |
                              triage.py (MITRE ATT&CK + explanation)
                                                        |
                       autonomy policy: high-confidence OR corroborated?
                               /                               \
                          yes: act                          no: HOLD (fail-safe)
                               |                                   |
                   soar.py (FortiGate/Cisco/AD/Linux, simulated)   |
                               |                                   |
                   metrics.py (MTTD/MTTC/MTTR)  --->  Incident  ---+--> GRC (CNC 419)
```

| Module | Role |
|---|---|
| `blueteam/normalize.py` | Multi-vendor logs -> one `NormalizedEvent` schema. |
| `blueteam/features.py` | Canonical behavioural feature set (shared by training + live). |
| `blueteam/detect.py` | From-scratch logistic regression + confusion matrix + XAI. |
| `blueteam/triage.py` | MITRE ATT&CK mapping + evidence-backed explanation. |
| `blueteam/correlate.py` | Correlate detections to verified Red findings. |
| `blueteam/soar.py` | Vendor-neutral containment + human-in-the-loop. |
| `blueteam/metrics.py` | MTTD / MTTC / MTTR. |
| `blueteam/pipeline.py` | Orchestrator -> contract-valid `Incident`. |
| `data/gen_dataset.py` | Deterministic labelled dataset across scenarios. |

## How this answers the handout

- **Vendor-agnostic normalisation (§4A).** `normalize.py` folds Windows Event
  IDs, Linux auth/syslog and firewall records into one schema; detection/SOAR are
  written once.
- **Behavioural ML + XAI (§3, §4B).** The detector reports a confusion matrix and
  attaches an evidence-backed explanation (top feature contributions) to every
  decision — never a bare confidence score.
- **Vendor-neutral SOAR (§4C).** One decision ("block_ip"/"isolate_host"/
  "disable_account") dispatches to FortiGate, Cisco, AD or Linux connectors.
- **Human-in-the-loop (§4C).** High-impact actions on tier1/tier2 assets are
  HELD, with the explanation surfaced for the approver.
- **False-positive / self-DoS control (§3).** Precision 1.0 / FPR 0.0 on test;
  autonomy only on high-confidence or Red-corroborated alerts.
- **Concept drift (§3 stretch).** A low-and-slow spray the model never trained on
  is flagged LOW confidence and **fails safe** (held), not silently misclassified.
- **Cross-course interop (§4D).** Ingests GRC asset profiles, correlates Red
  traffic by `X-Exercise-Run-ID`, exports `Incident` records (MTTD/MTTC/MTTR,
  containment_action, residual_status) to GRC.

## Guardrails

All containment is **simulated** via connectors — nothing touches a real device.
Autonomy is restricted to high-confidence or externally-corroborated alerts;
everything else waits for a human.
