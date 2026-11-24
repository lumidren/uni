# Integration — The Red–Blue–GRC Enterprise Platform (Bonus Challenge)

The three course systems operate as **one coordinated capability**, not three
dashboards behind one login. A single `exercise_run_id` threads every record so
an operator can trace a risk back to the finding, telemetry, action and evidence
that produced it.

## Run the whole thing in one command (offline)

```bash
python integration/demo_scenario.py
```

Output (abridged):

```
PURPLE TEAM EXERCISE  exercise_run_id = run-20261124-xxxxxx
1. GRC publishes asset criticality profiles
2. RED verifies 6 findings on asset-0007 (incl. a 2-step chain)
3. GRC ingests findings -> R-001 inherent 15 -> 25
4. BLUE: asset-0007 T1190 -> block_ip [contained];  asset-ad-dc01 T1558.003 -> HELD for approval
5. GRC ingests incidents -> R-001 residual 25 -> 15 (web attack contained)
6. Traceability: asset-0007 -> RED find-xxxx (chain=2) -> BLUE inc-xxxx (contained) -> GRC R-001
```

## End-to-end data flow

```
            exercise_run_id ──────────────────────────────────────────────┐
                                                                           │
  GRC ──GET /assets/profile──▶ RED ──POST /findings──▶ GRC                 │
   │   (asset criticality)      │   (verified only)     │                  │
   │                            │                       ▼                  │
   │                            │                 inherent risk ▲          │
   ▼                            ▼                                          │
  RED/BLUE read the same     X-Exercise-Run-ID tag on every request        │
  asset identities              │                                          │
                                ▼                                          │
                      BLUE correlates traffic, detects + explains,         │
                      contains (guardrailed) ──POST /incidents──▶ GRC      │
                                                        │                  │
                                                        ▼                  │
                                               residual risk ▼ + AAR ◀─────┘
```

## Shared contracts (the interface)

All three interfaces are defined once in [`../shared/`](../shared/README.md):

| Interface | Direction | Payload |
|---|---|---|
| `GET /api/v1/assets/profile` | GRC → Red/Blue | `AssetProfile` |
| `POST /api/v1/findings` | Red → GRC/Blue | `Finding` (incl. chains) |
| `POST /api/v1/incidents` | Blue → GRC | `Incident` (MTTD/MTTC/MTTR) |

- **One correlation id.** `exercise_run_id` is in every payload and on the wire
  as `X-Exercise-Run-ID`.
- **Validated at every boundary.** A malformed/duplicate-shaped event is rejected
  (HTTP 400) — the enterprise record is never silently corrupted
  (`cnc419-grc/tests/test_api.py`).
- **Verified-only downstream.** Only `exploit_status=verified` findings raise risk
  or validate a detection; a hallucinated finding corroborates nothing.

## Interoperability & failure handling

- **Uncertainty is visible.** AI conclusions (`exploit_status=suspected`, a
  low-confidence detection) are distinguishable from verified observations and
  human-approved actions.
- **Fail safe.** Low-confidence / uncorroborated detections are HELD, not
  auto-contained; high-impact actions on critical assets need human sign-off.
- **Robust exchange.** Contract validation rejects malformed events; unknown
  techniques degrade to `containment_action=none` rather than crashing.

## Live wire-protocol (optional, needs Docker)

```bash
docker compose -f integration/docker-compose.yml up -d   # GRC API + Juice Shop
python cnc418-redteam/cli.py --target http://127.0.0.1:3000 --grc-url http://127.0.0.1:4190 --publish
python cnc411-blueteam/cli.py
```

## Evidence produced

`integration/out/exercise_<run_id>.json` — the correlated record: assets, Red
findings, Blue incidents, the updated risk register, and the AARs, all under one
`exercise_run_id`.
