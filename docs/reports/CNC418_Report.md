# CNC 418 — Software Security
## AI-Powered Autonomous Red-Teaming & Penetration-Testing Solution

**Technical Project Report**

| | |
|---|---|
| **Course** | CNC 418 — Software Security |
| **Project title** | AI-Powered Autonomous Red-Team Agent (part of the Integrated Red–Blue–GRC Platform) |
| **Team** | `<Team number / name>` |
| **Members (name — ID)** | `<Name — ID>`; `<Name — ID>`; `<Name — ID>`; `<Name — ID>`; `<Name — ID>` |
| **Instructor** | Dr. Muhammad Hataba |
| **Repository** | https://github.com/lumidren/uni (`cnc418-redteam/`) |
| **Date** | 2026-11-24 |

---

## 1. Overview & System Architecture

Manual penetration testing is deep but does not scale; signature scanners scale
but hallucinate findings and miss logic flaws. Our Red Team agent sits between
the two: it **plans** which attacks to run, **executes** them against isolated
lab targets, and — critically — **programmatically verifies** every exploit
before it is ever recorded. A finding it cannot prove is rejected, not logged.

The agent is one component of an integrated three-course platform. It **ingests**
asset criticality profiles from the CNC 419 GRC platform to decide what to attack
first, **tags** all its traffic with an `X-Exercise-Run-ID` header so the CNC 411
Blue Team can correlate it, and **exports** verified findings as standardized
JSON and SARIF 2.1.0 to both Blue and GRC.

```
          GRC asset profiles (criticality-sorted)
                     |
                     v
   recon  ->  HeuristicPlanner  ->  prioritised probe list
                     |                       |
                     |                       v
              AttackMemory <----- probe + Verifier (proof-of-exploitation)
                     |                       |
                     |             verified? --- no --> REJECTED (not logged)
                     |                       | yes
                     v                       v
             chain assembly  ------>  Finding (JSON + SARIF 2.1.0)
                                             |
                                   X-Exercise-Run-ID on every request
                                             |
                                 POST to Blue (CNC 411) & GRC (CNC 419)
```

**Module map.**

| Module | Responsibility |
|---|---|
| `redteam/allowlist.py` | Hard target allowlist — the central safety control. |
| `redteam/transport.py` | The single HTTP choke point: allowlist + run-id tag + rate control. |
| `redteam/grc_client.py` | Ingests GRC asset profiles; sorts targets by criticality. |
| `redteam/planner.py` | Decides which vectors to run, in what order; LLM hook. |
| `redteam/memory.py` | State across a chain: artefacts, tried-set, recon notes. |
| `redteam/verify.py` | Proof-of-exploitation verifiers (anti-hallucination). |
| `redteam/agent.py` | The run loop: recon → plan → verify → chain → report. |
| `redteam/report.py` | JSON + SARIF 2.1.0 export (chains → codeFlows). |
| `targets/mock_vuln_app.py` | Our own localhost practice target (offline/CI). |

## 2. Tools, Models & Frameworks

- **Language/runtime:** Python 3.10+ (developed on 3.12). The agent is
  **stdlib-only** by design (`urllib`, `http.server`, `ipaddress`, `dataclasses`,
  `secrets`), so it runs with zero installs and nothing hidden in a dependency.
- **AI / planning:** a deterministic `HeuristicPlanner` prioritises vectors from
  asset criticality + reconnaissance; a documented `LLMPlanner` interface
  (`NullLLMPlanner` by default) lets an LLM re-rank the plan without any code
  change. This keeps the demo 100% reproducible and API-key-free while leaving
  the LLM path open.
- **Verification:** inference- and observation-based verifiers (no third-party
  scanners wrapped).
- **Targets:** OWASP Juice Shop (Dockerised, loopback-bound) for the graded demo;
  a bundled stdlib mock target for offline/CI.
- **Reporting:** standardized JSON and **SARIF 2.1.0**.
- **Optional extras** (`requirements.txt`): `jsonschema` (strict validation),
  `playwright` (headless DOM verification), an LLM SDK for the planner hook.

## 3. Core Functional Scope

The agent covers the four offensive domains of the brief, each with a dedicated
verifier so coverage is *proven*, not claimed:

1. **Web & Session Security** — boolean- and time-blind SQL injection, reflected
   XSS (context-aware: only in an HTML sink).
2. **Business Logic & Access Control** — IDOR / broken object-level
   authorisation (BOLA).
3. **LLM & ML Attacks** — direct prompt injection / system-prompt extraction
   against an AI endpoint.
4. **Mobile Backend & API** — the same IDOR/BOLA and token-handling checks apply
   to JSON API surfaces (the mock exposes `/api/basket/{id}`).

## 4. Attack-Chain Design (handout §3)

A passing demonstration shows an *intelligently constructed chain*, not unrelated
scans. `agent.build_chain()` assembles a single `Finding` whose ordered `chain[]`
is **SQLi → IDOR**, and **each step is verified independently before it counts**:

| Step | Name | MITRE | CWE | Verified by | Enables |
|---|---|---|---|---|---|
| 1 | Boolean-blind SQLi confirms an injectable, enumerable store | T1190 | CWE-89 | row-count delta | enumerable object ids |
| 2 | IDOR reads another tenant's basket via an enumerable id | T1190 | CWE-639 | cross-object owner delta | cross-tenant data read |

In the report this is **not flattened** — the JSON keeps the ordered `chain[]`
and the SARIF renders it as a `codeFlow` with one `threadFlow` location per step.

**Adaptation under blocking (stretch).** `planner.detect_block()` recognises
403/429/WAF responses; `planner.adapt_on_block()` then switches tactic (back-off,
URL-encoding, keyword case-variation, chunked timing) instead of replaying a
failing payload.

## 5. Architectural Answers (handout §4)

**A. AI Orchestration & Planning.**
- *Autonomous reasoning / prioritisation.* The planner ranks a fixed
  `VECTOR_CATALOG` by a base priority **plus a criticality bonus** (tier-1 assets
  pull high-impact server-side bugs to the front) and gates each vector behind a
  **recon check** — a vector is only queued if its endpoint was actually observed.
  The agent never sprays every payload on every parameter.
- *State & memory.* `AttackMemory` holds extracted artefacts (so step 2 uses what
  step 1 produced), a `(vector, target)` **tried-set** so nothing is retried, and
  recon observations. This is what lets a chain actually chain.
- *Context awareness.* The XSS verifier claims a bug **only** when an HTML-special
  marker is reflected *un-escaped in an HTML content-type*; the same marker echoed
  inside a JSON body is correctly **rejected** — the sink context decides.

**B. Tooling & Execution.** The agent talks to targets through one `Transport`
built on stdlib `urllib` (raw HTTP). The design is deliberately pluggable: a
headless-browser backend (Playwright) can be slotted in for DOM-based payloads,
and the LLM endpoint is exercised as a stateful JSON conversation (`/chat`).

**C. Verification & Anti-Hallucination.** Nothing is logged without a
deterministic signal:

| Vector | Proof method | Signal observed |
|---|---|---|
| Boolean SQLi | `boolean_blind_inference` | `OR 1=1` → N rows vs `OR 1=2` → 0 rows, both ≠ baseline |
| Time SQLi | `time_blind_inference` | response delayed ≥ threshold under `SLEEP()` |
| IDOR | `object_access_delta` | two ids return two distinct owners, no auth |
| XSS | `reflected_marker` | `<marker>` returned un-escaped in HTML |
| Prompt injection | canary leak | model emits its protected `SYS-SECRET-…` key |

Unprovable claims become `exploit_status: rejected`. *Noise & rate control:*
`Transport` enforces a minimum inter-request interval and a hard per-run request
cap (`RequestBudgetExceeded`), so the agent cannot loop or self-DoS the target.

**D. Cross-Course Interoperability.** `grc_client.fetch_asset_profiles()` pulls
`AssetProfile`s (`criticality_tier`, `mtd_minutes`, `applicable_standards`) and
sorts targets. Every request carries `X-Exercise-Run-ID`. Findings export the full
contract (`finding_id`, `exercise_run_id`, `target_asset`, `cwe_id`,
`stride_category`, `mitre_technique_id`, `cvss_vector`, `exploit_status`,
`verified_poc`) as JSON **and** SARIF 2.1.0; chained findings carry the sequence.

## 6. Verification & Results (telemetry artifacts)

Running the agent against the bundled target (`python cnc418-redteam/cli.py
--start-mock`) produces, deterministically:

```
=== RUN SUMMARY ===
verified findings : 6
rejected / unproven: 1
  + CWE-89   T1190      verified single     (boolean-blind SQLi)
  + CWE-89   T1190      verified single     (time-blind SQLi)
  + CWE-639  T1190      verified single     (IDOR / BOLA)
  + CWE-79   T1059.007  verified single     (reflected XSS)
  + CWE-1427 T1190      verified single     (LLM prompt injection)
  + CWE-89   T1190      verified chain[2]   (SQLi -> IDOR)
transport: sent=20 blocked=0 errors=0
reports: out/findings_<run>.json / out/findings_<run>.sarif.json
```

The one **rejected** item is the anti-hallucination gate working live: an XSS
claim against the JSON endpoint cannot be proven and is refused.

**Tests (all pass, no pytest required):**

| Test | Proves |
|---|---|
| `tests/test_allowlist.py` | 7/7 — non-loopback targets (incl. `169.254.169.254` cloud-metadata) are blocked; a config cannot open a public range. |
| `tests/test_verify_against_mock.py` | all 5 verifiers fire on real HTTP; a benign request leaks nothing. |
| `tests/test_report_schema.py` | every finding validates against the shared `Finding` contract; the chain survives into a SARIF `codeFlow`. |

A sample verified-PoC record (JSON):

```json
{
  "finding_id": "find-a1b2c3", "exercise_run_id": "run-20261124-...",
  "target_asset": "asset-0007", "cwe_id": "CWE-89",
  "stride_category": "tampering", "mitre_technique_id": "T1190",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
  "exploit_status": "verified",
  "verified_poc": {"method": "boolean_blind_inference",
                   "evidence": "baseline=3, OR 1=1 => 5, OR 1=2 => 0"}
}
```

A visual summary of a full exercise is available in the SOC-console dashboard
(`integration/dashboard/dashboard.html`), which shows the verified findings, the
chain, and the downstream Blue/GRC records under one `exercise_run_id`.

## 7. Guardrails & Ethics

- **Hard-coded allowlist (`allowlist.py`).** Loopback-only by default; a
  globally-routable address is refused *unconditionally*, even if a config tries
  to add it. Both the hostname **and** every resolved IP are checked (closing the
  DNS-rebinding hole). This is the single most important control and is isolated
  in one auditable module behind one choke point (`transport.py`).
- **Mandatory sandboxing.** All activity targets `localhost` / approved private
  lab subnets; the graded target is OWASP Juice Shop, the offline target is our
  own planted-vulnerability mock. No external or university infrastructure is ever
  in scope.

## 8. Deployment & User Guide

```bash
# Offline (no Docker, no network, no API key):
python cnc418-redteam/cli.py --start-mock

# Against OWASP Juice Shop:
docker compose -f cnc418-redteam/targets/docker-compose.juiceshop.yml up -d
python cnc418-redteam/cli.py --target http://127.0.0.1:3000 \
    --grc-url http://127.0.0.1:4190 --blue-url http://127.0.0.1:4110 --publish
```

Key `.env` / flags: `TARGET_URL`, `ALLOWLIST_CONFIG`, `GRC_URL`, `BLUE_URL`,
`MAX_REQUESTS`, `MIN_REQUEST_INTERVAL_S`. The agent consumes
`GET /api/v1/assets/profile` and publishes to `POST /api/v1/findings`.

## 9. Division of Work

> Replace roles with member names. Every member must be able to defend **any**
> module in the oral defence, not only their own.

| Member | Primary area | Files |
|---|---|---|
| `<Name 1>` | Safety core | `allowlist.py`, `transport.py`, `test_allowlist.py` |
| `<Name 2>` | Verification | `verify.py`, `test_verify_against_mock.py` |
| `<Name 3>` | Planning & memory | `planner.py`, `memory.py`, `grc_client.py` |
| `<Name 4>` | Orchestration & reporting | `agent.py`, `report.py`, `cli.py` |
| `<Name 5>` | Target & integration | `targets/mock_vuln_app.py`, cross-course wiring, report |

## 10. AI-Use Disclosure & References

AI coding assistants helped scaffold and draft parts of the code and this report;
all generated content was reviewed, tested and is understood by the team.

**References (IEEE).**
[1] OWASP Foundation, "OWASP Top 10 – 2021," 2021.
[2] B. Kimminich, "OWASP Juice Shop," OWASP, 2024.
[3] MITRE, "ATT&CK," 2024.
[4] MITRE, "ATLAS (AML.T0051 LLM Prompt Injection)," 2024.
[5] OASIS, "SARIF v2.1.0," 2020.
[6] FIRST, "CVSS v3.1 Specification," 2019.
[7] MITRE, "Common Weakness Enumeration (CWE)," 2024.
