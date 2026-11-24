# CNC 418 — AI-Powered Autonomous Red-Team Agent

An agent that plans, executes, and **programmatically verifies** multi-step
attacks against intentionally-vulnerable lab targets — and refuses to log
anything it cannot prove. Built for the Software Security track of the integrated
capstone.

> Safety first: every outbound request passes through a hard-coded allowlist
> (`redteam/allowlist.py`). Loopback-only by default; globally-routable
> addresses are refused unconditionally. There is exactly one HTTP choke point
> and it is trivial to audit.

## Run it in one command (no Docker, no network, no API key)

```bash
python cnc418-redteam/cli.py --start-mock
```

This boots the bundled localhost target (`targets/mock_vuln_app.py`), runs the
agent, verifies exploits, assembles a chain, and writes reports to `./out/`:

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
```

Against the graded target (OWASP Juice Shop):

```bash
docker compose -f cnc418-redteam/targets/docker-compose.juiceshop.yml up -d
python cnc418-redteam/cli.py --target http://127.0.0.1:3000
```

## Architecture

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
                                   X-Exercise-Run-ID tag on every request
                                             |
                                 published to Blue (CNC 411) & GRC (CNC 419)
```

| Module | Role |
|---|---|
| `redteam/allowlist.py` | Hard target allowlist (the safety control). |
| `redteam/transport.py` | The one HTTP choke point: allowlist + run-id tagging + rate/noise control. |
| `redteam/grc_client.py` | Ingests GRC asset profiles to prioritise high-value targets. |
| `redteam/planner.py` | Decides *which* vectors to run and in *what* order; deterministic, with an LLM hook. |
| `redteam/memory.py` | State across a chain: artefacts, attempts (de-dup), recon notes. |
| `redteam/verify.py` | Proof-of-exploitation verifiers — the anti-hallucination gate. |
| `redteam/agent.py` | The run loop: recon -> plan -> verify -> chain -> report. |
| `redteam/report.py` | Standardized JSON + SARIF 2.1.0 (chains become codeFlows). |
| `targets/mock_vuln_app.py` | Our own localhost practice target (offline/CI). |

## How this answers the handout's architectural questions

- **Autonomous reasoning / prioritisation (§4A).** The planner ranks vectors by
  asset `criticality_tier` and only queues vectors whose endpoint recon actually
  found — not "every payload on every parameter."
- **State & memory across a chain (§4A).** `AttackMemory` carries artefacts and
  a tried-set so step 2 uses what step 1 produced and nothing is retried.
- **Context awareness (§4A).** The XSS verifier only claims a bug when the
  marker is reflected **un-escaped in an HTML content-type** — a marker echoed
  in a JSON body is rejected.
- **Verification / anti-hallucination (§4C).** Nothing is logged without a
  deterministic proof: boolean/time row-count & timing deltas for SQLi, cross
  object-access delta for IDOR, canary leak for prompt injection, un-escaped
  marker for XSS. Unprovable claims are recorded as `rejected`.
- **Noise & rate control (§4C).** `Transport` enforces a min interval and a hard
  per-run request cap, so the agent cannot loop or self-DoS the target.
- **Cross-course interop (§4D).** Consumes `AssetProfile`, tags traffic with
  `X-Exercise-Run-ID`, exports `Finding` records (incl. full chains) as JSON and
  SARIF 2.1.0, and can POST them to the Blue/GRC endpoints.
- **Adaptation under blocking (§3 stretch).** `planner.detect_block()` /
  `adapt_on_block()` recognise 403/429/WAF responses and switch tactic
  (back-off, encoding, timing) instead of repeating a failing payload.

## Tests

```bash
python cnc418-redteam/tests/test_allowlist.py            # guardrail: 7/7
python cnc418-redteam/tests/test_verify_against_mock.py  # verifiers fire end-to-end
python cnc418-redteam/tests/test_report_schema.py        # findings are contract-valid; chain -> SARIF
```

## Scope & ethics

All activity is confined to `localhost` / approved private lab subnets by
`allowlist.py`. The bundled target and OWASP Juice Shop are *intentionally*
vulnerable training apps. Do not point this at anything you do not own or have
written authorisation to test.
