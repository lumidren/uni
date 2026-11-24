# `shared/` — the Red–Blue–GRC data contracts

This is the spine of the whole platform. The three course projects stay
independently gradable, but they only become *one* system because they agree on
three record types and one correlation id. Everything here is **stdlib-only** so
any subsystem can import it without installing anything.

## The one id that ties it all together

`exercise_run_id` (e.g. `run-20261124-9f8e7d`) labels a single Purple Team
exercise. It travels:

- in every cross-course JSON payload, and
- on the wire as the HTTP header **`X-Exercise-Run-ID`**, so the Blue Team can
  correlate Red Team traffic without parsing bodies.

## The three records

| Record | Direction | Endpoint | Schema |
|---|---|---|---|
| **AssetProfile** | GRC → Red & Blue | `GET /api/v1/assets/profile` | [`schemas/asset_profile.schema.json`](schemas/asset_profile.schema.json) |
| **Finding** | Red → Blue & GRC | `POST /api/v1/findings` | [`schemas/finding.schema.json`](schemas/finding.schema.json) |
| **Incident** | Blue → GRC | `POST /api/v1/incidents` | [`schemas/incident.schema.json`](schemas/incident.schema.json) |

Field lists follow the capstone handout exactly (`criticality_tier`,
`mtd_minutes`, `cwe_id`, `stride_category`, `mitre_technique_id`, `cvss_vector`,
`mttd_sec`/`mttc_sec`/`mttr_sec`, `containment_action`, `residual_status`, …).

### Design choices worth defending

- **Verified-only downstream.** A `Finding` carries `exploit_status`. Only
  `verified` findings (with a reproducible `verified_poc`) are allowed to raise
  risk or trigger containment. A `rejected` finding is an LLM hallucination the
  Red Team caught — it is recorded, not acted on.
- **Chains are first-class.** A multi-step attack is one `Finding` with an
  ordered `chain[]`; each step verifies independently before it counts.
- **Explanation, not just confidence.** An `Incident` must carry an
  `explanation{}` (evidence + rationale). A bare confidence score is explicitly
  not accepted as a substitute.
- **Fail loud at the boundary.** `validate()` rejects malformed / out-of-order
  / duplicate-shaped payloads so a bad event never silently corrupts the
  enterprise record.

## Use it

```python
from shared.contracts import validate, new_exercise_run_id, EXERCISE_RUN_HEADER

run_id = new_exercise_run_id()
asset  = validate("asset",    asset_payload)     # -> AssetProfile
finding = validate("finding", finding_payload)   # -> Finding   (raises ContractError if bad)
incident = validate("incident", incident_payload)
```

Smoke-test the contracts and the bundled examples:

```bash
python shared/contracts/examples/run_examples.py
```

`validate()` uses the real `jsonschema` library when it is installed, and falls
back to a dependency-free checker otherwise.
