# SOC Console Dashboard

A single, self-contained dark SOC-console dashboard that visualises one
correlated Purple Team exercise across all three systems — assets, verified Red
findings, Blue incidents + containment, the live GRC risk register, the detector
confusion matrix, cross-framework conflicts, and end-to-end traceability.

## Regenerate

```bash
python integration/dashboard/build_dashboard.py
```

This runs the three systems in-process, embeds the resulting data into
[`dashboard.html`](dashboard.html), and writes it out. Then just open
`dashboard.html` in any browser — no server, no build step, no network.

- `build_dashboard.py` — runs Red→Blue→GRC, collects the exercise data + the
  confusion matrix + the conflict set, and injects it into the template.
- `template.html` — the dark SOC-console UI (edit the `<style>` block to restyle).
- `dashboard.html` — the generated, self-contained output (committed as a snapshot).

The data is a live snapshot: `exercise_run_id`, finding/incident ids and the
timestamp change each run; the metrics are deterministic.
