"""Synthetic, labelled, reproducible dataset across mixed OS / network scenarios.

Real attack telemetry is hard to share and messy to label, so we generate a
*balanced, deterministic* dataset whose feature distributions encode the
behavioural signatures of the handout's scenarios. The seed makes every run
identical, which is what lets the confusion matrix be a stable, defensible
experimental result instead of a lucky screenshot.

    python cnc411-blueteam/data/gen_dataset.py   # writes data/dataset.json

Each row: {<feature>: float, ..., "label": 0|1, "scenario": str}.
"""
from __future__ import annotations

import json
import pathlib
import random
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from blueteam.features import FEATURE_NAMES  # noqa: E402

_HERE = pathlib.Path(__file__).resolve().parent


def _clamp(x: float, lo: float = 0.0) -> float:
    return max(lo, round(x, 3))


def _benign(r: random.Random) -> dict:
    return {
        "auth_failures_5m": _clamp(r.gauss(1.5, 1.2)),
        "distinct_targets_5m": _clamp(r.gauss(1.2, 1.0)),
        "off_hours": float(r.random() < 0.12),
        "kerberos_ticket_rate": _clamp(r.gauss(0.6, 0.6)),
        "dns_query_entropy": _clamp(r.gauss(2.1, 0.5)),
        "dns_bytes_out_kb": _clamp(r.gauss(1.5, 1.0)),
        "sudo_cmd_anomaly": _clamp(r.gauss(0.4, 0.6)),
        "lateral_conn_count": _clamp(r.gauss(1.5, 1.2)),
        "new_account_flag": float(r.random() < 0.03),
    }


def _password_spray(r: random.Random) -> dict:
    b = _benign(r)
    b.update({
        "auth_failures_5m": _clamp(r.gauss(26, 7)),
        "distinct_targets_5m": _clamp(r.gauss(18, 6)),
        "off_hours": float(r.random() < 0.5),
    })
    return b


def _kerberoast(r: random.Random) -> dict:
    b = _benign(r)
    b.update({
        "kerberos_ticket_rate": _clamp(r.gauss(14, 4)),
        "distinct_targets_5m": _clamp(r.gauss(9, 3)),
        "off_hours": float(r.random() < 0.6),
    })
    return b


def _linux_privesc(r: random.Random) -> dict:
    b = _benign(r)
    b.update({
        "sudo_cmd_anomaly": _clamp(r.gauss(5, 1.5)),
        "auth_failures_5m": _clamp(r.gauss(6, 3)),
        "off_hours": float(r.random() < 0.55),
        "new_account_flag": float(r.random() < 0.4),
    })
    return b


def _dns_tunnel(r: random.Random) -> dict:
    b = _benign(r)
    b.update({
        "dns_query_entropy": _clamp(r.gauss(4.1, 0.3)),
        "dns_bytes_out_kb": _clamp(r.gauss(80, 35)),
    })
    return b


def _lateral(r: random.Random) -> dict:
    b = _benign(r)
    b.update({
        "lateral_conn_count": _clamp(r.gauss(14, 4)),
        "off_hours": float(r.random() < 0.45),
    })
    return b


_ATTACKS = {
    "password_spray": _password_spray,
    "kerberoasting": _kerberoast,
    "linux_privesc": _linux_privesc,
    "dns_tunnel": _dns_tunnel,
    "lateral_movement": _lateral,
}


def generate(n_benign: int = 400, n_per_attack: int = 90, seed: int = 1337) -> list[dict]:
    r = random.Random(seed)
    rows: list[dict] = []
    for _ in range(n_benign):
        rows.append({**_benign(r), "label": 0, "scenario": "benign"})
    for name, fn in _ATTACKS.items():
        for _ in range(n_per_attack):
            rows.append({**fn(r), "label": 1, "scenario": name})
    r.shuffle(rows)
    return rows


def drift_variant(seed: int = 7) -> list[dict]:
    """A *modified* attack the model was not trained on (concept-drift stretch):
    a 'low-and-slow' password spray — few failures but still broad targeting."""
    r = random.Random(seed)
    rows = []
    for _ in range(40):
        row = _benign(r)
        row.update({
            "auth_failures_5m": _clamp(r.gauss(5, 2)),      # deliberately low
            "distinct_targets_5m": _clamp(r.gauss(16, 4)),  # still broad
            "off_hours": float(r.random() < 0.5),
        })
        rows.append({**row, "label": 1, "scenario": "slow_spray_drift"})
    return rows


def split(rows: list[dict], test_frac: float = 0.25, seed: int = 99):
    r = random.Random(seed)
    rows = rows[:]
    r.shuffle(rows)
    n_test = int(len(rows) * test_frac)
    return rows[n_test:], rows[:n_test]


def main() -> None:
    rows = generate()
    (_HERE / "dataset.json").write_text(json.dumps(rows, indent=1), encoding="utf-8")
    pos = sum(r["label"] for r in rows)
    print(f"wrote {len(rows)} rows -> data/dataset.json  (attack={pos}, benign={len(rows) - pos})")
    print("features:", FEATURE_NAMES)


if __name__ == "__main__":
    main()
