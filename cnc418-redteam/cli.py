"""CNC 418 Red Team agent — command-line entrypoint.

Offline demo (no Docker, no network, one command):

    python cnc418-redteam/cli.py --start-mock

That boots the bundled localhost target, runs the agent against it, verifies
exploits, assembles a chain, and writes JSON + SARIF into ./out/.

Against OWASP Juice Shop instead:

    docker compose -f cnc418-redteam/targets/docker-compose.juiceshop.yml up -d
    python cnc418-redteam/cli.py --target http://127.0.0.1:3000
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
import threading
from http.server import ThreadingHTTPServer
from urllib.parse import urlparse

_PKG_ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_PKG_ROOT))
sys.path.insert(0, str(_PKG_ROOT / "targets"))

from redteam.agent import RedTeamAgent                     # noqa: E402
from redteam.allowlist import Allowlist                    # noqa: E402
from redteam.transport import Transport                    # noqa: E402
from redteam import report, grc_client                     # noqa: E402
from redteam.ids_bridge import new_exercise_run_id         # noqa: E402

from shared.contracts import AssetProfile                  # noqa: E402


def _start_mock(target_url: str) -> ThreadingHTTPServer:
    import mock_vuln_app
    port = urlparse(target_url).port or 3000
    server = ThreadingHTTPServer(("127.0.0.1", port), mock_vuln_app.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"[cli] started mock target on http://127.0.0.1:{port}")
    return server


def _publish(findings, blue_url: str | None, grc_url: str | None, tx: Transport) -> None:
    if not findings:
        return
    body = json.dumps(report.findings_to_json(findings)).encode()
    for name, url in (("Blue", blue_url), ("GRC", grc_url)):
        if not url:
            continue
        try:
            resp = tx.post(f"{url}/api/v1/findings",
                           headers={"Content-Type": "application/json"}, body=body)
            print(f"[cli] published {len(findings)} findings to {name} ({url}) -> HTTP {resp.status}")
        except Exception as exc:
            print(f"[cli] could not publish to {name} ({url}): {exc}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="CNC 418 autonomous red-team agent (lab-only).")
    ap.add_argument("--target", default="http://127.0.0.1:3000", help="Target base URL (must be on allowlist).")
    ap.add_argument("--run-id", default=None, help="Exercise run id (default: generated).")
    ap.add_argument("--allowlist-config", default=str(_PKG_ROOT / "config" / "allowlist.json"))
    ap.add_argument("--grc-assets", default=None, help="Path to a GRC asset-profile JSON (mock peer payload).")
    ap.add_argument("--grc-url", default=None, help="Live GRC API base URL for asset profiles.")
    ap.add_argument("--blue-url", default=None, help="Blue Team API base URL to publish findings to.")
    ap.add_argument("--out", default=str(_PKG_ROOT / "out"))
    ap.add_argument("--start-mock", action="store_true", help="Boot the bundled localhost mock target.")
    ap.add_argument("--publish", action="store_true", help="POST verified findings to Blue/GRC.")
    args = ap.parse_args(argv)

    run_id = args.run_id or new_exercise_run_id()
    allowlist = Allowlist.from_config(args.allowlist_config)
    tx = Transport(allowlist, run_id=run_id)

    server = _start_mock(args.target) if args.start_mock else None
    try:
        # --- ingest GRC context (criticality-sorted) --- #
        assets = grc_client.fetch_asset_profiles(
            grc_base_url=args.grc_url, transport=tx, mock_path=args.grc_assets
        )
        if not assets:
            # No GRC feed -> synthesise one asset for the given target so the
            # agent still has something in-scope to work on.
            assets = [AssetProfile(
                asset_id="asset-local",
                ip_or_url=args.target,
                criticality_tier="tier1_critical",
                mtd_minutes=240, rpo_minutes=60,
                applicable_standards=["ISO_27001"],
            )]

        print(f"[cli] run_id={run_id}  targets={[a.asset_id for a in assets]}")
        agent = RedTeamAgent(tx, run_id)
        result = agent.run(assets)

        # explicit anti-hallucination demonstration
        rej = agent.demo_rejection(args.target, assets[0].asset_id)
        if rej.get("exploit_status") == "rejected":
            result.rejected.append(rej)

        paths = report.write_reports(result.findings, run_id, args.out)

        print("\n=== RUN SUMMARY ===")
        print(f"verified findings : {result.verified_count}")
        print(f"rejected / unproven: {len(result.rejected)}")
        for f in result.findings:
            tag = f"chain[{len(f.chain)}]" if f.chain else "single"
            print(f"  + {f.cwe_id:8} {f.mitre_technique_id:10} {f.exploit_status:8} {tag}")
        print(f"transport: sent={tx.stats.sent} blocked={tx.stats.blocked} errors={tx.stats.errors}")
        print(f"reports: {paths['json']}")
        print(f"         {paths['sarif']}")

        if args.publish:
            _publish(result.findings, args.blue_url, args.grc_url, tx)
        return 0
    finally:
        if server is not None:
            server.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
