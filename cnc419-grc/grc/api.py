"""The GRC bridge API — the governance nerve centre of the ecosystem.

Exposes the three cross-course interfaces from the handout:
  * GET  /api/v1/assets/profile  -> publishes asset criticality profiles
  * POST /api/v1/findings        -> ingests verified Red Team findings
  * POST /api/v1/incidents       -> ingests Blue Team incident/containment records

Plus read-only helpers (GET /api/v1/risk/register, /health). Built on stdlib
http.server, bound to loopback. Every inbound payload is validated against the
shared contract and a malformed one is rejected with 400 — the enterprise record
is never silently corrupted.
"""
from __future__ import annotations

import json
import pathlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .ids_bridge import ContractError, EXERCISE_RUN_HEADER
from .state import GrcState

_DATA = pathlib.Path(__file__).resolve().parents[1] / "data" / "assets.json"
STATE = GrcState(_DATA)


class Handler(BaseHTTPRequestHandler):
    server_version = "grc-bridge/1.0"

    def log_message(self, fmt, *args):  # noqa: N802
        return

    def _send(self, code: int, obj) -> None:
        body = json.dumps(obj, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        run_id = self.headers.get(EXERCISE_RUN_HEADER)
        if run_id:
            self.send_header(EXERCISE_RUN_HEADER, run_id)   # echo correlation id
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length else b""
        return json.loads(raw.decode("utf-8")) if raw else {}

    def do_GET(self):  # noqa: N802
        path = urlparse(self.path).path
        if path == "/api/v1/assets/profile":
            return self._send(200, STATE.asset_profiles())
        if path == "/api/v1/risk/register":
            return self._send(200, STATE.risk_snapshot())
        if path in ("/", "/api/v1/health"):
            return self._send(200, {"service": "grc-bridge", "status": "ok",
                                    "assets": len(STATE.assets),
                                    "findings_ingested": len(STATE.findings),
                                    "incidents_ingested": len(STATE.incidents)})
        return self._send(404, {"error": "not found", "path": path})

    def do_POST(self):  # noqa: N802
        path = urlparse(self.path).path
        try:
            payload = self._read_json()
        except json.JSONDecodeError:
            return self._send(400, {"error": "invalid JSON"})
        try:
            if path == "/api/v1/findings":
                return self._send(201, STATE.ingest_finding(payload))
            if path == "/api/v1/incidents":
                return self._send(201, STATE.ingest_incident(payload))
        except ContractError as exc:
            return self._send(400, {"error": "contract violation", "detail": str(exc)})
        return self._send(404, {"error": "not found", "path": path})


def serve(port: int = 4190) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"[grc-api] listening on http://127.0.0.1:{port}  (loopback only)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    serve()
