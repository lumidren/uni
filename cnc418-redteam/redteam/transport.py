"""The one HTTP choke point. Every outbound request goes through here.

Responsibilities:
  * **Enforce the allowlist** before the socket is ever opened (``allowlist.py``).
  * **Tag traffic** with the ``X-Exercise-Run-ID`` header so the Blue Team can
    correlate it (this is how Red and Blue line up in the Purple Team exercise).
  * **Rate / noise control** — a minimum interval between requests and a hard
    cap on total requests per run, so the agent cannot loop forever or
    accidentally DoS the lab target.

Built on stdlib ``urllib`` so there is nothing to install and nothing hidden.
"""
from __future__ import annotations

import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

from .allowlist import Allowlist, TargetNotAllowed

EXERCISE_RUN_HEADER = "X-Exercise-Run-ID"


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: str
    url: str
    elapsed_ms: float


@dataclass
class TransportStats:
    sent: int = 0
    blocked: int = 0
    errors: int = 0
    log: list[str] = field(default_factory=list)


class RequestBudgetExceeded(Exception):
    """Raised when the per-run request cap is hit (noise / self-DoS guard)."""


class Transport:
    def __init__(
        self,
        allowlist: Allowlist,
        run_id: str,
        *,
        min_interval_s: float = 0.15,
        max_requests: int = 800,
        timeout_s: float = 10.0,
        user_agent: str = "cnc418-redteam/1.0 (lab-only)",
    ):
        self.allowlist = allowlist
        self.run_id = run_id
        self.min_interval_s = min_interval_s
        self.max_requests = max_requests
        self.timeout_s = timeout_s
        self.user_agent = user_agent
        self.stats = TransportStats()
        self._last_request_at = 0.0

    def _throttle(self) -> None:
        delta = time.monotonic() - self._last_request_at
        if delta < self.min_interval_s:
            time.sleep(self.min_interval_s - delta)
        self._last_request_at = time.monotonic()

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[dict[str, str]] = None,
        body: Optional[bytes] = None,
    ) -> Response:
        # 1. Guardrail first. If the target is not allowed, we never open a socket.
        try:
            self.allowlist.assert_allowed(url)
        except TargetNotAllowed:
            self.stats.blocked += 1
            self.stats.log.append(f"BLOCKED {method} {url}")
            raise

        # 2. Noise / self-DoS guard.
        if self.stats.sent >= self.max_requests:
            raise RequestBudgetExceeded(
                f"request cap {self.max_requests} reached for run {self.run_id}"
            )

        # 3. Throttle, tag, send.
        self._throttle()
        req_headers = {
            "User-Agent": self.user_agent,
            EXERCISE_RUN_HEADER: self.run_id,  # <-- Blue Team correlation tag
        }
        if headers:
            req_headers.update(headers)

        req = urllib.request.Request(url, data=body, method=method, headers=req_headers)
        start = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                elapsed = (time.monotonic() - start) * 1000
                self.stats.sent += 1
                self.stats.log.append(f"{resp.status} {method} {url}")
                return Response(
                    status=resp.status,
                    headers={k: v for k, v in resp.headers.items()},
                    body=raw,
                    url=url,
                    elapsed_ms=elapsed,
                )
        except urllib.error.HTTPError as exc:
            # A 4xx/5xx is still a useful signal to the agent (e.g. blind SQLi
            # boolean inference, WAF blocks), so surface it as a Response.
            raw = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            elapsed = (time.monotonic() - start) * 1000
            self.stats.sent += 1
            self.stats.log.append(f"{exc.code} {method} {url}")
            return Response(
                status=exc.code,
                headers={k: v for k, v in (exc.headers or {}).items()},
                body=raw,
                url=url,
                elapsed_ms=elapsed,
            )
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            self.stats.errors += 1
            self.stats.log.append(f"ERROR {method} {url} -> {exc}")
            raise

    def get(self, url: str, **kw) -> Response:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw) -> Response:
        return self.request("POST", url, **kw)
