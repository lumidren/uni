"""Hard-coded target allowlist — the single most important control in this project.

The capstone rules are absolute: all offensive activity stays inside
localhost / 127.0.0.1 / an instructor-approved lab subnet. Touching anything
else is immediate project failure. So this module is written defensively:

1. **Loopback-only by default.** With no config, the only legal targets are
   ``localhost``, ``127.0.0.0/8`` and ``::1``.
2. **Globally-routable addresses are refused unconditionally.** Even if a config
   file tries to add a public range, :func:`assert_allowed` rejects any IP whose
   ``is_global`` flag is set. The safety floor cannot be configured away.
3. **Both the hostname and every resolved IP are checked.** A hostname that
   resolves to a non-allowed IP is blocked, which closes the DNS-rebinding /
   sneaky-hostname hole that a naive string check would leave open.

The allowlist is consulted by ``transport.py`` before *every* outbound request,
so there is exactly one choke point and it is trivial to audit in the oral
defence.
"""
from __future__ import annotations

import ipaddress
import json
import socket
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

# Hard safety floor: these loopback networks are always allowed.
_LOOPBACK_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]

# Private ranges that MAY be enabled via config for an approved lab subnet.
# They are never enabled by default.
_PRIVATE_LAB_NETS_ALLOWED_VIA_CONFIG = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

_ALLOWED_HOSTNAMES = {"localhost", "ip6-localhost"}


class TargetNotAllowed(Exception):
    """Raised when a target is outside the allowlist. Never caught-and-ignored."""


class Allowlist:
    def __init__(self, extra_networks: Iterable[str] | None = None):
        self._extra: list[ipaddress._BaseNetwork] = []
        for net in extra_networks or []:
            parsed = ipaddress.ip_network(net, strict=False)
            # A config entry is only honoured if it is a recognised private lab
            # range. Anything public is silently dropped here AND re-checked at
            # request time, so misconfiguration cannot open a public target.
            if any(parsed.subnet_of(p) for p in _PRIVATE_LAB_NETS_ALLOWED_VIA_CONFIG):
                self._extra.append(parsed)

    @classmethod
    def from_config(cls, path: str | Path | None) -> "Allowlist":
        if not path:
            return cls()
        p = Path(path)
        if not p.exists():
            return cls()
        data = json.loads(p.read_text(encoding="utf-8"))
        return cls(extra_networks=data.get("lab_networks", []))

    # -- the gate ----------------------------------------------------------- #
    def _ip_allowed(self, ip: ipaddress._BaseAddress) -> bool:
        # Absolute floor: a globally-routable address is never allowed.
        if ip.is_global:
            return False
        if any(ip in net for net in _LOOPBACK_NETS):
            return True
        if any(ip in net for net in self._extra):
            return True
        return False

    def assert_allowed(self, url: str) -> None:
        """Raise :class:`TargetNotAllowed` unless *url* is a legal lab target."""
        host = urlparse(url).hostname
        if not host:
            raise TargetNotAllowed(f"no host in URL: {url!r}")

        # Literal allowed hostnames (localhost) resolve to loopback anyway, but
        # we special-case them so the tool works even with odd resolver setups.
        if host in _ALLOWED_HOSTNAMES:
            return

        # Resolve the host. EVERY resolved address must pass, or we refuse.
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror as exc:
            raise TargetNotAllowed(f"cannot resolve host {host!r}: {exc}") from exc

        resolved = {ipaddress.ip_address(info[4][0]) for info in infos}
        if not resolved:
            raise TargetNotAllowed(f"host {host!r} resolved to nothing")

        bad = [str(ip) for ip in resolved if not self._ip_allowed(ip)]
        if bad:
            raise TargetNotAllowed(
                f"target {host!r} resolves to non-allowed address(es): {bad}. "
                f"Only loopback (and approved private lab subnets) are permitted."
            )

    def is_allowed(self, url: str) -> bool:
        try:
            self.assert_allowed(url)
            return True
        except TargetNotAllowed:
            return False
