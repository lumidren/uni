"""Proof that the target allowlist actually blocks. Runs offline (numeric IPs
only, no DNS needed). Works under pytest or as a bare script:

    python cnc418-redteam/tests/test_allowlist.py
"""
from __future__ import annotations

import pathlib
import sys

_PKG_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PKG_ROOT))

from redteam.allowlist import Allowlist, TargetNotAllowed  # noqa: E402


def test_loopback_is_allowed():
    al = Allowlist()
    assert al.is_allowed("http://127.0.0.1:3000")
    assert al.is_allowed("http://localhost:3000/rest/products/search")
    assert al.is_allowed("http://[::1]:8080/")


def test_public_literal_ip_is_blocked():
    al = Allowlist()
    assert not al.is_allowed("http://8.8.8.8/")
    assert not al.is_allowed("https://1.1.1.1/admin")


def test_private_lab_subnet_blocked_by_default():
    al = Allowlist()
    # Private, but not enabled unless the lab config opts in.
    assert not al.is_allowed("http://10.1.2.3:3000")
    assert not al.is_allowed("http://192.168.56.10/")


def test_private_lab_subnet_allowed_when_configured():
    al = Allowlist(extra_networks=["192.168.56.0/24"])
    assert al.is_allowed("http://192.168.56.10/")
    # A different private host is still blocked.
    assert not al.is_allowed("http://10.1.2.3/")


def test_config_cannot_open_a_public_range():
    # Even if someone tries to allowlist a public /8, it must be refused.
    al = Allowlist(extra_networks=["8.0.0.0/8"])
    assert not al.is_allowed("http://8.8.8.8/")


def test_link_local_is_blocked():
    al = Allowlist()
    assert not al.is_allowed("http://169.254.169.254/latest/meta-data/")  # cloud metadata SSRF classic


def test_assert_raises_with_reason():
    al = Allowlist()
    try:
        al.assert_allowed("http://8.8.8.8/")
    except TargetNotAllowed as exc:
        assert "non-allowed" in str(exc) or "resolves" in str(exc)
    else:
        raise AssertionError("public IP should have raised TargetNotAllowed")


def _run_all() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL {t.__name__}: {exc}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())
