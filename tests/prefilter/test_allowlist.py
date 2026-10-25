from __future__ import annotations

from pathlib import Path

import pytest

from nazar.config import PolicyConfig
from nazar.prefilter import build_allowlist, local_addresses

POLICY = PolicyConfig(allowlist_cidrs=["198.51.100.0/24"], host_addresses=["203.0.113.10"])


@pytest.mark.parametrize(
    ("ip", "label"),
    [
        ("127.0.0.1", "loopback"),
        ("::1", "loopback"),
        ("10.1.2.3", "rfc1918"),
        ("172.31.255.255", "rfc1918"),
        ("192.168.1.1", "rfc1918"),
        ("169.254.0.5", "link_local"),
        ("fe80::1", "link_local"),
        ("100.64.0.1", "cgnat"),
        ("fd00::1", "ula"),
        ("0.0.0.0", "unspecified"),
        ("::ffff:10.0.0.1", "rfc1918"),
        ("203.0.113.10", "host"),
        ("203.0.113.99", "host"),  # discovered
        ("198.51.100.200", "config"),
        ("192.0.2.1", "crowdsec"),
        ("not-an-ip", "invalid"),
        ("203.0.113.45", None),
        ("172.32.0.1", None),
        ("2001:db8::1", None),
    ],
)
def test_match(ip: str, label: str | None) -> None:
    allow = build_allowlist(
        POLICY, host_addresses=["203.0.113.99"], crowdsec_cidrs=["192.0.2.0/24"]
    )
    assert allow.match(ip) == label


def test_protected_cannot_be_removed() -> None:
    allow = build_allowlist(PolicyConfig(), host_addresses=[])
    assert allow.match("127.0.0.1") == "loopback"
    assert allow.match("10.0.0.1") == "rfc1918"


def test_local_addresses_from_proc(tmp_path: Path) -> None:
    (tmp_path / "fib_trie").write_text(
        "Main:\n  +-- 0.0.0.0/0 3 0 5\n     |-- 203.0.113.7\n        /32 host LOCAL\n"
        "     |-- 203.0.113.255\n        /32 link BROADCAST\n"
    )
    (tmp_path / "if_inet6").write_text("20010db8000000000000000000000001 02 40 00 80 eth0\n")
    found = local_addresses(tmp_path)
    assert "203.0.113.7" in found
    assert "2001:db8::1" in found
    assert "203.0.113.255" not in found
