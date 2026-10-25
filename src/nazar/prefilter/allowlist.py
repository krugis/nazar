"""Allow-lists and always-protected networks (LLD 05)."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable
from pathlib import Path

from nazar.config import PolicyConfig

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

PROTECTED: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("loopback", ("127.0.0.0/8", "::1/128")),
    ("rfc1918", ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")),
    ("link_local", ("169.254.0.0/16", "fe80::/10")),
    ("cgnat", ("100.64.0.0/10",)),
    ("ula", ("fc00::/7",)),
    ("unspecified", ("0.0.0.0/8", "::/128")),
)


def _parse_ip(value: str) -> IPAddress | None:
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


class AllowList:
    """Immutable, I/O-free matcher. The first matching entry's label wins."""

    def __init__(self, entries: Iterable[tuple[str, IPNetwork]]) -> None:
        self._entries = tuple(entries)

    def match(self, ip: str) -> str | None:
        """Label of the first network containing ``ip``. Invalid IPs match as ``invalid``."""
        addr = _parse_ip(ip)
        if addr is None:
            return "invalid"
        for label, net in self._entries:
            if addr.version == net.version and addr in net:
                return label
        return None

    def __len__(self) -> int:
        return len(self._entries)


def _net(value: str) -> IPNetwork:
    return ipaddress.ip_network(value.strip(), strict=False)


def protected_entries() -> list[tuple[str, IPNetwork]]:
    return [(label, _net(cidr)) for label, cidrs in PROTECTED for cidr in cidrs]


def local_addresses(proc: Path = Path("/proc/net")) -> set[str]:
    """This host's addresses: hostname resolution plus kernel interface tables. No subprocesses."""
    found: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            found.add(str(info[4][0]).split("%")[0])
    except OSError:
        pass
    try:
        last = ""
        for line in (proc / "fib_trie").read_text().splitlines():
            text = line.strip()
            if text.startswith("|--"):
                last = text[3:].strip()
            elif "/32 host LOCAL" in text and last:
                found.add(last)
    except OSError:
        pass
    try:
        for line in (proc / "if_inet6").read_text().splitlines():
            raw = line.split()[0] if line.strip() else ""
            if len(raw) == 32:
                found.add(str(ipaddress.IPv6Address(int(raw, 16))))
    except (OSError, ValueError):
        pass
    return {a for a in found if _parse_ip(a) is not None}


def build_allowlist(
    policy: PolicyConfig,
    host_addresses: Iterable[str] | None = None,
    crowdsec_cidrs: Iterable[str] = (),
) -> AllowList:
    """Assemble the allow-list. ``host_addresses=None`` discovers them from the system."""
    discovered = local_addresses() if host_addresses is None else set(host_addresses)
    entries = protected_entries()
    for addr in sorted({*policy.host_addresses, *discovered}):
        try:
            entries.append(("host", _net(addr)))
        except ValueError:
            continue
    entries += [("config", _net(c)) for c in policy.allowlist_cidrs]
    entries += [("crowdsec", _net(c)) for c in crowdsec_cidrs]
    return AllowList(entries)
