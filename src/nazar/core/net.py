"""IP helpers and the allow-list interface shared by prefilter, policy and actuator."""

from __future__ import annotations

import ipaddress
from typing import Protocol

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class IpMatcher(Protocol):
    """Anything that can say whether an IP is allow-listed (``prefilter.AllowList``)."""

    def match(self, ip: str) -> str | None:
        """Label of the matching entry, or None."""
        ...


def parse_ip(value: str) -> IPAddress | None:
    """Parse a single IP; IPv4-mapped IPv6 addresses are unwrapped. None if invalid."""
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip
