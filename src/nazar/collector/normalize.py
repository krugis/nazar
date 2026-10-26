"""Turn a LAPI ``Alert`` into an ``Event`` (LLD 04). Everything in an alert is untrusted."""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any

from nazar import NAZAR_SCENARIO_PREFIX
from nazar.core.clock import from_iso
from nazar.core.log import get_logger
from nazar.core.sanitize import clean_line
from nazar.models import Event

log = get_logger(__name__)

SAMPLE_META_KEYS = frozenset(
    {
        "log_type",
        "service",
        "http_verb",
        "http_path",
        "http_status",
        "http_user_agent",
        "target_fqdn",
        "user",
        "target_user",
        "rule_name",
        "matched_zones",
    }
)
_SHORT = 120


def _time(value: Any, fallback: datetime) -> datetime:
    try:
        return from_iso(str(value))
    except (TypeError, ValueError):
        return fallback


def _sample_lines(alert: dict[str, Any], max_lines: int, max_len: int) -> list[str]:
    lines: list[str] = []
    for event in alert.get("events") or []:
        if len(lines) >= max_lines:
            break
        meta = event.get("meta") if isinstance(event, dict) else None
        if not isinstance(meta, list):
            continue
        pairs = sorted(
            (str(m.get("key")), str(m.get("value")))
            for m in meta
            if isinstance(m, dict) and m.get("key") in SAMPLE_META_KEYS
        )
        if pairs:
            lines.append(clean_line(" ".join(f"{k}={v}" for k, v in pairs), max_len))
    return lines


def _is_active(decision: dict[str, Any], now: datetime) -> bool:
    """Whether a decision attached to an alert is still in force.

    ``until`` is used when present. CrowdSec 1.8 omits it in alerts and reports ``duration`` as
    the *remaining* time, negative once the decision expired or was deleted (e.g. ``-24s``).
    """
    until = decision.get("until")
    if until:
        try:
            return from_iso(str(until)) > now
        except ValueError:
            pass
    duration = str(decision.get("duration") or "").strip()
    return not duration.startswith("-")


def _active_decisions(alert: dict[str, Any], now: datetime) -> list[str]:
    types: set[str] = set()
    for decision in alert.get("decisions") or []:
        if not isinstance(decision, dict) or decision.get("simulated"):
            continue
        if _is_active(decision, now):
            types.add(clean_line(decision.get("type", ""), 32))
    return sorted(t for t in types if t)


def alert_to_event(
    alert: dict[str, Any], *, now: datetime, max_lines: int, max_len: int
) -> Event | None:
    """Normalize one alert, or return None when Nazar must ignore it."""
    alert_id = alert.get("id")
    scenario = str(alert.get("scenario") or "")
    source = alert.get("source") or {}
    if not isinstance(alert_id, int) or not scenario or not isinstance(source, dict):
        log.debug("alert_ignored", reason="malformed", alert_id=alert_id)
        return None
    if scenario.startswith(NAZAR_SCENARIO_PREFIX):
        return None  # our own alert: feedback-loop protection
    if alert.get("simulated"):
        log.debug("alert_ignored", reason="simulated", alert_id=alert_id)
        return None
    if str(source.get("scope", "")).lower() != "ip":
        log.debug("alert_ignored", reason="scope", alert_id=alert_id, scope=source.get("scope"))
        return None
    raw_ip = str(source.get("ip") or source.get("value") or "")
    try:
        ip = ipaddress.ip_address(raw_ip)
    except ValueError:
        log.debug("alert_ignored", reason="invalid_ip", alert_id=alert_id)
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    started = _time(alert.get("start_at"), now)
    as_number, as_name = source.get("as_number"), source.get("as_name")
    asn = f"AS{as_number} {as_name}" if as_number and as_name else None
    count = alert.get("events_count")
    return Event(
        alert_id=alert_id,
        source_ip=str(ip),
        scenario=clean_line(scenario, _SHORT),
        started_at=started,
        stopped_at=_time(alert.get("stop_at"), started),
        event_count=count if isinstance(count, int) and count > 0 else 1,
        message=clean_line(alert.get("message") or "", max_len),
        sample_lines=_sample_lines(alert, max_lines, max_len),
        labels=[clean_line(x, _SHORT) for x in (alert.get("labels") or []) if x][:20],
        country=clean_line(source["cn"], 8) if source.get("cn") else None,
        asn=clean_line(asn, _SHORT) if asn else None,
        crowdsec_decisions=_active_decisions(alert, now),
    )
