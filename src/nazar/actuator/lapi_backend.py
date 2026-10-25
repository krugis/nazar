"""Decisions through the CrowdSec LAPI (LLD 09, payload verified against the swagger)."""

from __future__ import annotations

from typing import Any, Protocol

from nazar import NAZAR_SCENARIO
from nazar.actuator.backend import CSCLI_REF, BanRequest
from nazar.core.clock import Clock, to_iso


class LapiDecisionApi(Protocol):
    """The LAPI calls the actuator needs; ``collector.LapiClient`` provides them."""

    async def push_alerts(self, alerts: list[dict[str, Any]]) -> list[str]: ...
    async def get_alert(self, alert_id: str) -> dict[str, Any] | None: ...
    async def find_alerts(self, *, scenario: str, ip: str) -> list[dict[str, Any]]: ...
    async def delete_decision(self, decision_id: int) -> int: ...
    async def delete_decisions(self, *, ip: str, scenario: str) -> int: ...


class LapiDecisionBackend:
    def __init__(self, lapi: LapiDecisionApi, clock: Clock, origin: str = "cscli") -> None:
        self._lapi = lapi
        self._clock = clock
        self._origin = origin

    def payload(self, req: BanRequest) -> list[dict[str, Any]]:
        now = to_iso(self._clock.now())
        return [
            {
                "scenario": NAZAR_SCENARIO,
                "scenario_hash": "",
                "scenario_version": "",
                "message": req.message,
                "events_count": 1,
                "start_at": now,
                "stop_at": now,
                "capacity": 0,
                "leakspeed": "0",
                "simulated": False,
                "remediation": True,
                "events": [],
                "labels": ["nazar", f"incident:{req.incident_id}"],
                "source": {"scope": "Ip", "value": req.ip, "ip": req.ip},
                "decisions": [
                    {
                        "type": req.type.value,
                        "scope": "Ip",
                        "value": req.ip,
                        "duration": req.duration,
                        "origin": self._origin,
                        "scenario": NAZAR_SCENARIO,
                    }
                ],
            }
        ]

    async def add(self, req: BanRequest) -> str:
        ids = await self._lapi.push_alerts(self.payload(req))
        if not ids:
            raise ValueError("LAPI accepted the alert but returned no ID")
        return ids[0]

    async def remove(self, crowdsec_alert_id: str, ip: str) -> int:
        alert = None
        if crowdsec_alert_id and crowdsec_alert_id != CSCLI_REF:
            alert = await self._lapi.get_alert(crowdsec_alert_id)
        decisions = [
            d for d in (alert or {}).get("decisions") or [] if isinstance(d.get("id"), int)
        ]
        if alert is None or not decisions:
            # Alert gone, cscli-made, or no IDs: remove only Nazar's decisions on this IP.
            return await self._lapi.delete_decisions(ip=ip, scenario=NAZAR_SCENARIO)
        removed = 0
        for decision in decisions:
            removed += await self._lapi.delete_decision(int(decision["id"]))
        return removed

    async def find(self, req: BanRequest) -> str | None:
        for alert in await self._lapi.find_alerts(scenario=NAZAR_SCENARIO, ip=req.ip):
            if str(alert.get("message", "")) == req.message and alert.get("id") is not None:
                return str(alert["id"])
        return None
