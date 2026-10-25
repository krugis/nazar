"""CrowdSec Local API client (LLD 04). Shared by the collector and the actuator."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import httpx

from nazar.core.clock import Clock, from_iso
from nazar.core.errors import LapiAuthError, LapiError
from nazar.core.log import get_logger

log = get_logger(__name__)

_REFRESH_MARGIN = timedelta(seconds=60)


class LapiClient:
    """Watcher (machine) client: JWT login with proactive refresh and one retry on 401."""

    def __init__(
        self, machine_id: str, password: str, http: httpx.AsyncClient, clock: Clock
    ) -> None:
        self._machine_id = machine_id
        self._password = password
        self._http = http
        self._clock = clock
        self._token: str | None = None
        self._expires: datetime | None = None

    async def login(self) -> None:
        body = {"machine_id": self._machine_id, "password": self._password, "scenarios": []}
        resp = await self._send("POST", "/v1/watchers/login", json=body)
        if resp.status_code == 403:
            raise LapiAuthError("LAPI login refused: machine not validated or wrong password", 403)
        if resp.status_code != 200:
            raise LapiError(f"LAPI login failed with HTTP {resp.status_code}", resp.status_code)
        data = resp.json()
        token = data.get("token")
        if not token:
            raise LapiAuthError("LAPI login response has no token", resp.status_code)
        self._token = token
        try:
            self._expires = from_iso(data["expire"])
        except (KeyError, ValueError):
            self._expires = self._clock.now() + timedelta(minutes=30)
        log.info("lapi_login_ok", machine_id=self._machine_id)

    async def get_alerts(self, *, since: str, limit: int) -> list[dict[str, Any]]:
        data = await self._call("GET", "/v1/alerts", params={"since": since, "limit": limit})
        return data if isinstance(data, list) else []

    async def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        try:
            data = await self._call("GET", f"/v1/alerts/{alert_id}")
        except LapiError as exc:
            if exc.status == 404:
                return None
            raise
        return data if isinstance(data, dict) else None

    async def find_alerts(self, *, scenario: str, ip: str) -> list[dict[str, Any]]:
        data = await self._call("GET", "/v1/alerts", params={"scenario": scenario, "ip": ip})
        return data if isinstance(data, list) else []

    async def push_alerts(self, alerts: list[dict[str, Any]]) -> list[str]:
        data = await self._call("POST", "/v1/alerts", json=alerts)
        if not isinstance(data, list):
            raise LapiError("unexpected response to POST /v1/alerts")
        return [str(x) for x in data]

    async def delete_decision(self, decision_id: int) -> int:
        data = await self._call("DELETE", f"/v1/decisions/{decision_id}")
        return _nb_deleted(data)

    async def delete_decisions(self, *, ip: str, scenario: str) -> int:
        data = await self._call("DELETE", "/v1/decisions", params={"ip": ip, "scenario": scenario})
        return _nb_deleted(data)

    async def health(self) -> bool:
        try:
            await self._ensure_token()
            await self._call("GET", "/v1/alerts", params={"limit": 1})
        except LapiError:
            return False
        return True

    # ------------------------------------------------------------------ internals

    async def _ensure_token(self) -> None:
        if (
            self._token is None
            or self._expires is None
            or self._expires - self._clock.now() < _REFRESH_MARGIN
        ):
            await self.login()

    async def _call(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
    ) -> Any:
        await self._ensure_token()
        resp = await self._send(method, path, params=params, json=json, auth=True)
        if resp.status_code == 401:
            log.info("lapi_token_rejected_relogin")
            await self.login()
            resp = await self._send(method, path, params=params, json=json, auth=True)
            if resp.status_code == 401:
                raise LapiAuthError(f"{method} {path}: unauthorized after re-login", 401)
        if resp.status_code >= 400:
            raise LapiError(
                f"{method} {path} failed with HTTP {resp.status_code}", resp.status_code
            )
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError as exc:
            raise LapiError(f"{method} {path}: invalid JSON response", resp.status_code) from exc

    async def _send(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
        auth: bool = False,
    ) -> httpx.Response:
        headers = {"Authorization": f"Bearer {self._token}"} if auth and self._token else {}
        try:
            return await self._http.request(method, path, params=params, json=json, headers=headers)
        except httpx.HTTPError as exc:
            raise LapiError(f"{method} {path}: {type(exc).__name__}") from exc


def _nb_deleted(data: Any) -> int:
    try:
        return int(data.get("nbDeleted", 0)) if isinstance(data, dict) else 0
    except (TypeError, ValueError):
        return 0
