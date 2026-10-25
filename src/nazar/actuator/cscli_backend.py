"""Fallback through ``cscli`` (LLD 09). Off by default; argv built from validated values only."""

from __future__ import annotations

import asyncio
import ipaddress
import re

from nazar import NAZAR_SCENARIO
from nazar.actuator.backend import CSCLI_REF, BanRequest, DecisionBackend
from nazar.core.errors import LapiAuthError, LapiError
from nazar.models import VERDICT_DURATION_RE, Action

_DURATION = re.compile(r"^\d+(s|m|h)$")
TIMEOUT_S = 15.0


class CscliDecisionBackend:
    def __init__(self, binary: str = "cscli") -> None:
        self._binary = binary

    @staticmethod
    def add_argv(req: BanRequest, binary: str = "cscli") -> list[str]:
        ip = str(ipaddress.ip_address(req.ip))  # raises on anything but a plain IP
        if req.type not in (Action.BAN, Action.CAPTCHA):
            raise ValueError(f"not an enforcing action: {req.type}")
        if not (_DURATION.match(req.duration) or VERDICT_DURATION_RE.match(req.duration)):
            raise ValueError(f"invalid duration {req.duration!r}")
        return [
            binary, "decisions", "add",
            "--ip", ip,
            "--type", req.type.value,
            "--duration", req.duration,
            "--reason", NAZAR_SCENARIO,
        ]  # fmt: skip

    @staticmethod
    def delete_argv(ip: str, binary: str = "cscli") -> list[str]:
        return [
            binary, "decisions", "delete",
            "--ip", str(ipaddress.ip_address(ip)),
            "--scenario", NAZAR_SCENARIO,
        ]  # fmt: skip

    async def _run(self, argv: list[str]) -> None:
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), TIMEOUT_S)
        except (OSError, TimeoutError) as exc:
            raise LapiError(f"cscli failed: {type(exc).__name__}") from exc
        if proc.returncode != 0:
            raise LapiError(f"cscli exited with {proc.returncode}: {stderr.decode()[:200]}")

    async def add(self, req: BanRequest) -> str:
        await self._run(self.add_argv(req, self._binary))
        return CSCLI_REF

    async def remove(self, crowdsec_alert_id: str, ip: str) -> int:
        await self._run(self.delete_argv(ip, self._binary))
        return 1

    async def find(self, req: BanRequest) -> str | None:
        return None


class FallbackDecisionBackend:
    """Use ``primary`` (LAPI); on a non-auth LAPI error, add through ``fallback`` (cscli)."""

    def __init__(self, primary: DecisionBackend, fallback: CscliDecisionBackend) -> None:
        self._primary = primary
        self._fallback = fallback

    async def add(self, req: BanRequest) -> str:
        try:
            return await self._primary.add(req)
        except LapiAuthError:
            raise
        except LapiError:
            return await self._fallback.add(req)

    async def remove(self, crowdsec_alert_id: str, ip: str) -> int:
        if crowdsec_alert_id == CSCLI_REF:
            return await self._fallback.remove(crowdsec_alert_id, ip)
        return await self._primary.remove(crowdsec_alert_id, ip)

    async def find(self, req: BanRequest) -> str | None:
        return await self._primary.find(req)
