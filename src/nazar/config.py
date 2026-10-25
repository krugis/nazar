"""Configuration loading and validation (LLD 02).

Secrets never live in the config file. The config names environment variables (``*_env``) whose
values come from the process environment or ``/etc/nazar/secrets.env``.
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from nazar.core.errors import ConfigError
from nazar.models import Action, parse_duration

DEFAULT_CONFIG_PATH = Path("/etc/nazar/config.yaml")
DEFAULT_SECRETS_PATH = Path("/etc/nazar/secrets.env")
HMAC_KEY_ENV = "NAZAR_HMAC_KEY"

__all__ = [
    "DEFAULT_CONFIG_PATH",
    "DEFAULT_SECRETS_PATH",
    "HMAC_KEY_ENV",
    "Config",
    "ConfigError",
    "Issue",
    "Mode",
    "check_config",
    "load_config",
    "load_secrets",
    "secret",
]


class Mode(StrEnum):
    DRY_RUN = "dry_run"
    ACTIVE = "active"


def _check_duration(value: str) -> str:
    parse_duration(value)
    return value


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CrowdSecConfig(_Section):
    lapi_url: str = "http://127.0.0.1:8080"
    machine_id: str = "nazar"
    password_env: str = "NAZAR_LAPI_PASSWORD"
    cti_api_key_env: str | None = None
    cti_url: str = "https://cti.api.crowdsec.net/v2"
    cti_cache_hours: int = Field(default=24, ge=1)
    timeout_seconds: float = Field(default=10.0, gt=0)
    decision_origin: str = "cscli"
    use_cscli_fallback: bool = False
    import_allowlists: bool = False


class CollectorConfig(_Section):
    interval_seconds: int = Field(default=30, ge=5)
    lookback: str = "1h"
    batch_limit: int = Field(default=500, ge=1, le=10000)

    _lookback = field_validator("lookback")(_check_duration)


class PrefilterConfig(_Section):
    dedupe_window_seconds: int = Field(default=300, ge=0)
    incident_window_minutes: int = Field(default=30, ge=1)
    max_sample_lines: int = Field(default=20, ge=0, le=200)
    max_line_length: int = Field(default=300, ge=20, le=4000)


class AnalystConfig(_Section):
    ollama_url: str = "http://127.0.0.1:11434"
    model: str = "hf.co/Nguuma/security-slm-unsloth-1.5b"
    timeout_seconds: float = Field(default=60.0, gt=0)
    temperature: float = Field(default=0.1, ge=0.0, le=1.0)
    max_calls_per_minute: int = Field(default=10, ge=1)
    prompt_version: str = "triage-v1"
    num_ctx: int = Field(default=4096, ge=512)
    num_predict: int = Field(default=2048, ge=64)
    """Token budget for reasoning *and* answer: reasoning models think before the JSON."""
    max_queue: int = Field(default=200, ge=1)
    think: bool | None = None
    keep_alive: str = "30m"

    _keep_alive = field_validator("keep_alive")(_check_duration)


class PolicyConfig(_Section):
    auto_actions: list[Action] = Field(default_factory=lambda: [Action.BAN, Action.NOTIFY])
    auto_min_confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    approval_min_confidence: float = Field(default=0.6, ge=0.0, le=1.0)
    default_ban_duration: str = "4h"
    max_ban_duration: str = "24h"
    max_auto_actions_per_hour: int = Field(default=20, ge=0)
    allowlist_cidrs: list[str] = Field(default_factory=list)
    host_addresses: list[str] = Field(default_factory=list)
    captcha_available: bool = False

    _durations = field_validator("default_ban_duration", "max_ban_duration")(_check_duration)

    @field_validator("allowlist_cidrs", "host_addresses")
    @classmethod
    def _networks(cls, values: list[str]) -> list[str]:
        for value in values:
            ipaddress.ip_network(value, strict=False)
        return values

    @model_validator(mode="after")
    def _cross_fields(self) -> PolicyConfig:
        if self.approval_min_confidence > self.auto_min_confidence:
            raise ValueError("approval_min_confidence must not exceed auto_min_confidence")
        if self.default_ban > self.max_ban:
            raise ValueError("default_ban_duration must not exceed max_ban_duration")
        return self

    @property
    def max_ban(self) -> timedelta:
        return parse_duration(self.max_ban_duration)

    @property
    def default_ban(self) -> timedelta:
        return parse_duration(self.default_ban_duration)


class TelegramConfig(_Section):
    enabled: bool = False
    bot_token_env: str = "NAZAR_TG_TOKEN"
    chat_id: str = ""
    allowed_user_ids: list[int] = Field(default_factory=list)

    @model_validator(mode="after")
    def _chat_required(self) -> TelegramConfig:
        if self.enabled and not self.chat_id:
            raise ValueError("telegram.chat_id is required when telegram is enabled")
        return self


_HHMM = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


class NotifierConfig(_Section):
    telegram: TelegramConfig = Field(default_factory=TelegramConfig)
    approval_ttl_minutes: int = Field(default=60, ge=1)
    daily_summary_time: str = "09:00"
    timezone: str = "UTC"

    @field_validator("daily_summary_time")
    @classmethod
    def _hhmm(cls, value: str) -> str:
        if not _HHMM.match(value):
            raise ValueError("daily_summary_time must be HH:MM")
        return value

    @field_validator("timezone")
    @classmethod
    def _tz(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"unknown timezone {value!r}") from exc
        return value


class EnrichConfig(_Section):
    timeout_seconds: float = Field(default=5.0, gt=0)
    geoip_country_db: Path | None = None
    """MaxMind GeoLite2 Country or City database (needs the ``geoip`` extra)."""
    geoip_asn_db: Path | None = None
    """MaxMind GeoLite2 ASN database."""


class HostContextConfig(_Section):
    exposed_services: list[str] = Field(default_factory=list)


class StoreConfig(_Section):
    path: Path = Path("/var/lib/nazar/nazar.db")
    retention_days: int = Field(default=90, ge=1)


class Config(_Section):
    mode: Mode = Mode.DRY_RUN
    crowdsec: CrowdSecConfig = Field(default_factory=CrowdSecConfig)
    collector: CollectorConfig = Field(default_factory=CollectorConfig)
    prefilter: PrefilterConfig = Field(default_factory=PrefilterConfig)
    analyst: AnalystConfig = Field(default_factory=AnalystConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    enrich: EnrichConfig = Field(default_factory=EnrichConfig)
    notifier: NotifierConfig = Field(default_factory=NotifierConfig)
    host_context: HostContextConfig = Field(default_factory=HostContextConfig)
    store: StoreConfig = Field(default_factory=StoreConfig)

    @property
    def dry_run(self) -> bool:
        return self.mode is Mode.DRY_RUN

    def with_mode(self, mode: Mode) -> Config:
        return self.model_copy(update={"mode": mode})

    def secret_values(self) -> list[str]:
        """Every configured secret that is set, for log redaction."""
        names = [
            self.crowdsec.password_env,
            self.crowdsec.cti_api_key_env,
            self.notifier.telegram.bot_token_env,
            HMAC_KEY_ENV,
        ]
        return [v for v in (secret(n) for n in names) if v]


def load_config(path: Path | None = None) -> Config:
    path = path or Path(os.environ.get("NAZAR_CONFIG", DEFAULT_CONFIG_PATH))
    try:
        raw: Any = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc.strerror}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: top level must be a mapping")
    try:
        return Config.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"invalid configuration in {path}:\n{exc}") from exc


_ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


def parse_env_file(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = _ENV_LINE.match(line)
        if not match:
            continue
        key, value = match.groups()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key] = value
    return values


def load_secrets(path: Path | None = None) -> None:
    """Load ``KEY=value`` lines into ``os.environ`` without overriding existing variables."""
    path = path or Path(os.environ.get("NAZAR_SECRETS", DEFAULT_SECRETS_PATH))
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return
    for key, value in parse_env_file(text).items():
        os.environ.setdefault(key, value)


def secret(env_name: str | None) -> str | None:
    """Value of a secret environment variable, or None when unset or empty."""
    if not env_name:
        return None
    return os.environ.get(env_name) or None


@dataclass(frozen=True)
class Issue:
    level: Literal["error", "warning"]
    message: str


def check_config(cfg: Config) -> list[Issue]:
    """Semantic checks beyond the schema, for ``nazar config check``."""
    issues: list[Issue] = []
    if not secret(cfg.crowdsec.password_env):
        issues.append(Issue("error", f"LAPI password not set (${cfg.crowdsec.password_env})"))
    if cfg.crowdsec.cti_api_key_env and not secret(cfg.crowdsec.cti_api_key_env):
        issues.append(Issue("warning", f"CTI key not set (${cfg.crowdsec.cti_api_key_env})"))
    tg = cfg.notifier.telegram
    if tg.enabled:
        if not secret(tg.bot_token_env):
            issues.append(Issue("error", f"Telegram token not set (${tg.bot_token_env})"))
        if not secret(HMAC_KEY_ENV):
            issues.append(Issue("error", f"callback signing key not set (${HMAC_KEY_ENV})"))
    if cfg.mode is Mode.ACTIVE and not cfg.policy.allowlist_cidrs:
        issues.append(
            Issue("warning", "active mode with an empty policy.allowlist_cidrs: add your own IPs")
        )
    if Action.CAPTCHA in cfg.policy.auto_actions and not cfg.policy.captcha_available:
        issues.append(Issue("warning", "captcha in auto_actions but captcha_available is false"))
    store_dir = cfg.store.path.parent
    if store_dir.exists() and not os.access(store_dir, os.W_OK):
        issues.append(Issue("error", f"store directory {store_dir} is not writable"))
    return issues
