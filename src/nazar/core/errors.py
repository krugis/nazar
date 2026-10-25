"""Nazar exception hierarchy (LLD 00)."""

from __future__ import annotations


class NazarError(Exception):
    """Base class for every error Nazar raises on purpose."""


class ConfigError(NazarError):
    """Bad or missing configuration or secrets."""


class StoreError(NazarError):
    pass


class UpstreamError(NazarError):
    """An external service failed."""


class LapiError(UpstreamError):
    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class LapiAuthError(LapiError):
    pass


class LlmError(UpstreamError):
    pass


class CtiError(UpstreamError):
    pass


class NotifierError(UpstreamError):
    pass


class PolicyViolation(NazarError):
    """A component was asked to do something the policy forbids. Indicates a bug."""
