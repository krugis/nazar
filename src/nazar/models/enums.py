from __future__ import annotations

from enum import StrEnum


class VerdictLabel(StrEnum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


class Action(StrEnum):
    """The complete list of actions Nazar can ever take. This enum is the action whitelist."""

    NONE = "none"
    NOTIFY = "notify"
    BAN = "ban"
    CAPTCHA = "captcha"

    @property
    def enforces(self) -> bool:
        """True for actions that create a CrowdSec decision."""
        return self in (Action.BAN, Action.CAPTCHA)


class Outcome(StrEnum):
    AUTO = "auto"
    APPROVAL = "approval"
    REPORT_ONLY = "report_only"
    NO_ACTION = "no_action"


class IncidentStatus(StrEnum):
    OPEN = "open"
    CLOSED = "closed"


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class Actor(StrEnum):
    """Fixed audit actors. Humans are recorded as ``user:<id>`` (see ``user_actor``)."""

    MODEL = "model"
    POLICY = "policy"
    SYSTEM = "system"


def user_actor(user_id: str) -> str:
    return f"user:{user_id}"
