"""Deterministic policy engine (LLD 08). Pure: no I/O, no clock, no randomness."""

from nazar.policy.engine import evaluate
from nazar.policy.rules import RULES
from nazar.policy.types import IpMatcher, PolicyInput

__all__ = ["RULES", "IpMatcher", "PolicyInput", "evaluate"]
