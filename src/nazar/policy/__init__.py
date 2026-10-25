"""Deterministic policy engine (LLD 08). Pure: no I/O, no clock, no randomness."""

from nazar.policy.engine import PolicyInput, evaluate

__all__ = ["PolicyInput", "evaluate"]
