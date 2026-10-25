"""Loading config, secrets and logging for a command."""

from __future__ import annotations

import argparse
import sys

from nazar.config import Config, load_config, load_secrets
from nazar.core.log import redact, setup_logging


def load(args: argparse.Namespace) -> Config:
    load_secrets(args.secrets)
    cfg = load_config(args.config)
    redact.set(cfg.secret_values())
    fmt = args.log_format or ("text" if sys.stderr.isatty() else "json")
    setup_logging(args.log_level, fmt)
    return cfg
