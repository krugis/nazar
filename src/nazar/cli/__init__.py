"""``nazar`` command line (LLD 12). Each module registers its own sub-commands."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from nazar import __version__
from nazar.cli import run, setup
from nazar.cli._output import err
from nazar.core.errors import ConfigError, NazarError

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_CONFIG = 2
EXIT_REFUSED = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nazar", description="AI-assisted protection for Linux servers, built on CrowdSec."
    )
    parser.add_argument("--version", action="version", version=f"nazar {__version__}")
    parser.add_argument("--config", type=Path, help="config file (default /etc/nazar/config.yaml)")
    parser.add_argument(
        "--secrets", type=Path, help="secrets file (default /etc/nazar/secrets.env)"
    )
    parser.add_argument(
        "--log-level", default="info", choices=["debug", "info", "warning", "error"]
    )
    parser.add_argument("--log-format", choices=["json", "text"], help="default: text on a TTY")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND", required=True)
    for module in (run, setup):
        module.register(sub)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        code: int = args.handler(args)
    except ConfigError as exc:
        err(f"configuration error: {exc}")
        return EXIT_CONFIG
    except NazarError as exc:
        err(f"error: {exc}")
        return EXIT_ERROR
    except KeyboardInterrupt:
        return EXIT_ERROR
    return code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
