"""``nazar rollback`` (approve/reject arrive with M3)."""

from __future__ import annotations

import argparse
import asyncio
import getpass
from typing import Any

from nazar.app import build_app
from nazar.cli import _context
from nazar.cli._output import print_json, print_table
from nazar.config import Config
from nazar.core.clock import to_iso
from nazar.models import parse_duration, user_actor


def cli_actor() -> str:
    try:
        name = getpass.getuser()
    except (KeyError, OSError):
        name = "unknown"
    return user_actor(f"cli:{name}")


def register(sub: Any) -> None:
    p = sub.add_parser("rollback", help="remove decisions Nazar created")
    which = p.add_mutually_exclusive_group(required=True)
    which.add_argument("--incident", help="all decisions of this incident")
    which.add_argument("--since", help="decisions applied within this window, e.g. 1h")
    which.add_argument("--decision", type=int, help="one decision ID")
    p.add_argument("--yes", "-y", action="store_true", help="do not ask for confirmation")
    p.set_defaults(handler=cmd_rollback)


def cmd_rollback(args: argparse.Namespace) -> int:
    cfg = _context.load(args)
    return asyncio.run(_rollback(cfg, args))


async def _rollback(cfg: Config, args: argparse.Namespace) -> int:
    app = build_app(cfg)
    try:
        rows = app.actuator.select(
            decision_id=args.decision,
            incident_id=args.incident,
            since=parse_duration(args.since) if args.since else None,
        )
        if not rows:
            if args.json:
                print_json([])
            else:
                print("nothing to roll back")
            return 0
        if not args.json:
            print_table(
                ["decision", "incident", "ip", "type", "duration", "applied"],
                [
                    [r.id, r.incident_id, r.source_ip, r.decision.action.value,
                     r.decision.duration, to_iso(r.applied_at) if r.applied_at else ""]
                    for r in rows
                ],
            )  # fmt: skip
        if not args.yes:
            answer = input(f"Remove {len(rows)} decision(s) from CrowdSec? [y/N] ")
            if answer.strip().lower() not in ("y", "yes"):
                print("aborted")
                return 1
        results = await app.actuator.rollback(rows, by=cli_actor())
    finally:
        await app.aclose()
    if args.json:
        print_json([r.__dict__ for r in results])
    else:
        for r in results:
            print(f"rolled back decision {r.decision_id} ({r.ip}): {r.removed} removed in CrowdSec")
    return 0
