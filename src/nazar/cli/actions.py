"""``nazar approve``, ``nazar reject``, ``nazar rollback``."""

from __future__ import annotations

import argparse
import asyncio
import getpass
from typing import Any

from nazar.app import build_app
from nazar.approvals import ApprovalOutcome
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
    for name, helptext in (
        ("approve", "approve a pending action (re-checked by the policy engine)"),
        ("reject", "reject a pending action"),
    ):
        a = sub.add_parser(name, help=helptext)
        a.add_argument("approval_id")
        a.set_defaults(handler=cmd_approve if name == "approve" else cmd_reject)

    p = sub.add_parser("rollback", help="remove decisions Nazar created")
    which = p.add_mutually_exclusive_group(required=True)
    which.add_argument("--incident", help="all decisions of this incident")
    which.add_argument("--since", help="decisions applied within this window, e.g. 1h")
    which.add_argument("--decision", type=int, help="one decision ID")
    p.add_argument("--yes", "-y", action="store_true", help="do not ask for confirmation")
    p.set_defaults(handler=cmd_rollback)


def cmd_approve(args: argparse.Namespace) -> int:
    return asyncio.run(_resolve(_context.load(args), args, approve=True))


def cmd_reject(args: argparse.Namespace) -> int:
    return asyncio.run(_resolve(_context.load(args), args, approve=False))


_EXIT = {
    ApprovalOutcome.APPROVED: 0,
    ApprovalOutcome.REJECTED: 0,
    ApprovalOutcome.REFUSED: 3,
    ApprovalOutcome.EXPIRED: 1,
    ApprovalOutcome.NOT_PENDING: 1,
    ApprovalOutcome.NOT_FOUND: 1,
}


async def _resolve(cfg: Config, args: argparse.Namespace, *, approve: bool) -> int:
    app = build_app(cfg)
    try:
        service = app.approvals
        result = await (
            service.approve(args.approval_id, cli_actor())
            if approve
            else service.reject(args.approval_id, cli_actor())
        )
    finally:
        await app.aclose()
    if args.json:
        print_json(
            {
                "approval_id": result.approval_id,
                "outcome": result.outcome.value,
                "reasons": result.reasons,
                "applied": result.applied.status.value if result.applied else None,
            }
        )
    else:
        print(f"approval {result.approval_id}: {result.outcome.value}")
        if result.applied is not None:
            print(f"decision {result.applied.decision_id}: {result.applied.status.value}")
        if result.outcome is ApprovalOutcome.REFUSED:
            for reason in result.reasons:
                print(f"  - {reason}")
    return _EXIT[result.outcome]


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
