"""``nazar run``."""

from __future__ import annotations

import argparse
import asyncio
from typing import Any

from nazar.app import build_app
from nazar.cli import _context
from nazar.cli._output import err, print_json
from nazar.config import Mode, check_config
from nazar.daemon import Daemon
from nazar.pipeline import PipelineResult, report_line


def register(sub: Any) -> None:
    p = sub.add_parser("run", help="run the daemon in the foreground")
    p.add_argument("--dry-run", action="store_true", help="force dry-run mode")
    p.add_argument("--once", action="store_true", help="one collect + triage cycle, then exit")
    p.set_defaults(handler=cmd_run)


def cmd_run(args: argparse.Namespace) -> int:
    cfg = _context.load(args)
    if args.dry_run:
        cfg = cfg.with_mode(Mode.DRY_RUN)
    errors = [i for i in check_config(cfg) if i.level == "error"]
    if errors:
        for issue in errors:
            err(f"error: {issue.message}")
        return 2
    return asyncio.run(_run(cfg, args))


async def _run(cfg: Any, args: argparse.Namespace) -> int:
    app = build_app(cfg)
    try:
        # Dry-run prints one report line per incident as it is triaged (not with --json).
        daemon = Daemon(app, reporter=None if args.json else _report_line)
        if not args.once:
            await daemon.run()
            return 0
        health = await daemon.health_check()
        if not health["lapi"]:
            err("error: CrowdSec LAPI is unreachable or rejected the credentials")
            return 1
        results = await daemon.run_once()
        if args.json:
            print_json([_result_json(r) for r in results])
            return 0
        if not cfg.dry_run:
            for r in results:
                print(report_line(r))
        print(f"{len(results)} incident(s) triaged")
        return 0
    finally:
        await app.aclose()


def _report_line(line: str) -> None:
    # Flush: under systemd stdout is a pipe, and buffered report lines would only appear much later.
    print(line, flush=True)


def _result_json(r: PipelineResult) -> dict[str, Any]:
    return {
        "incident": r.incident.model_dump(mode="json"),
        "verdict": r.verdict.model_dump(mode="json"),
        "decision": r.decision.model_dump(mode="json") if r.decision else None,
        "skipped": r.skipped_reason,
    }
