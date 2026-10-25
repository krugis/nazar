"""``nazar init``, ``nazar config check``, ``nazar status``, ``nazar test-model``."""

from __future__ import annotations

import argparse
import asyncio
import os
from pathlib import Path
from typing import Any

from nazar import bootstrap
from nazar.analyst import PromptTemplate
from nazar.analyst.evaluate import load_cases, run_eval
from nazar.app import build_app
from nazar.cli import _context
from nazar.cli._output import err, print_json, print_table
from nazar.collector.source import CURSOR_KEY, LAST_POLL_KEY
from nazar.config import Config, Issue, check_config, load_config
from nazar.daemon import HEALTH_KEY


def register(sub: Any) -> None:
    init = sub.add_parser("init", help="create config and secrets, register with CrowdSec")
    init.add_argument("--machine-id", default="nazar", help="CrowdSec machine name")
    init.add_argument("--skip-register", action="store_true", help="do not call cscli")
    init.add_argument(
        "--force-register", action="store_true", help="reset an existing machine's password"
    )
    init.add_argument("--skip-checks", action="store_true", help="skip Ollama and self-test")
    init.add_argument("--root", type=Path, default=Path("/"), help=argparse.SUPPRESS)
    init.set_defaults(handler=cmd_init)

    config = sub.add_parser("config", help="configuration commands")
    config_sub = config.add_subparsers(dest="config_command", metavar="COMMAND", required=True)
    check = config_sub.add_parser("check", help="validate the configuration file")
    check.add_argument("--strict", action="store_true", help="exit 1 on warnings")
    check.set_defaults(handler=cmd_config_check)

    status = sub.add_parser("status", help="health of LAPI, Ollama and the model")
    status.set_defaults(handler=cmd_status)

    test_model = sub.add_parser("test-model", help="evaluate the model on labelled incidents")
    test_model.add_argument("--file", type=Path, help="JSONL eval file (default: packaged set)")
    test_model.add_argument("--limit", type=int, help="only the first N cases")
    test_model.set_defaults(handler=cmd_test_model)


def _issues(cfg: Config) -> list[Issue]:
    issues = check_config(cfg)
    version = PromptTemplate.load().version
    if version != cfg.analyst.prompt_version:
        issues.append(
            Issue(
                "warning",
                f"prompt file version {version} differs from analyst.prompt_version "
                f"{cfg.analyst.prompt_version}",
            )
        )
    return issues


def cmd_config_check(args: argparse.Namespace) -> int:
    cfg = _context.load(args)
    issues = _issues(cfg)
    if args.json:
        print_json({"ok": not issues, "issues": [i.__dict__ for i in issues]})
    else:
        for issue in issues:
            print(f"{issue.level}: {issue.message}")
        if not issues:
            print("configuration OK")
    if any(i.level == "error" for i in issues):
        return 2
    return 1 if args.strict and issues else 0


def cmd_status(args: argparse.Namespace) -> int:
    cfg = _context.load(args)
    return asyncio.run(_status(cfg, args))


async def _status(cfg: Config, args: argparse.Namespace) -> int:
    app = build_app(cfg)
    try:
        lapi_ok = await app.lapi.health()
        backend = await app.backend.health()
        info = {
            "mode": cfg.mode.value,
            "lapi": {"url": cfg.crowdsec.lapi_url, "ok": lapi_ok},
            "ollama": {
                "url": cfg.analyst.ollama_url,
                "ok": backend.reachable,
                "version": backend.version,
            },
            "model": {"name": cfg.analyst.model, "present": backend.model_present},
            "prompt_version": app.analyst.template.version,
            "pending_triage": len(app.store.incidents.pending_triage()),
            "pending_approvals": len(app.store.approvals.pending()),
            "cursor": app.store.kv.get(CURSOR_KEY),
            "last_poll": app.store.kv.get(LAST_POLL_KEY),
            "daemon_health": app.store.kv.get(HEALTH_KEY),
        }
    finally:
        await app.aclose()
    healthy = lapi_ok and backend.reachable and backend.model_present
    if args.json:
        print_json(info | {"healthy": healthy})
    else:
        ok = {True: "ok", False: "DOWN"}
        print_table(
            ["component", "state", "detail"],
            [
                ["mode", cfg.mode.value, ""],
                ["crowdsec lapi", ok[lapi_ok], cfg.crowdsec.lapi_url],
                [
                    "ollama",
                    ok[backend.reachable],
                    f"{cfg.analyst.ollama_url} {backend.version or ''}",
                ],
                ["model", "ok" if backend.model_present else "MISSING", cfg.analyst.model],
                ["prompt", info["prompt_version"], ""],
                ["queue", info["pending_triage"], "incidents waiting for triage"],
                ["approvals", info["pending_approvals"], "pending"],
                ["cursor", info["cursor"], f"last poll {info['last_poll'] or 'never'}"],
            ],
        )
    return 0 if healthy else 1


def cmd_test_model(args: argparse.Namespace) -> int:
    cfg = _context.load(args)
    return asyncio.run(_test_model(cfg, args))


async def _test_model(cfg: Config, args: argparse.Namespace) -> int:
    cases = load_cases(args.file)[: args.limit] if args.limit else load_cases(args.file)
    app = build_app(cfg)
    try:
        health = await app.backend.health()
        if not (health.reachable and health.model_present):
            err(f"error: Ollama unreachable or model {cfg.analyst.model} not pulled")
            return 1
        report = await run_eval(app.analyst, cases)
    finally:
        await app.aclose()
    summary = report.summary()
    if args.json:
        print_json(summary | {"failures": report.failures})
    else:
        print_table(["metric", "value"], [[k, v] for k, v in summary.items()])
        if report.failures:
            print(f"\n{len(report.failures)} case(s) disagreed:")
            for f in report.failures:
                print(f"  {f['id']}: expected {f['expected']} got {f['got']}")
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    paths = bootstrap.Paths(args.root)
    if args.root == Path("/") and os.geteuid() != 0:
        err("error: nazar init must run as root (it writes /etc/nazar and calls cscli)")
        return 1
    report = bootstrap.init(
        paths,
        machine_id=args.machine_id,
        register=not args.skip_register,
        force_register=args.force_register,
    )
    bootstrap.apply_secrets_to_env(paths)
    cfg = load_config(paths.config)
    if args.root != Path("/"):
        cfg = cfg.model_copy(
            update={"store": cfg.store.model_copy(update={"path": paths.state / "nazar.db"})}
        )
    bootstrap.prepare_database(cfg.store.path)
    report.add("database", "ok", str(cfg.store.path))
    for issue in _issues(cfg):
        report.add("config check", issue.level, issue.message)
    if not args.skip_checks:
        asyncio.run(_init_checks(cfg, report))
    if args.json:
        print_json({"steps": report.steps, "suggestions": report.suggestions,
                    "ok": not report.failed})  # fmt: skip
    else:
        print_table(["step", "status", "detail"], report.steps)
        for suggestion in report.suggestions:
            print(f"\nsuggestion: {suggestion}")
        if not report.failed:
            print(
                "\nNext: review /etc/nazar/config.yaml, add your own IPs to "
                "policy.allowlist_cidrs, then try `nazar run --dry-run --once`."
            )
    return 1 if report.failed else 0


async def _init_checks(cfg: Config, report: bootstrap.InitReport) -> None:
    app = build_app(cfg)
    try:
        lapi_ok = await app.lapi.health()
        report.add("crowdsec lapi", "ok" if lapi_ok else "error", cfg.crowdsec.lapi_url)
        health = await app.backend.health()
        if not health.reachable:
            report.add("ollama", "error", f"unreachable at {cfg.analyst.ollama_url}")
            return
        report.add("ollama", "ok", health.version or "")
        if not health.model_present:
            report.add("model", "error", f"run: ollama pull {cfg.analyst.model}")
            return
        report.add("model", "ok", cfg.analyst.model)
        result = await run_eval(app.analyst, load_cases()[:1])
        ok = result.invalid == 0
        latency = result.latencies_ms[0] if result.latencies_ms else None
        detail = f"valid model output in {latency} ms" if ok else "model output was invalid"
        report.add("self-test", "ok" if ok else "warning", detail)
    finally:
        await app.aclose()
