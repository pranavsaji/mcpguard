"""Command-line interface for MCPGuard.

Usage::

    mcpguard scan <config|manifest.json> [--format text|json]
                                         [--min-severity low|medium|high|critical]
                                         [--connect] [--baseline mcpguard.lock.json]
                                         [--no-color]
    mcpguard lock <config.json> [--connect] [-o mcpguard.lock.json]
    mcpguard check-output [FILE] [--hook] [--min-severity ...] [--format text|json]

Exit codes: ``0`` clean (no finding at/above the gate), ``1`` gate failed,
``2`` usage/IO error. This makes ``mcpguard`` a drop-in CI gate. In ``--hook``
mode ``check-output`` always exits 0 and speaks the Claude Code hook protocol.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from typing import TYPE_CHECKING

from . import __version__
from .config_parser import ConfigError
from .models import Severity
from .reporting import FORMATS, render
from .scanner import scan_specs

if TYPE_CHECKING:
    from .ai import AIConfig

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcpguard",
        description="Security scanner for Model Context Protocol (MCP) servers.",
    )
    parser.add_argument("--version", action="version", version=f"mcpguard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan an MCP config or manifest file.")
    scan.add_argument("target", help="Path to an MCP config or manifest JSON file.")
    scan.add_argument(
        "-f", "--format", choices=FORMATS, default="text", help="Output format (default: text)."
    )
    scan.add_argument(
        "-s",
        "--min-severity",
        default="high",
        help="Gate threshold; exit 1 if any finding is at/above this (default: high).",
    )
    scan.add_argument(
        "--connect",
        action="store_true",
        help="Enable dynamic rules that connect to the live server (requires the 'connect' extra).",
    )
    scan.add_argument(
        "--baseline",
        metavar="LOCKFILE",
        help="Reviewed lockfile from `mcpguard lock`; flags drift from it (rug pulls).",
    )
    scan.add_argument("--no-color", action="store_true", help="Disable ANSI color in text output.")
    _add_ai_args(scan)
    scan.set_defaults(func=_cmd_scan)

    lock = sub.add_parser(
        "lock", help="Record the reviewed state of every server (tool pinning / rug-pull baseline)."
    )
    lock.add_argument("target", help="Path to an MCP config JSON file.")
    lock.add_argument(
        "--connect", action="store_true",
        help="Enumerate each live server so its full tool manifest is pinned (recommended).",
    )
    lock.add_argument(
        "-o", "--output", default="mcpguard.lock.json", help="Lockfile path (default: %(default)s)."
    )
    lock.set_defaults(func=_cmd_lock)

    check = sub.add_parser(
        "check-output",
        help="Scan a tool result for indirect prompt injection (file, stdin, or hook event).",
    )
    check.add_argument("file", nargs="?", default="-", help="File to scan (default: stdin).")
    check.add_argument(
        "--hook", action="store_true",
        help="Read a Claude Code PostToolUse event on stdin and answer in the hook protocol.",
    )
    check.add_argument(
        "-s", "--min-severity", default="high", help="Gate threshold (default: high)."
    )
    check.add_argument("-f", "--format", choices=FORMATS, default="text", help="Output format.")
    _add_ai_args(check)
    check.add_argument(
        "--ai-triage", action="store_true",
        help="Let a confident 'benign' AI verdict downgrade keyword-only injection hits to LOW.",
    )
    check.set_defaults(func=_cmd_check_output)

    red = sub.add_parser("redteam", help="Run the red-team suite against the detection layers.")
    red.add_argument("--cases", help="JSONL case file (default: the bundled suite).")
    red.add_argument("--category", action="append", help="Only run these categories (repeatable).")
    red.add_argument("-f", "--format", choices=FORMATS, default="text", help="Output format.")
    red.add_argument(
        "--min-recall", type=float, default=None,
        help="Exit 1 if the combined detection rate on attacks is below this (0-1).",
    )
    red.add_argument(
        "--max-fpr", type=float, default=None,
        help="Exit 1 if the combined false-positive rate on benign cases is above this (0-1).",
    )
    _add_ai_args(red)
    red.set_defaults(func=_cmd_redteam)
    return parser


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        threshold = Severity.parse(args.min_severity)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    try:
        # Import here so a parse/IO error reports cleanly without a traceback.
        from .config_parser import load_targets

        specs = load_targets(args.target)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if not specs:
        print(f"error: no MCP servers found in {args.target!r}", file=sys.stderr)
        return EXIT_ERROR

    connector = None
    if args.connect:
        try:
            from .dynamic.connector import build_connector

            connector = build_connector()
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR

    baseline = None
    if args.baseline:
        from .lockfile import load_lock

        try:
            baseline = load_lock(args.baseline)
        except ConfigError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR

    ai, ai_error = _build_ai(args)
    if ai_error:
        print(f"error: {ai_error}", file=sys.stderr)
        return EXIT_ERROR

    reports = scan_specs(
        specs, include_dynamic=args.connect, connector=connector, baseline=baseline, ai=ai
    )

    color = (not args.no_color) and args.format == "text" and sys.stdout.isatty()
    output = render(
        reports, fmt=args.format, color=color, threshold=threshold, version=__version__
    )
    print(output)

    failed = any(r.failed(threshold) for r in reports)
    return EXIT_FINDINGS if failed else EXIT_OK


def _cmd_lock(args: argparse.Namespace) -> int:
    from .config_parser import load_targets
    from .lockfile import build_lock

    try:
        specs = load_targets(args.target)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    if not specs:
        print(f"error: no MCP servers found in {args.target!r}", file=sys.stderr)
        return EXIT_ERROR

    manifests = {spec.name: spec.manifest for spec in specs}
    if args.connect:
        try:
            from .dynamic.connector import build_connector
            from .scanner import enumerate_live

            live, failures = enumerate_live(specs, build_connector())
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR
        if failures:
            for report in failures:
                for finding in report.findings:
                    print(f"error: {report.target}: {finding.evidence}", file=sys.stderr)
            print("error: not writing a lockfile with unverified servers", file=sys.stderr)
            return EXIT_ERROR
        manifests.update(live)

    document = build_lock(specs, manifests, generator=f"mcpguard {__version__}")
    try:
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, sort_keys=True, ensure_ascii=True)
            handle.write("\n")
    except OSError as exc:
        print(f"error: cannot write {args.output!r}: {exc}", file=sys.stderr)
        return EXIT_ERROR
    pinned = sum(1 for m in manifests.values() if m is not None)
    print(
        f"wrote {args.output}: {len(specs)} server(s), {pinned} with a pinned tool manifest"
        + ("" if pinned == len(specs) else " (use --connect to pin the rest)")
    )
    return EXIT_OK


def _cmd_check_output(args: argparse.Namespace) -> int:
    from .guard import extract_text, hook_response, inspect_output
    from .models import Report

    try:
        threshold = Severity.parse(args.min_severity)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    try:
        if args.file == "-":
            raw = sys.stdin.read()
        else:
            with open(args.file, encoding="utf-8", errors="replace") as handle:
                raw = handle.read()
    except OSError as exc:
        print(f"error: cannot read {args.file!r}: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.hook:
        # A hook must never break the session: malformed input passes silently.
        try:
            event = json.loads(raw)
        except (ValueError, RecursionError):
            return EXIT_OK
        ai, ai_error = _build_ai(args)
        if ai_error:  # never break the session: fall back to the deterministic guard
            print(f"mcpguard: AI judge disabled: {ai_error}", file=sys.stderr)
        response = hook_response(event, threshold, ai) if isinstance(event, dict) else None
        if response is not None:
            print(json.dumps(response))
        return EXIT_OK

    try:
        text = extract_text(json.loads(raw))
    except (ValueError, RecursionError):
        text = raw
    ai, ai_error = _build_ai(args)
    if ai_error:
        print(f"error: {ai_error}", file=sys.stderr)
        return EXIT_ERROR
    report = Report(target=args.file if args.file != "-" else "stdin")
    report.extend(inspect_output(text, origin=report.target, ai=ai))
    color = args.format == "text" and sys.stdout.isatty()
    print(render([report], fmt=args.format, color=color, threshold=threshold, version=__version__))
    return EXIT_FINDINGS if report.failed(threshold) else EXIT_OK


def _add_ai_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("AI judge (optional; keys from env or .env)")
    group.add_argument(
        "--ai", choices=("auto", "jev", "claude", "ensemble"),
        help="Add the AI judge layer: Jev (TYPESAFE_API_KEY), Claude (ANTHROPIC_API_KEY), "
        "both (ensemble), or auto = the best configured.",
    )
    group.add_argument(
        "--ai-threshold", type=float, default=0.8,
        help="Probability at/above which a judge answer becomes a finding (default: 0.8).",
    )
    group.add_argument(
        "--ai-fail-closed", action="store_true",
        help="Treat an unavailable judge as a HIGH finding instead of INFO.",
    )
    group.add_argument(
        "--ai-cache", metavar="PATH",
        help="Persist verdicts by content hash (saves cost; makes CI re-runs repeatable).",
    )


def _build_ai(args: argparse.Namespace) -> tuple[AIConfig | None, str | None]:
    """The AIConfig for ``--ai``, or ``(None, error)``; ``(None, None)`` when not requested."""
    if not getattr(args, "ai", None):
        return None, None
    from .ai import AIConfig, JudgeError, build_judge, find_dotenv, load_dotenv

    if not 0.0 < args.ai_threshold <= 1.0:
        return None, "--ai-threshold must be in (0, 1]"
    env_file = find_dotenv()
    if env_file:
        load_dotenv(env_file)
    try:
        judge = build_judge(args.ai, cache_path=args.ai_cache)
    except JudgeError as exc:
        return None, str(exc)
    return AIConfig(
        judge=judge,
        threshold=args.ai_threshold,
        fail_closed=args.ai_fail_closed,
        triage=bool(getattr(args, "ai_triage", False)),
    ), None


def _cmd_redteam(args: argparse.Namespace) -> int:
    from .redteam import load_cases, render_result, run_suite

    try:
        cases = load_cases(args.cases)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    if args.category:
        cases = [c for c in cases if c.category in set(args.category)]
    if not cases:
        print("error: no red-team cases selected", file=sys.stderr)
        return EXIT_ERROR
    ai, ai_error = _build_ai(args)
    if ai_error:
        print(f"error: {ai_error}", file=sys.stderr)
        return EXIT_ERROR
    result = run_suite(cases, ai=ai)
    print(render_result(result, fmt=args.format))
    failed = bool(result.regressions)
    if args.min_recall is not None and result.recall("combined") < args.min_recall:
        failed = True
    if args.max_fpr is not None and result.false_positive_rate("combined") > args.max_fpr:
        failed = True
    return EXIT_FINDINGS if failed else EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
