"""Command-line interface for MCPGuard.

Usage::

    mcpguard scan <config|manifest.json> [--format text|json]
                                         [--min-severity low|medium|high|critical]
                                         [--connect] [--no-color]

Exit codes: ``0`` clean (no finding at/above the gate), ``1`` gate failed,
``2`` usage/IO error. This makes ``mcpguard`` a drop-in CI gate.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from . import __version__
from .config_parser import ConfigError
from .models import Severity
from .reporting import FORMATS, render
from .scanner import scan_specs

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
    scan.add_argument("--no-color", action="store_true", help="Disable ANSI color in text output.")
    scan.set_defaults(func=_cmd_scan)
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

    reports = scan_specs(specs, include_dynamic=args.connect, connector=connector)

    color = (not args.no_color) and args.format == "text" and sys.stdout.isatty()
    output = render(
        reports, fmt=args.format, color=color, threshold=threshold, version=__version__
    )
    print(output)

    failed = any(r.failed(threshold) for r in reports)
    return EXIT_FINDINGS if failed else EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
