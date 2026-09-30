"""Command-line interface for MCPGuard.

Usage::

    mcpguard scan <config|manifest.json> [--format text|json]
                                         [--min-severity low|medium|high|critical]
                                         [--connect] [--baseline mcpguard.lock.json]
                                         [--no-color]
    mcpguard lock <config.json> [--connect] [-o mcpguard.lock.json]
    mcpguard check-output [FILE] [--hook] [--min-severity ...] [--format text|json]
    mcpguard check-call [FILE] --policy POLICY [--hook] [--user U] [--format text|json]
    mcpguard policy-test POLICY SCENARIOS.jsonl [--format text|json]

Exit codes: ``0`` clean (no finding at/above the gate), ``1`` gate failed,
``2`` usage/IO error. This makes ``mcpguard`` a drop-in CI gate. In ``--hook``
mode ``check-output`` and ``check-call`` always exit 0 and speak the Claude Code
hook protocol; ``check-call`` otherwise exits 0 on allow and 1 on ask / deny.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import signal
import sys
import threading
from collections.abc import Iterator, Sequence
from typing import TYPE_CHECKING

from . import __version__
from .config_parser import ConfigError
from .models import Severity
from .reporting import FORMATS, render
from .scanner import scan_specs

if TYPE_CHECKING:
    from .ai import AIConfig
    from .dynamic.oauth import AuthMetadata

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
    check.add_argument(
        "--state-dir", metavar="DIR",
        help="Hook mode: where a hit is recorded as session taint for `check-call` (default: "
        "$MCPGUARD_STATE_DIR, or ~/.mcpguard/sessions — the same place check-call reads).",
    )
    check.add_argument(
        "--no-state", action="store_true", help="Hook mode: don't record session taint."
    )
    check.set_defaults(func=_cmd_check_output)

    call = sub.add_parser(
        "check-call",
        help="Decide on a proposed tool call against a policy, before it runs (PreToolUse hook).",
    )
    call.add_argument("file", nargs="?", default="-", help="Call / hook event JSON (default: stdin).")
    call.add_argument(
        "--policy", metavar="POLICY", help="Policy JSON (default: $MCPGUARD_POLICY)."
    )
    call.add_argument(
        "--hook", action="store_true",
        help="Read a Claude Code PreToolUse event on stdin and answer in the hook protocol.",
    )
    call.add_argument("--user", help="The end user the call is made for (default: $MCPGUARD_USER).")
    call.add_argument("--server", default="", help="Server name when the input doesn't carry one.")
    call.add_argument("--state-dir", metavar="DIR", help="Session state directory (default: "
                      "policy session.state_dir, $MCPGUARD_STATE_DIR, or ~/.mcpguard/sessions).")
    call.add_argument("--audit-log", metavar="PATH", help="Append each decision as a JSON line.")
    call.add_argument(
        "--timeout", type=float, default=10.0,
        help="Seconds to decide before failing closed (default: %(default)s).",
    )
    call.add_argument(
        "--fail-open", action="store_true",
        help="If the policy can't be loaded, allow instead of deny (not recommended).",
    )
    call.add_argument("-f", "--format", choices=FORMATS, default="text", help="Output format.")
    call.set_defaults(func=_cmd_check_call)

    ptest = sub.add_parser(
        "policy-test",
        help="Replay hostile scenarios through a policy; fail if a forbidden call would run.",
    )
    ptest.add_argument("policy", help="Policy JSON.")
    ptest.add_argument("scenarios", help="Scenario JSONL file.")
    ptest.add_argument("-f", "--format", choices=FORMATS, default="text", help="Output format.")
    ptest.set_defaults(func=_cmd_policy_test)

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

    from .context import AnalysisContext
    from .egress import egress_hosts

    manifests = {spec.name: spec.manifest for spec in specs}
    source_ctx = AnalysisContext()
    egress = {spec.name: egress_hosts(spec, source_ctx) for spec in specs if spec.source_path}
    auth: dict[str, AuthMetadata | None] = {}
    if args.connect:
        try:
            from .dynamic.connector import build_connector
            from .scanner import discover_auth, enumerate_live

            connector = build_connector()
            live, failures = enumerate_live(specs, connector)
            auth = {spec.name: discover_auth(spec, connector) for spec in specs}
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

    document = build_lock(
        specs, manifests, generator=f"mcpguard {__version__}", egress=egress, auth=auth
    )
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
            if not args.no_state:
                _record_taint(event, args.state_dir)
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


def _record_taint(event: object, state_dir: str | None) -> None:
    """Mark the session as having read injected instructions (read by `check-call`).

    The label names the tool only — output text stays out of state files and audit logs.
    """
    if not isinstance(event, dict) or not event.get("session_id"):
        return
    from .policy import parse_call
    from .session import FileSessionStore, default_state_dir

    try:
        call = parse_call(event)
        store = FileSessionStore(state_dir or default_state_dir())
        with store.transaction(str(event["session_id"])) as state:
            state.taint.append(f"{call.name}: suspected prompt injection in its output")
    except Exception as exc:  # noqa: BLE001 - the block decision is already printed; never undo it
        print(f"mcpguard: could not record session taint: {exc}", file=sys.stderr)


def _cmd_check_call(args: argparse.Namespace) -> int:
    """Any failure to decide — including a bug or a timeout — resolves through
    :func:`_call_failure`: in hook mode a deny, never a traceback the client ignores."""
    try:
        with _deadline(args.timeout):
            return _check_call(args)
    except Exception as exc:  # noqa: BLE001 - an escaped exception would fail open
        return _call_failure(args, f"internal error ({type(exc).__name__}: {exc})")


@contextlib.contextmanager
def _deadline(seconds: float) -> Iterator[None]:
    """Raise :class:`TimeoutError` after ``seconds`` (POSIX main thread; else no limit).

    A pathological pattern in a server-authored schema must not hold the hook until the
    client gives up on it — clients treat a hook timeout as "proceed".
    """
    usable = (
        seconds > 0 and hasattr(signal, "setitimer")
        and threading.current_thread() is threading.main_thread()
    )
    if not usable:
        yield
        return

    def _expire(signum: int, frame: object) -> None:
        raise TimeoutError(f"no decision within {seconds:g}s")

    previous = signal.signal(signal.SIGALRM, _expire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _check_call(args: argparse.Namespace) -> int:
    from .policy import ALLOW, PolicyError, audit, evaluate, load_policy, parse_call
    from .session import FileSessionStore, default_state_dir

    policy_path = args.policy or os.environ.get("MCPGUARD_POLICY")
    user = args.user or os.environ.get("MCPGUARD_USER") or None
    try:
        if args.file == "-":
            raw = sys.stdin.read()
        else:
            with open(args.file, encoding="utf-8") as handle:
                raw = handle.read()
    except OSError as exc:
        return _call_failure(args, f"cannot read {args.file!r}: {exc}")
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        return _call_failure(args, f"the call is not valid JSON: {exc}")
    if not isinstance(data, dict):
        return _call_failure(args, "the call must be a JSON object")
    if not policy_path:
        return _call_failure(args, "no policy given (use --policy or set MCPGUARD_POLICY)")
    try:
        policy = load_policy(policy_path)
    except PolicyError as exc:
        return _call_failure(args, str(exc))

    call = parse_call(data, server=args.server, user=user)
    if call.session_id:
        store = FileSessionStore(args.state_dir or policy.state_dir or default_state_dir())
        try:
            with store.transaction(call.session_id) as state:
                decision = evaluate(policy, call, state)
        except OSError as exc:
            from .policy import Decision, Reason

            decision = Decision(policy.fail, call, [Reason(
                "error", policy.fail, f"session state unavailable ({exc}); failing {policy.fail}",
            )])
    else:
        decision = evaluate(policy, call)

    audit_path = args.audit_log or policy.audit_log
    if audit_path:
        try:
            audit(decision, audit_path)
        except OSError as exc:
            print(f"mcpguard: audit log write failed: {exc}", file=sys.stderr)

    if args.hook:
        # Allow defers to the client's own permission flow: a policy gate only restricts.
        if decision.decision != ALLOW:
            print(json.dumps(_pretool_output(decision.decision, decision.message())))
        return EXIT_OK
    if args.format == "json":
        print(json.dumps(decision.to_dict(), indent=2))
    else:
        print(decision.message())
    return EXIT_OK if decision.decision == ALLOW else EXIT_FINDINGS


def _pretool_output(decision: str, reason: str) -> dict[str, object]:
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": decision, "permissionDecisionReason": reason,
    }}


def _call_failure(args: argparse.Namespace, message: str) -> int:
    """The gate could not decide. In hook mode that is a decision too: fail closed."""
    if args.hook:
        if not args.fail_open:
            print(json.dumps(_pretool_output(
                "deny", f"MCPGuard could not evaluate this call ({message}); failing closed.",
            )))
        else:
            print(f"mcpguard: {message}; failing open", file=sys.stderr)
        return EXIT_OK
    print(f"error: {message}", file=sys.stderr)
    return EXIT_ERROR


def _cmd_policy_test(args: argparse.Namespace) -> int:
    from .policy import PolicyError, load_policy
    from .policytest import load_scenarios, render, run_scenarios

    try:
        policy = load_policy(args.policy)
        scenarios = load_scenarios(args.scenarios)
    except (PolicyError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    result = run_scenarios(policy, scenarios)
    print(render(result, fmt=args.format))
    return EXIT_FINDINGS if result.failures else EXIT_OK


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
