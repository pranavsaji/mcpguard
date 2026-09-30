"""Scan orchestration: run the rule set over one or more targets.

The scanner is deliberately thin — it owns *coordination* (which rules run over
which targets, error isolation, report assembly) and delegates *detection* to
rules and *target discovery* to the config parser. A misbehaving rule is
contained: its exception becomes an ``INFO`` finding rather than aborting the
scan, so one bad detector can't deny coverage of the rest.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .context import AnalysisContext
from .models import Category, Finding, Location, MCPManifest, MCPServerSpec, Report, Severity
from .rules import Rule, load_rules

if TYPE_CHECKING:
    from .ai import AIConfig
    from .dynamic.connector import Connector
    from .lockfile import LockEntry

__all__ = ["enumerate_live", "scan_file", "scan_spec", "scan_specs"]


def scan_spec(
    spec: MCPServerSpec,
    *,
    rules: list[Rule] | None = None,
    include_dynamic: bool = False,
    connector: Connector | None = None,
    baseline: dict[str, LockEntry] | None = None,
    ai: AIConfig | None = None,
) -> Report:
    """Scan a single target and return its :class:`Report`.

    When ``include_dynamic`` is set and a ``connector`` is provided, the live
    server is enumerated first so both static metadata rules and the drift rule
    analyze authoritative data. A failed connection degrades gracefully to an
    ``INFO`` finding rather than aborting the scan.
    """
    return scan_specs(
        [spec], rules=rules, include_dynamic=include_dynamic, connector=connector,
        baseline=baseline, ai=ai,
    )[0]


def scan_specs(
    specs: list[MCPServerSpec],
    *,
    rules: list[Rule] | None = None,
    include_dynamic: bool = False,
    connector: Connector | None = None,
    baseline: dict[str, LockEntry] | None = None,
    ai: AIConfig | None = None,
) -> list[Report]:
    """Scan many targets from one config, sharing one rule set instance.

    Runs in two phases: every server is enumerated first (when connecting), so
    cross-server rules — tool shadowing, toxic flow — see the whole config's
    effective manifests, not just the servers scanned so far.
    """
    active = rules if rules is not None else load_rules(include_dynamic=include_dynamic)
    reports = [Report(target=spec.name) for spec in specs]
    live: list[MCPManifest | None] = [None] * len(specs)
    if include_dynamic and connector is not None:
        for index, spec in enumerate(specs):
            live[index] = _connect(spec, connector, reports[index])

    peers = tuple(
        (spec, manifest if manifest is not None else spec.manifest)
        for spec, manifest in zip(specs, live)
    )
    for spec, manifest, report in zip(specs, live, reports):
        ctx = AnalysisContext(
            include_dynamic=include_dynamic,
            connector=connector,
            live_manifest=manifest,
            peers=peers,
            baseline=baseline,
            ai=ai,
        )
        errors_before = len(ai.errors) if ai is not None else 0
        for rule in active:
            report.extend(_run_rule(rule, spec, ctx))
        if ai is not None and len(ai.errors) > errors_before:
            report.add(_ai_unavailable(spec, ai, ai.errors[errors_before:]))
    return reports


def scan_file(
    path: str,
    *,
    include_dynamic: bool = False,
    connector: Connector | None = None,
    baseline: dict[str, LockEntry] | None = None,
    ai: AIConfig | None = None,
) -> list[Report]:
    """Load targets from a config/manifest file and scan each one."""
    from .config_parser import load_targets  # local import avoids a cycle

    specs = load_targets(path)
    return scan_specs(
        specs, include_dynamic=include_dynamic, connector=connector, baseline=baseline, ai=ai
    )


def enumerate_live(
    specs: list[MCPServerSpec], connector: Connector
) -> tuple[dict[str, MCPManifest | None], list[Report]]:
    """Enumerate every server live; return manifests by name plus failure reports."""
    manifests: dict[str, MCPManifest | None] = {}
    failures: list[Report] = []
    for spec in specs:
        report = Report(target=spec.name)
        manifests[spec.name] = _connect(spec, connector, report)
        if report.findings:
            failures.append(report)
    return manifests, failures


def _ai_unavailable(spec: MCPServerSpec, ai: AIConfig, errors: list[str]) -> Finding:
    """One finding per target when the judge failed: visible, never a silent pass."""
    unique = list(dict.fromkeys(errors))
    return Finding(
        rule_id="AI00",
        title="AI judge degraded or unavailable (semantic checks may be incomplete)",
        severity=Severity.HIGH if ai.fail_closed else Severity.INFO,
        category=Category.TOOL_POISONING,
        location=Location(server=spec.name),
        evidence=f"{len(errors)} failed judgement(s): {'; '.join(unique[:2])}"[:300],
        remediation=(
            "Check the judge's API key, quota, and network. Deterministic rules still ran; "
            "use --ai-fail-closed to fail the gate when the AI layer can't answer."
        ),
        confidence=0.0,
    )


def _connect(spec: MCPServerSpec, connector: Connector, report: Report) -> MCPManifest | None:
    """Enumerate ``spec`` live, isolating failures as an ``INFO`` finding."""
    try:
        return connector.fetch_manifest(spec)
    except Exception as exc:
        report.add(
            Finding(
                rule_id="CONNECT",
                title="Live connection failed (dynamic rules skipped)",
                severity=Severity.INFO,
                category=Category.MANIFEST_DRIFT,
                location=Location(server=spec.name),
                evidence=f"{type(exc).__name__}: {exc}",
                remediation="Verify the server launches locally, then re-run with --connect.",
                confidence=0.0,
            )
        )
        return None


def _run_rule(rule: Rule, spec: MCPServerSpec, ctx: AnalysisContext) -> list[Finding]:
    """Execute one rule with error isolation.

    Findings are collected one at a time so that a crash part-way through (e.g.
    on hostile input) keeps everything the rule reported before it.
    """
    findings: list[Finding] = []
    try:
        for finding in rule.analyze(spec, ctx):
            findings.append(finding)  # noqa: PERF402 - a crash must keep partial results
        return findings
    except Exception as exc:  # pragma: no cover - defensive; exercised in tests via stub
        return findings + [
            Finding(
                rule_id=getattr(rule, "id", "UNKNOWN"),
                title="Rule raised an exception (skipped)",
                severity=Severity.INFO,
                category=Category.SUPPLY_CHAIN,
                location=Location(server=spec.name),
                evidence=f"{type(exc).__name__}: {exc}",
                remediation="This is an MCPGuard bug; please report it.",
                confidence=0.0,
            )
        ]
