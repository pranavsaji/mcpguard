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
from .models import Category, Finding, Location, MCPServerSpec, Report, Severity
from .rules import Rule, load_rules

if TYPE_CHECKING:
    from .dynamic.connector import Connector

__all__ = ["scan_spec", "scan_specs", "scan_file"]


def scan_spec(
    spec: MCPServerSpec,
    *,
    rules: list[Rule] | None = None,
    include_dynamic: bool = False,
    connector: Connector | None = None,
) -> Report:
    """Scan a single target and return its :class:`Report`.

    When ``include_dynamic`` is set and a ``connector`` is provided, the live
    server is enumerated first so both static metadata rules and the drift rule
    analyze authoritative data. A failed connection degrades gracefully to an
    ``INFO`` finding rather than aborting the scan.
    """
    active = rules if rules is not None else load_rules(include_dynamic=include_dynamic)
    ctx = AnalysisContext(include_dynamic=include_dynamic, connector=connector)
    report = Report(target=spec.name)

    if include_dynamic and connector is not None:
        _connect(spec, ctx, report)

    for rule in active:
        report.extend(_run_rule(rule, spec, ctx))
    return report


def scan_specs(
    specs: list[MCPServerSpec],
    *,
    rules: list[Rule] | None = None,
    include_dynamic: bool = False,
    connector: Connector | None = None,
) -> list[Report]:
    """Scan many targets, sharing one rule set instance across them."""
    active = rules if rules is not None else load_rules(include_dynamic=include_dynamic)
    return [
        scan_spec(spec, rules=active, include_dynamic=include_dynamic, connector=connector)
        for spec in specs
    ]


def scan_file(
    path: str, *, include_dynamic: bool = False, connector: Connector | None = None
) -> list[Report]:
    """Load targets from a config/manifest file and scan each one."""
    from .config_parser import load_targets  # local import avoids a cycle

    specs = load_targets(path)
    return scan_specs(specs, include_dynamic=include_dynamic, connector=connector)


def _connect(spec: MCPServerSpec, ctx: AnalysisContext, report: Report) -> None:
    """Populate ``ctx.live_manifest`` from the connector, isolating failures."""
    assert ctx.connector is not None
    try:
        ctx.live_manifest = ctx.connector.fetch_manifest(spec)
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


def _run_rule(rule: Rule, spec: MCPServerSpec, ctx: AnalysisContext) -> list[Finding]:
    """Execute one rule with error isolation."""
    try:
        return list(rule.analyze(spec, ctx))
    except Exception as exc:  # pragma: no cover - defensive; exercised in tests via stub
        return [
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
