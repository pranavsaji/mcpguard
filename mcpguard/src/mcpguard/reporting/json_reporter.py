"""Machine-readable JSON reporter (stable schema for CI consumption)."""

from __future__ import annotations

import json

from ..models import Report, Severity


def format_json(
    reports: list[Report],
    *,
    threshold: Severity = Severity.HIGH,
    version: str = "0.0.0",
    indent: int | None = 2,
) -> str:
    """Render ``reports`` as a single JSON document.

    The top-level ``ok`` field is the CI gate signal: ``false`` when any target
    has a finding at or above ``threshold``.
    """
    failed = any(r.failed(threshold) for r in reports)
    totals: dict[str, int] = {}
    for report in reports:
        for sev, count in report.counts().items():
            totals[sev] = totals.get(sev, 0) + count

    document = {
        "tool": "mcpguard",
        "version": version,
        "gate": str(threshold),
        "ok": not failed,
        "summary": {
            "targets": len(reports),
            "total_findings": sum(len(r.findings) for r in reports),
            "by_severity": totals,
        },
        "results": [report.to_dict() for report in reports],
    }
    return json.dumps(document, indent=indent, sort_keys=False)
