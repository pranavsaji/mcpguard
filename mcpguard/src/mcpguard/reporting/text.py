"""Human-readable terminal reporter (stdlib only, optional ANSI color)."""

from __future__ import annotations

from ..models import Report, Severity

_RESET = "\033[0m"
_SEVERITY_COLOR: dict[Severity, str] = {
    Severity.CRITICAL: "\033[1;37;41m",  # white on red
    Severity.HIGH: "\033[31m",  # red
    Severity.MEDIUM: "\033[33m",  # yellow
    Severity.LOW: "\033[36m",  # cyan
    Severity.INFO: "\033[90m",  # grey
}


def _paint(text: str, color: str, *, enabled: bool) -> str:
    return f"{color}{text}{_RESET}" if enabled else text


def _summary_line(reports: list[Report], threshold: Severity, *, color: bool) -> str:
    totals: dict[str, int] = {}
    total = 0
    failed = False
    for report in reports:
        total += len(report.findings)
        failed = failed or report.failed(threshold)
        for sev, count in report.counts().items():
            totals[sev] = totals.get(sev, 0) + count
    breakdown = ", ".join(
        f"{totals[str(s)]} {s}" for s in reversed(Severity) if str(s) in totals
    )
    verdict = "FAIL" if failed else "PASS"
    verdict = _paint(
        verdict,
        _SEVERITY_COLOR[Severity.HIGH] if failed else "\033[32m",
        enabled=color,
    )
    tail = f" — {breakdown}" if breakdown else ""
    return (
        f"Summary: {len(reports)} target(s), {total} finding(s){tail} "
        f"— {verdict} (gate >= {threshold})"
    )


def format_text(
    reports: list[Report],
    *,
    color: bool = False,
    threshold: Severity = Severity.HIGH,
) -> str:
    """Render ``reports`` as a readable report. ``threshold`` drives PASS/FAIL."""
    lines: list[str] = ["MCPGuard scan — %d target(s)" % len(reports), ""]

    for report in reports:
        findings = report.sorted()
        header = _paint(f"● server: {report.target}", "\033[1m", enabled=color)
        lines.append(header)
        if not findings:
            lines.append(_paint("  no findings ✓", "\033[32m", enabled=color))
            lines.append("")
            continue
        for finding in findings:
            sev = finding.severity
            badge = _paint(f"{str(sev).upper():<8}", _SEVERITY_COLOR[sev], enabled=color)
            lines.append(f"  {badge} {finding.rule_id}  {finding.title}")
            lines.append(f"           └ {finding.location}")
            lines.append(f"           evidence: {finding.evidence}")
            if finding.mappings:
                lines.append(f"           refs: {', '.join(finding.mappings)}")
            lines.append(f"           fix: {finding.remediation}")
        counts = ", ".join(f"{v} {k}" for k, v in report.counts().items())
        lines.append(f"  {len(findings)} finding(s): {counts}")
        lines.append("")

    lines.append(_summary_line(reports, threshold, color=color))
    return "\n".join(lines)
