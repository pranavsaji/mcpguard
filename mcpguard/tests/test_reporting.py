"""Tests for the text and JSON reporters."""

from __future__ import annotations

import json

import pytest

from mcpguard.models import Category, Finding, Location, Report, Severity
from mcpguard.reporting import render
from mcpguard.reporting.json_reporter import format_json
from mcpguard.reporting.text import format_text


def _report(target: str, *severities: Severity) -> Report:
    report = Report(target=target)
    for i, sev in enumerate(severities):
        report.add(
            Finding(
                rule_id=f"R{i}",
                title=f"finding {i}",
                severity=sev,
                category=Category.SECRETS,
                location=Location(server=target, tool="t"),
                evidence="evidence text",
                remediation="do the fix",
                mappings=("OWASP-LLM01",),
            )
        )
    return report


class TestTextReporter:
    def test_renders_findings_and_fail_verdict(self) -> None:
        out = format_text([_report("srv", Severity.CRITICAL, Severity.LOW)], threshold=Severity.HIGH)
        assert "server: srv" in out
        assert "CRITICAL" in out
        assert "OWASP-LLM01" in out
        assert "FAIL" in out

    def test_clean_report_passes(self) -> None:
        out = format_text([_report("srv")], threshold=Severity.HIGH)
        assert "no findings" in out
        assert "PASS" in out

    def test_color_adds_ansi_codes(self) -> None:
        out = format_text([_report("srv", Severity.HIGH)], color=True, threshold=Severity.HIGH)
        assert "\033[" in out

    def test_no_color_is_plain(self) -> None:
        out = format_text([_report("srv", Severity.HIGH)], color=False)
        assert "\033[" not in out

    def test_threshold_controls_verdict(self) -> None:
        report = [_report("srv", Severity.MEDIUM)]
        assert "FAIL" in format_text(report, threshold=Severity.MEDIUM)
        assert "PASS" in format_text(report, threshold=Severity.HIGH)


class TestJsonReporter:
    def test_schema_and_gate(self) -> None:
        doc = json.loads(
            format_json([_report("srv", Severity.HIGH)], threshold=Severity.HIGH, version="9.9.9")
        )
        assert doc["tool"] == "mcpguard"
        assert doc["version"] == "9.9.9"
        assert doc["ok"] is False
        assert doc["summary"]["targets"] == 1
        assert doc["summary"]["total_findings"] == 1
        assert doc["results"][0]["target"] == "srv"

    def test_ok_true_when_below_threshold(self) -> None:
        doc = json.loads(format_json([_report("srv", Severity.LOW)], threshold=Severity.HIGH))
        assert doc["ok"] is True

    def test_aggregates_across_targets(self) -> None:
        reports = [_report("a", Severity.HIGH), _report("b", Severity.HIGH, Severity.LOW)]
        doc = json.loads(format_json(reports, threshold=Severity.HIGH))
        assert doc["summary"]["targets"] == 2
        assert doc["summary"]["total_findings"] == 3
        assert doc["summary"]["by_severity"]["high"] == 2


class TestRenderDispatch:
    def test_unknown_format_raises(self) -> None:
        with pytest.raises(ValueError, match="unknown format"):
            render([_report("srv")], fmt="xml")

    def test_dispatch_text_and_json(self) -> None:
        reports = [_report("srv", Severity.HIGH)]
        assert "server: srv" in render(reports, fmt="text")
        assert json.loads(render(reports, fmt="json"))["tool"] == "mcpguard"
