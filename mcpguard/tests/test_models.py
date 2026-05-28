"""Unit tests for the core domain models."""

from __future__ import annotations

import json

import pytest

from mcpguard.models import (
    Category,
    Finding,
    Location,
    MCPManifest,
    MCPServerSpec,
    MCPTool,
    Report,
    Severity,
    Transport,
)


class TestSeverity:
    def test_ordering(self) -> None:
        assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL

    @pytest.mark.parametrize(
        "raw,expected",
        [("high", Severity.HIGH), ("CRITICAL", Severity.CRITICAL), (" low ", Severity.LOW)],
    )
    def test_parse_accepts_case_and_whitespace(self, raw: str, expected: Severity) -> None:
        assert Severity.parse(raw) is expected

    def test_parse_passthrough(self) -> None:
        assert Severity.parse(Severity.MEDIUM) is Severity.MEDIUM

    def test_parse_invalid_raises_with_help(self) -> None:
        with pytest.raises(ValueError, match="unknown severity"):
            Severity.parse("nope")

    def test_str_is_lowercase(self) -> None:
        assert str(Severity.HIGH) == "high"


class TestFinding:
    def _make(self, **overrides: object) -> Finding:
        base: dict[str, object] = dict(
            rule_id="TP01",
            title="Tool poisoning",
            severity=Severity.HIGH,
            category=Category.TOOL_POISONING,
            location=Location(server="s", tool="t", field="description"),
            evidence="ignore previous instructions",
            remediation="review the description",
            mappings=("OWASP-LLM01",),
        )
        base.update(overrides)
        return Finding(**base)  # type: ignore[arg-type]

    def test_to_dict_roundtrips_through_json(self) -> None:
        finding = self._make()
        blob = json.dumps(finding.to_dict())
        loaded = json.loads(blob)
        assert loaded["rule_id"] == "TP01"
        assert loaded["severity"] == "high"
        assert loaded["category"] == "tool_poisoning"
        assert loaded["location"] == {"server": "s", "tool": "t", "field": "description"}
        assert loaded["mappings"] == ["OWASP-LLM01"]

    def test_is_hashable_and_frozen(self) -> None:
        finding = self._make()
        assert finding in {finding}
        with pytest.raises(Exception):
            finding.severity = Severity.LOW  # type: ignore[misc]

    @pytest.mark.parametrize("bad", [-0.1, 1.1, 2.0])
    def test_confidence_bounds_enforced(self, bad: float) -> None:
        with pytest.raises(ValueError, match="confidence"):
            self._make(confidence=bad)

    def test_empty_rule_id_rejected(self) -> None:
        with pytest.raises(ValueError, match="rule_id"):
            self._make(rule_id="")


class TestLocation:
    def test_str_renders_known_parts_only(self) -> None:
        assert str(Location(server="srv", tool="exec")) == "server=srv tool=exec"
        assert str(Location(path="server.py", line=12)) == "server.py:12"
        assert str(Location()) == "<unknown>"

    def test_to_dict_omits_none(self) -> None:
        assert Location(server="s").to_dict() == {"server": "s"}


class TestReport:
    def _finding(self, rule_id: str, sev: Severity) -> Finding:
        return Finding(
            rule_id=rule_id,
            title=rule_id,
            severity=sev,
            category=Category.SECRETS,
            location=Location(server="s"),
            evidence="e",
            remediation="r",
        )

    def test_sorted_orders_by_severity_then_rule(self) -> None:
        report = Report(target="s")
        report.add(self._finding("B", Severity.LOW))
        report.add(self._finding("A", Severity.CRITICAL))
        report.add(self._finding("C", Severity.CRITICAL))
        ordered = [f.rule_id for f in report.sorted()]
        assert ordered == ["A", "C", "B"]  # criticals first, ties by rule id

    def test_filter_and_max_and_counts(self) -> None:
        report = Report(target="s")
        report.extend([self._finding("A", Severity.LOW), self._finding("B", Severity.HIGH)])
        assert report.max_severity is Severity.HIGH
        assert report.counts() == {"low": 1, "high": 1}
        assert [f.rule_id for f in report.filter(Severity.MEDIUM)] == ["B"]

    def test_empty_report_has_no_max(self) -> None:
        assert Report(target="s").max_severity is None

    def test_gate_semantics(self) -> None:
        report = Report(target="s")
        report.add(self._finding("A", Severity.MEDIUM))
        assert report.failed(Severity.MEDIUM) is True
        assert report.exit_code(Severity.MEDIUM) == 1
        assert report.failed(Severity.HIGH) is False
        assert report.exit_code(Severity.HIGH) == 0

    def test_to_json_is_valid_and_structured(self) -> None:
        report = Report(target="srv")
        report.add(self._finding("A", Severity.HIGH))
        doc = json.loads(report.to_json())
        assert doc["target"] == "srv"
        assert doc["summary"]["total"] == 1
        assert doc["summary"]["max_severity"] == "high"
        assert len(doc["findings"]) == 1


class TestMCPModels:
    def test_tool_parameter_descriptions_extracted(self) -> None:
        tool = MCPTool(
            name="fetch",
            description="Fetch a URL",
            input_schema={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "the target URL"},
                    "timeout": {"type": "number"},  # no description -> skipped
                },
            },
        )
        assert tool.parameter_descriptions == {"url": "the target URL"}

    def test_tool_parameter_descriptions_handles_malformed_schema(self) -> None:
        assert MCPTool(name="x", input_schema={"properties": "nope"}).parameter_descriptions == {}
        assert MCPTool(name="x").parameter_descriptions == {}

    def test_server_command_line(self) -> None:
        spec = MCPServerSpec(
            name="fs",
            transport=Transport.STDIO,
            command="npx",
            args=("-y", "@modelcontextprotocol/server-filesystem"),
        )
        assert spec.command_line == "npx -y @modelcontextprotocol/server-filesystem"

    def test_server_command_line_args_only(self) -> None:
        assert MCPServerSpec(name="x", args=("a", "b")).command_line == "a b"

    def test_manifest_defaults_are_immutable_tuples(self) -> None:
        manifest = MCPManifest()
        assert manifest.tools == ()
        assert isinstance(manifest.tools, tuple)
