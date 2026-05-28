"""End-to-end CLI tests, including the vulnerable/clean fixtures.

These are the acceptance tests: the scanner must flag every planted issue in the
vulnerable fixture and stay silent on the clean one, with correct exit codes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcpguard.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main

FIXTURES = Path(__file__).parent / "fixtures"
VULN = str(FIXTURES / "vulnerable_config.json")
CLEAN = str(FIXTURES / "clean_config.json")


class TestScanVulnerableFixture:
    def test_exit_code_is_findings(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["scan", VULN]) == EXIT_FINDINGS
        capsys.readouterr()  # drain

    def test_json_output_flags_all_expected_rules(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code = main(["scan", VULN, "--format", "json"])
        out = capsys.readouterr().out
        doc = json.loads(out)
        assert code == EXIT_FINDINGS
        assert doc["ok"] is False
        rule_ids = {
            f["rule_id"] for result in doc["results"] for f in result["findings"]
        }
        # poisoning, hidden content, excessive agency, secret, unpinned launch
        assert {"TP01", "TP02", "CAP01", "SEC01", "SUP01"} <= rule_ids

    def test_secret_is_redacted_in_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        main(["scan", VULN, "--format", "json"])
        out = capsys.readouterr().out
        # The full planted key must never appear in output.
        assert "sk-proj-abcdef1234567890abcdef1234567890abcdef12" not in out


class TestScanCleanFixture:
    def test_exits_ok_and_reports_clean(self, capsys: pytest.CaptureFixture[str]) -> None:
        code = main(["scan", CLEAN])
        out = capsys.readouterr().out
        assert code == EXIT_OK
        assert "no findings" in out

    def test_json_ok_true(self, capsys: pytest.CaptureFixture[str]) -> None:
        main(["scan", CLEAN, "--format", "json"])
        doc = json.loads(capsys.readouterr().out)
        assert doc["ok"] is True
        assert doc["summary"]["total_findings"] == 0


class TestThresholdGate:
    def test_lower_threshold_can_flip_clean_to_fail(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The clean fixture has no findings at all, so even 'low' stays OK.
        assert main(["scan", CLEAN, "--min-severity", "low"]) == EXIT_OK
        capsys.readouterr()

    def test_high_only_gate_on_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        # Even gating at 'critical', the vulnerable fixture has a critical finding.
        assert main(["scan", VULN, "--min-severity", "critical"]) == EXIT_FINDINGS
        capsys.readouterr()


class TestCliErrors:
    def test_missing_file_exits_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["scan", "/no/such/file.json"]) == EXIT_ERROR
        assert "error:" in capsys.readouterr().err

    def test_bad_severity_exits_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["scan", CLEAN, "--min-severity", "bogus"]) == EXIT_ERROR
        assert "unknown severity" in capsys.readouterr().err

    def test_invalid_json_exits_error(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("{nope")
        assert main(["scan", str(bad)]) == EXIT_ERROR
        assert "not valid JSON" in capsys.readouterr().err

    def test_no_command_errors(self) -> None:
        with pytest.raises(SystemExit):
            main([])

    def test_version_flag(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as exc:
            main(["--version"])
        assert exc.value.code == 0
        assert "mcpguard" in capsys.readouterr().out


class TestConnectFlag:
    def test_connect_uses_built_connector(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from mcpguard.dynamic import connector as conn_mod
        from mcpguard.models import MCPManifest, MCPTool

        # Inject a recorded connector so --connect needs no live SDK/server.
        live = MCPManifest(tools=(MCPTool(name="x", description="benign"),))
        monkeypatch.setattr(conn_mod, "build_connector", lambda: conn_mod.RecordedConnector(live))

        code = main(["scan", CLEAN, "--connect", "--format", "json"])
        out = capsys.readouterr().out
        doc = json.loads(out)
        # Drift fires: the live server serves a tool the clean baseline omits.
        rule_ids = {f["rule_id"] for r in doc["results"] for f in r["findings"]}
        assert "MAN01" in rule_ids
        assert code == EXIT_FINDINGS

    def test_connect_errors_when_sdk_unavailable(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from mcpguard.dynamic import connector as conn_mod

        def _raise() -> None:
            raise RuntimeError("install mcpguard[connect]")

        monkeypatch.setattr(conn_mod, "build_connector", _raise)
        assert main(["scan", CLEAN, "--connect"]) == EXIT_ERROR
        assert "install mcpguard[connect]" in capsys.readouterr().err
