"""The red-team suite as tests: every case's deterministic outcome is pinned.

A change to any detector that flips a case — a new miss *or* a new false
positive — fails here with the case id, so detection quality can't silently
drift. The AI layer is exercised with a fake judge (live runs: ``test_ai_live.py``).
"""

from __future__ import annotations

import json

import pytest

from mcpguard.ai import AIConfig, Verdict
from mcpguard.ai.base import QUESTIONS
from mcpguard.cli import EXIT_FINDINGS, EXIT_OK, main
from mcpguard.redteam import RELEVANT_RULES, load_cases, render_result, run_suite

CASES = load_cases()


@pytest.mark.parametrize("case", CASES, ids=[c.id for c in CASES])
def test_static_outcome_is_pinned(case) -> None:
    result = run_suite([case]).results[0]
    assert result.static == case.expect_static, (
        f"{case.id} ({case.technique}): deterministic layer now "
        f"{'detects' if result.static else 'misses'} it — {result.evidence or 'no finding'}"
    )


def test_suite_shape() -> None:
    assert len(CASES) >= 120
    assert {c.surface for c in CASES} == set(RELEVANT_RULES)
    assert sum(not c.is_attack for c in CASES) >= 25  # hard negatives, not just attacks
    assert all(c.expect_static is not None for c in CASES)


def test_known_static_limits_are_the_semantic_cases() -> None:
    """What the deterministic layer misses should be paraphrase / language / naming cases."""
    missed = {c.id for c in CASES if c.is_attack and c.expect_static is False}
    assert all(
        c.startswith(("SEM-", "FSP-008", "SHD-005", "JUD-", "IPI-", "FLW-003", "SRC-", "PUR-"))
        for c in missed
    )
    assert {f"SEM-{i:03d}" for i in range(1, 11)} <= missed


def test_deterministic_baseline_metrics() -> None:
    result = run_suite(CASES)
    assert result.recall("static") >= 0.65  # the AI-only cases (SEM-, SRC-, PUR-) pull this down by design
    assert result.false_positive_rate("static") <= 0.10
    assert result.regressions == []


class _OracleJudge:
    """Flags everything: exercises attribution of AI-only detections and FP accounting."""

    name = "oracle"

    def judge(self, surface: str, content: object) -> Verdict:
        return Verdict({q: 0.99 for q in QUESTIONS[surface]}, judge=self.name)


def test_ai_layer_accounting() -> None:
    subset = [c for c in CASES if c.id in {"SEM-001", "IPI-008", "BEN-M01", "TP-001", "FLW-003"}]
    result = run_suite(subset, ai=AIConfig(judge=_OracleJudge()))
    by_id = {r.case.id: r for r in result.results}
    assert by_id["SEM-001"].static is False and by_id["SEM-001"].ai is True and by_id["SEM-001"].combined
    assert by_id["IPI-008"].ai is True
    assert by_id["FLW-003"].ai is True  # AI-inferred roles complete the trifecta
    assert by_id["BEN-M01"].combined is True  # an over-eager judge shows up as a false positive
    assert result.false_positive_rate("ai") == 1.0


def test_render_text_and_json() -> None:
    result = run_suite([c for c in CASES if c.category == "tool_poisoning"])
    text = render_result(result)
    assert "tool_poisoning" in text and "TOTAL" in text
    doc = json.loads(render_result(result, fmt="json"))
    assert doc["attacks"] == 10 and doc["recall_static"] == 1.0 and doc["recall_ai"] is None


def test_cli_redteam(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["redteam", "--category", "launch_config"]) == EXIT_OK
    assert main(["redteam", "--category", "semantic_evasion", "--min-recall", "0.5"]) == EXIT_FINDINGS
    capsys.readouterr()
