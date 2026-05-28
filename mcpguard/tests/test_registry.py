"""Tests for the rule registry guards and rule loading."""

from __future__ import annotations

from collections.abc import Iterable

import pytest

import mcpguard.rules.base as base
from mcpguard.context import AnalysisContext
from mcpguard.models import Category, Finding, Location, MCPServerSpec, Severity
from mcpguard.rules import load_rules
from mcpguard.rules.base import (
    Rule,
    RuleKind,
    register,
    registered_rule_classes,
)


@pytest.fixture(autouse=True)
def _isolate_registry():
    """Snapshot and restore the global rule registry around each test.

    These tests register throwaway rules; without isolation they would leak into
    every other test's rule set.
    """
    snapshot = dict(base._REGISTRY)
    try:
        yield
    finally:
        base._REGISTRY.clear()
        base._REGISTRY.update(snapshot)


class TestRegisterGuards:
    def test_missing_id_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-empty `id`"):

            @register
            class _NoId(Rule):  # type: ignore[unused-ignore]
                title = "x"
                category = Category.SECRETS
                default_severity = Severity.LOW

                def analyze(self, target, ctx):  # noqa: ANN001
                    return []

    def test_missing_metadata_rejected(self) -> None:
        with pytest.raises(ValueError, match="must define `category`"):

            @register
            class _NoCategory(Rule):
                id = "NOCAT"
                title = "x"
                default_severity = Severity.LOW

                def analyze(self, target, ctx):  # noqa: ANN001
                    return []

    def test_duplicate_id_rejected(self) -> None:
        @register
        class _First(Rule):
            id = "DUP_TEST"
            title = "first"
            category = Category.SECRETS
            default_severity = Severity.LOW

            def analyze(self, target, ctx):  # noqa: ANN001
                return []

        with pytest.raises(ValueError, match="duplicate rule id"):

            @register
            class _Second(Rule):
                id = "DUP_TEST"
                title = "second"
                category = Category.SECRETS
                default_severity = Severity.LOW

                def analyze(self, target, ctx):  # noqa: ANN001
                    return []

    def test_reregistering_same_class_is_idempotent(self) -> None:
        class _Idem(Rule):
            id = "IDEM_TEST"
            title = "x"
            category = Category.SECRETS
            default_severity = Severity.LOW

            def analyze(self, target, ctx):  # noqa: ANN001
                return []

        register(_Idem)
        register(_Idem)  # must not raise
        assert _Idem in registered_rule_classes()


class TestLoadRules:
    def test_builtin_rules_present_and_ordered(self) -> None:
        ids = [r.id for r in load_rules()]
        assert ids == sorted(ids)  # deterministic order
        assert {"TP01", "TP02", "CAP01", "CMD01", "SEC01", "SUP01"} <= set(ids)

    def test_static_only_by_default(self) -> None:
        @register
        class _Dyn(Rule):
            id = "DYN_TEST"
            title = "x"
            category = Category.RUG_PULL
            default_severity = Severity.LOW
            kind = RuleKind.DYNAMIC

            def analyze(self, target: MCPServerSpec, ctx: AnalysisContext) -> Iterable[Finding]:
                yield self.finding(location=Location(server="s"), evidence="e", remediation="r")

        assert "DYN_TEST" not in {r.id for r in load_rules()}
        assert "DYN_TEST" in {r.id for r in load_rules(include_dynamic=True)}
