"""Rule package: importing it registers all built-in detectors.

Adding a new rule means dropping a module here and importing it below — nothing
else in the codebase changes. :func:`load_rules` returns instantiated rules,
optionally filtered to the static set (the default, hermetic mode).
"""

from __future__ import annotations

# Dynamic rules live in the `dynamic` package; importing registers them too.
from ..dynamic import drift  # noqa: E402,F401

# Import side-effect: each module registers its rule(s) on import.
from . import (  # noqa: E402,F401  (imported for registration side-effects)
    ai_judge,
    ai_purpose,
    ai_source,
    command_injection,
    excessive_agency,
    hidden_content,
    launch_config,
    pinning,
    secrets,
    shadowing,
    tool_poisoning,
    toxic_flow,
    transport,
    vulnerable_packages,
)
from .base import Rule, RuleKind, register, registered_rule_classes

__all__ = ["Rule", "RuleKind", "register", "load_rules"]


def load_rules(*, include_dynamic: bool = False) -> list[Rule]:
    """Instantiate all registered rules.

    Parameters
    ----------
    include_dynamic:
        When False (default), dynamic rules (those needing a live connection)
        are excluded, keeping scans offline and deterministic.
    """
    rules = [cls() for cls in registered_rule_classes()]
    if include_dynamic:
        return rules
    return [r for r in rules if r.kind is RuleKind.STATIC]
