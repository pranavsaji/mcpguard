"""Rule base class and registry.

A :class:`Rule` is a stateless detector. Each declares its identity and default
severity as class attributes and implements :meth:`Rule.analyze`, which yields
:class:`~mcpguard.models.Finding` objects for a single target.

Rules self-register via the :func:`register` decorator, so adding a detector is
a matter of writing a class and importing its module — the scanner discovers it
automatically. This keeps the engine open for extension and closed for
modification.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from enum import Enum
from typing import ClassVar

from ..context import AnalysisContext
from ..models import Category, Finding, Location, MCPServerSpec, Severity


class RuleKind(Enum):
    """Whether a rule needs a live connection to run."""

    STATIC = "static"
    DYNAMIC = "dynamic"


class Rule(ABC):
    """Base class for all detectors.

    Subclasses set the class-level metadata and implement :meth:`analyze`.
    Use :meth:`finding` to construct findings with the rule's metadata
    pre-populated, so a detector never has to repeat its own id/category.
    """

    id: ClassVar[str]
    title: ClassVar[str]
    category: ClassVar[Category]
    default_severity: ClassVar[Severity]
    mappings: ClassVar[tuple[str, ...]] = ()
    kind: ClassVar[RuleKind] = RuleKind.STATIC

    @abstractmethod
    def analyze(self, target: MCPServerSpec, ctx: AnalysisContext) -> Iterable[Finding]:
        """Yield findings for ``target``. Must not mutate ``target`` or ``ctx``."""
        raise NotImplementedError

    def finding(
        self,
        *,
        location: Location,
        evidence: str,
        remediation: str,
        severity: Severity | None = None,
        title: str | None = None,
        confidence: float = 1.0,
    ) -> Finding:
        """Build a :class:`Finding` carrying this rule's identity."""
        return Finding(
            rule_id=self.id,
            title=title or self.title,
            severity=severity if severity is not None else self.default_severity,
            category=self.category,
            location=location,
            evidence=evidence,
            remediation=remediation,
            mappings=self.mappings,
            confidence=confidence,
        )


# --------------------------------------------------------------------------- #
# Registry                                                                    #
# --------------------------------------------------------------------------- #

_REGISTRY: dict[str, type[Rule]] = {}


def register(cls: type[Rule]) -> type[Rule]:
    """Class decorator that registers a rule by its ``id``.

    Raises if the class is missing required metadata or the id collides — these
    are programming errors we want to surface loudly at import time.
    """
    rule_id = getattr(cls, "id", None)
    if not rule_id:
        raise ValueError(f"{cls.__name__} must define a non-empty `id`")
    for attr in ("title", "category", "default_severity"):
        if getattr(cls, attr, None) is None:
            raise ValueError(f"{cls.__name__} must define `{attr}`")
    if rule_id in _REGISTRY and _REGISTRY[rule_id] is not cls:
        raise ValueError(f"duplicate rule id {rule_id!r} ({cls.__name__})")
    _REGISTRY[rule_id] = cls
    return cls


def registered_rule_classes() -> list[type[Rule]]:
    """All registered rule classes, ordered by id for deterministic runs."""
    return [_REGISTRY[key] for key in sorted(_REGISTRY)]


def clear_registry() -> None:
    """Test helper: empty the registry."""
    _REGISTRY.clear()
