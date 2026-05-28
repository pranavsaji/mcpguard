"""CAP01 — excessive agency / dangerous tool capabilities.

The top risk in the OWASP Top 10 for Agentic Applications is *excessive agency*:
agents wielding more power than their task needs. This rule infers a tool's
capability from its name and description and flags high-blast-radius powers
(code execution, shell, filesystem writes, arbitrary network, credential access,
database mutation) so they can be scoped down or gated behind human approval.

Maps to OWASP Agentic "Excessive Agency".
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator

from ..context import AnalysisContext
from ..models import Category, Finding, Location, MCPServerSpec, Severity
from ..patterns import CAPABILITY_KEYWORDS, DANGEROUS_NAME_TOKENS
from .base import Rule, register

_WORD_RE = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> set[str]:
    """Lowercased alphanumeric tokens (splits snake_case, camelCase, kebab)."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text)
    return set(_WORD_RE.findall(spaced.lower()))


@register
class ExcessiveAgencyRule(Rule):
    id = "CAP01"
    title = "Tool exposes a dangerous capability"
    category = Category.EXCESSIVE_AGENCY
    default_severity = Severity.MEDIUM
    mappings = ("OWASP-AGENTIC-EXCESSIVE-AGENCY",)

    def analyze(self, target: MCPServerSpec, ctx: AnalysisContext) -> Iterable[Finding]:
        manifest = ctx.effective_manifest(target)
        if manifest is None:
            return
        for tool in manifest.tools:
            yield from self._classify(target, tool.name, tool.description)

    def _classify(
        self, target: MCPServerSpec, tool_name: str, description: str
    ) -> Iterator[Finding]:
        haystack = f"{tool_name} {description}".lower()
        name_tokens = _tokens(tool_name)
        location = Location(server=target.name, tool=tool_name)

        matched: list[str] = []
        for capability, keywords in CAPABILITY_KEYWORDS.items():
            if any(kw in haystack for kw in keywords):
                matched.append(capability)

        if matched:
            # A dangerous verb in the *name* itself is a stronger signal.
            severity = (
                Severity.HIGH if name_tokens & DANGEROUS_NAME_TOKENS else Severity.MEDIUM
            )
            yield self.finding(
                location=location,
                evidence=f"capabilities inferred: {', '.join(sorted(matched))}",
                remediation=(
                    "Confirm this tool needs this power. Apply least privilege: scope "
                    "filesystem/network access, sandbox execution, and require human "
                    "approval for high-impact actions."
                ),
                severity=severity,
                confidence=0.7,
            )
