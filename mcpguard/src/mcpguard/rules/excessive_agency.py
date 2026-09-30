"""CAP01 — excessive agency / dangerous tool capabilities.

The top risk in the OWASP Top 10 for Agentic Applications is *excessive agency*:
agents wielding more power than their task needs. This rule infers a tool's
capability from its name and description and flags high-blast-radius powers
(code execution, shell, filesystem writes, arbitrary network, credential access,
database mutation) so they can be scoped down or gated behind human approval.

Keywords are matched on word boundaries (see ``CAPABILITY_KEYWORDS``), so
"lists filesystem entries" is not mistaken for shell access.

Maps to OWASP Agentic "Excessive Agency".
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping

from ..context import AnalysisContext
from ..models import Category, Finding, Location, MCPServerSpec, Severity
from ..patterns import CAPABILITY_KEYWORDS, DANGEROUS_NAME_TOKENS
from ..util import contains_phrase, keyword_phrases, normalize_word, words
from .base import Rule, register

_MUTATING_CAPABILITIES = frozenset(
    {"code execution", "shell / command", "filesystem write", "database"}
)
_DESTRUCTIVE_NAME_TOKENS = frozenset(
    {"delete", "remove", "drop", "write", "exec", "execute", "run", "update", "create", "kill", "send"}
)


def _tokens(text: str) -> set[str]:
    return set(words(text))


_KEYWORD_PHRASES: dict[str, tuple[tuple[str, ...], ...]] = {
    capability: keyword_phrases(keywords) for capability, keywords in CAPABILITY_KEYWORDS.items()
}


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
            yield from self._classify(target, tool.name, tool.description, tool.annotations)

    def _classify(
        self,
        target: MCPServerSpec,
        tool_name: str,
        description: str,
        annotations: Mapping[str, object] | None = None,
    ) -> Iterator[Finding]:
        # Name and description are matched separately so a phrase can't straddle them.
        fields = [
            [normalize_word(w) for w in words(tool_name)],
            [normalize_word(w) for w in words(description)],
        ]
        location = Location(server=target.name, tool=tool_name)

        matched = [
            capability
            for capability, phrases in _KEYWORD_PHRASES.items()
            if any(contains_phrase(field, phrase) for field in fields for phrase in phrases)
        ]

        if matched:
            # A dangerous verb in the *name* itself is a stronger signal.
            severity = (
                Severity.HIGH if _tokens(tool_name) & DANGEROUS_NAME_TOKENS else Severity.MEDIUM
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

        # Clients may auto-approve tools that claim to be read-only; a tool that
        # says so while wielding write/exec power is lying to the approval gate.
        mutating = sorted(set(matched) & _MUTATING_CAPABILITIES)
        destructive_name = _tokens(tool_name) & _DESTRUCTIVE_NAME_TOKENS
        if annotations and annotations.get("readOnlyHint") is True and (mutating or destructive_name):
            yield self.finding(
                title="Tool annotations understate its capability (readOnlyHint)",
                location=Location(server=target.name, tool=tool_name, field="annotations"),
                evidence=(
                    "readOnlyHint=true but "
                    + (f"capabilities inferred: {', '.join(mutating)}" if mutating
                       else f"name implies mutation: {', '.join(sorted(destructive_name))}")
                ),
                remediation=(
                    "Annotations are self-reported and untrusted. Never auto-approve based on "
                    "them; require confirmation for this tool and report the mismatch upstream."
                ),
                severity=Severity.HIGH,
                confidence=0.7,
            )
