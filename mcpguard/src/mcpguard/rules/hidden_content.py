"""TP02 — hidden / invisible content in MCP metadata.

Attackers smuggle instructions past human review using characters the model
reads but a reviewer cannot see: zero-width spaces, BiDi overrides, and HTML
comments. This rule flags any metadata field containing such content.

Maps to OWASP LLM01 (Prompt Injection).
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from ..context import AnalysisContext
from ..models import Category, Finding, Location, MCPServerSpec, Severity
from ..patterns import HTML_COMMENT_RE, INVISIBLE_CHAR_SET
from ..util import truncate
from .base import Rule, register


def _named_invisibles(text: str) -> list[str]:
    """Return unique U+XXXX labels for invisible characters present in ``text``."""
    seen: dict[str, None] = {}
    for char in text:
        if char in INVISIBLE_CHAR_SET:
            seen.setdefault(f"U+{ord(char):04X}", None)
    return list(seen)


@register
class HiddenContentRule(Rule):
    id = "TP02"
    title = "Hidden or invisible content in tool metadata"
    category = Category.HIDDEN_CONTENT
    default_severity = Severity.HIGH
    mappings = ("OWASP-LLM01", "MCP-TOOL-POISONING")

    def analyze(self, target: MCPServerSpec, ctx: AnalysisContext) -> Iterable[Finding]:
        manifest = ctx.effective_manifest(target)
        if manifest is None:
            return

        fields: list[tuple[str | None, str, str]] = [(None, "instructions", manifest.instructions)]
        for tool in manifest.tools:
            fields.append((tool.name, "description", tool.description))
            for pname, pdesc in tool.parameter_descriptions.items():
                fields.append((tool.name, f"param:{pname}", pdesc))

        for tool_name, field, text in fields:
            yield from self._scan(target, tool_name, field, text)

    def _scan(
        self, target: MCPServerSpec, tool: str | None, field: str, text: str
    ) -> Iterator[Finding]:
        if not text:
            return
        location = Location(server=target.name, tool=tool, field=field)

        invisibles = _named_invisibles(text)
        if invisibles:
            yield self.finding(
                location=location,
                evidence=f"invisible characters present: {', '.join(invisibles)}",
                remediation=(
                    "Strip zero-width / BiDi control characters from this field. Their "
                    "only plausible purpose in metadata is to hide instructions from "
                    "human reviewers."
                ),
            )

        comment = HTML_COMMENT_RE.search(text)
        if comment:
            yield self.finding(
                title="HTML comment hidden in tool metadata",
                location=location,
                evidence=truncate(comment.group(0)),
                remediation="Remove HTML comments; they are invisible in many UIs but read by the model.",
                severity=Severity.MEDIUM,
            )
