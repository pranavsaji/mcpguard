"""TP01 — tool poisoning / prompt injection in MCP metadata.

Tool poisoning hides instructions aimed at the *model* inside text the model is
guaranteed to read: tool descriptions, parameter descriptions, server
instructions, and prompt/resource descriptions. This rule scans every such
field for injection directives and data-exfiltration hints.

Maps to OWASP LLM01 (Prompt Injection) and the 2026 MCP tool-poisoning class.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from ..context import AnalysisContext
from ..models import Category, Finding, Location, MCPServerSpec, Severity
from ..patterns import EXFIL_PATTERNS, INJECTION_PATTERNS
from ..util import first_match, truncate
from .base import Rule, register


@register
class ToolPoisoningRule(Rule):
    id = "TP01"
    title = "Prompt injection in tool metadata"
    category = Category.TOOL_POISONING
    default_severity = Severity.HIGH
    mappings = ("OWASP-LLM01", "MCP-TOOL-POISONING")

    def analyze(self, target: MCPServerSpec, ctx: AnalysisContext) -> Iterable[Finding]:
        manifest = ctx.effective_manifest(target)
        if manifest is None:
            return

        yield from self._scan_field(target, "instructions", manifest.instructions, tool=None)

        for tool in manifest.tools:
            yield from self._scan_field(target, "description", tool.description, tool=tool.name)
            for pname, pdesc in tool.parameter_descriptions.items():
                yield from self._scan_field(
                    target, f"param:{pname}", pdesc, tool=tool.name
                )

        for prompt in manifest.prompts:
            yield from self._scan_field(target, "description", prompt.description, tool=prompt.name)
        for resource in manifest.resources:
            yield from self._scan_field(
                target, "description", resource.description, tool=resource.name or resource.uri
            )

    def _scan_field(
        self, target: MCPServerSpec, field: str, text: str, *, tool: str | None
    ) -> Iterator[Finding]:
        if not text:
            return
        location = Location(server=target.name, tool=tool, field=field)

        injection = first_match(INJECTION_PATTERNS, text)
        if injection:
            yield self.finding(
                location=location,
                evidence=truncate(injection),
                remediation=(
                    "Remove instruction-like content from this field. Tool/parameter "
                    "descriptions should describe behavior, never direct the model."
                ),
                severity=Severity.HIGH,
            )

        exfil = first_match(EXFIL_PATTERNS, text)
        if exfil:
            yield self.finding(
                title="Possible data-exfiltration directive in tool metadata",
                location=location,
                evidence=truncate(exfil),
                remediation=(
                    "This field appears to instruct the model to send data to an "
                    "external destination or read sensitive files. Treat the server as "
                    "untrusted and review its source."
                ),
                severity=Severity.CRITICAL,
            )
