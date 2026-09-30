"""TP01 — tool poisoning / prompt injection in MCP metadata.

Tool poisoning hides instructions aimed at the *model* inside text the model is
guaranteed to read. This rule scans the whole metadata surface — server
instructions; tool descriptions, titles, and annotation titles; every string in
the input and output schemas at any depth (parameter names, descriptions,
titles, defaults, enums, examples: "Full-Schema Poisoning"); prompt and prompt
argument descriptions; resource descriptions — for:

* injection directives (instruction override, concealment from the user,
  ``<IMPORTANT>``-style pseudo-tags, chat-template tokens, tool-ordering hijacks),
* data-exfiltration directives (sensitive file reads, send-to-URL, templated
  markdown image beacons, credential / conversation leaks),
* base64-encoded payloads that decode to either of the above.

At most one finding per kind per field, with *every* match as evidence.

Maps to OWASP LLM01 (Prompt Injection) and the MCP tool-poisoning class.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from ..context import AnalysisContext
from ..detectors import (
    decode_base64_payloads,
    exfil_matches,
    injection_matches,
    suspicious_parameter_name,
)
from ..models import Category, Finding, Location, MCPServerSpec, Severity
from ..util import matches_evidence
from .base import Rule, register


@register
class ToolPoisoningRule(Rule):
    id = "TP01"
    title = "Prompt injection in tool metadata"
    category = Category.TOOL_POISONING
    default_severity = Severity.HIGH
    mappings = ("OWASP-LLM01", "MCP-TOOL-POISONING", "OWASP-ASI01")

    def analyze(self, target: MCPServerSpec, ctx: AnalysisContext) -> Iterable[Finding]:
        manifest = ctx.effective_manifest(target)
        if manifest is None:
            return
        for owner, field, text in manifest.text_fields():
            yield from self._scan_field(target, field, text, tool=owner)

    def _scan_field(
        self, target: MCPServerSpec, field: str, text: str, *, tool: str | None
    ) -> Iterator[Finding]:
        if not text:
            return
        location = Location(server=target.name, tool=tool, field=field)

        injections = injection_matches(text)
        if injections:
            yield self.finding(
                location=location,
                evidence=matches_evidence(injections),
                remediation=(
                    "Remove instruction-like content from this field. Tool/parameter "
                    "descriptions should describe behavior, never direct the model."
                ),
                severity=Severity.HIGH,
            )

        exfils = exfil_matches(text)
        if exfils:
            yield self.finding(
                title="Possible data-exfiltration directive in tool metadata",
                location=location,
                evidence=matches_evidence(exfils),
                remediation=(
                    "This field appears to instruct the model to send data to an "
                    "external destination or read sensitive files. Treat the server as "
                    "untrusted and review its source."
                ),
                severity=Severity.CRITICAL,
            )

        lure = suspicious_parameter_name(text) if field.endswith("#name") else None
        if lure is not None:
            kind, token = lure
            yield self.finding(
                title=(
                    "Parameter name solicits sensitive data" if kind == "sensitive"
                    else "Parameter name opens a covert side channel"
                ),
                location=location,
                evidence=f"parameter {text!r} (token: {token})",
                remediation=(
                    "A parameter's name is read by the model as an instruction of what to "
                    "fill in. Names asking for keys or files, or 'sidenote'-style catch-alls, "
                    "are a known tool-poisoning channel. Treat the server as untrusted."
                ),
                severity=Severity.HIGH if kind == "sensitive" else Severity.MEDIUM,
                confidence=0.7,
            )

        encoded = decode_base64_payloads(text)
        if encoded:
            yield self.finding(
                title="Encoded (base64) instructions hidden in tool metadata",
                location=location,
                evidence=matches_evidence([f"decodes to: {d}" for d in encoded]),
                remediation=(
                    "This field carries base64 that decodes to model-directed instructions — "
                    "an encoding used to slip past reviewers and filters. Treat the server "
                    "as malicious."
                ),
                severity=Severity.CRITICAL,
            )
