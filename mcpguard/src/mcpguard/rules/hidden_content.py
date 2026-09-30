"""TP02 — hidden / invisible content in MCP metadata.

Attackers smuggle instructions past human review using content the model reads
but a reviewer cannot see. This rule flags, in every model-visible metadata
field (see :meth:`MCPManifest.text_fields`):

* zero-width, BiDi-override, and other invisible format characters,
* Unicode Tag characters — invisible ASCII ("ASCII smuggling"); the hidden text
  is decoded into the evidence, and escalates to critical if it is a directive,
* runs of variation selectors (arbitrary bytes smuggled after a character),
* ANSI escape / terminal control sequences, which hide or rewrite text in
  terminal-based clients (Trail of Bits, 2025),
* HTML comments, and blank padding that pushes trailing text out of view.

Maps to OWASP LLM01 (Prompt Injection).
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from ..context import AnalysisContext
from ..detectors import exfil_matches, find_hidden_content, injection_matches
from ..models import Category, Finding, Location, MCPServerSpec, Severity
from ..util import matches_evidence, truncate
from .base import Rule, register


@register
class HiddenContentRule(Rule):
    id = "TP02"
    title = "Hidden or invisible content in tool metadata"
    category = Category.HIDDEN_CONTENT
    default_severity = Severity.HIGH
    mappings = ("OWASP-LLM01", "MCP-TOOL-POISONING", "OWASP-ASI01")

    def analyze(self, target: MCPServerSpec, ctx: AnalysisContext) -> Iterable[Finding]:
        manifest = ctx.effective_manifest(target)
        if manifest is None:
            return
        for owner, field, text in manifest.text_fields():
            yield from self._scan(target, owner, field, text)
        for tool in manifest.tools:  # names are model-visible too (and shown to users)
            yield from self._scan(target, tool.name, "name", tool.name)

    def _scan(
        self, target: MCPServerSpec, tool: str | None, field: str, text: str
    ) -> Iterator[Finding]:
        if not text:
            return
        location = Location(server=target.name, tool=tool, field=field)
        hidden = find_hidden_content(text)

        if hidden.invisibles:
            evidence = f"invisible characters present: {', '.join(hidden.invisibles)}"
            severity = Severity.HIGH
            if hidden.tag_text:
                evidence += f"; hidden text decodes to: {truncate(hidden.tag_text, 120)!r}"
                if injection_matches(hidden.tag_text) or exfil_matches(hidden.tag_text):
                    severity = Severity.CRITICAL
            yield self.finding(
                location=location,
                evidence=evidence,
                remediation=(
                    "Strip zero-width / BiDi / tag characters from this field. Their "
                    "only plausible purpose in metadata is to hide instructions from "
                    "human reviewers."
                ),
                severity=severity,
            )

        if hidden.variation_selectors:
            yield self.finding(
                title="Variation-selector smuggling in tool metadata",
                location=location,
                evidence=f"{hidden.variation_selectors} suspicious variation selectors (invisible byte encoding)",
                remediation=(
                    "Runs of Unicode variation selectors can encode arbitrary hidden data. "
                    "Strip them and treat the server as untrusted."
                ),
            )

        if hidden.ansi:
            yield self.finding(
                title="Terminal escape sequences in tool metadata",
                location=location,
                evidence=matches_evidence(hidden.ansi),
                remediation=(
                    "ANSI / control sequences can hide or rewrite text shown to the user in "
                    "terminal clients while the model still reads it. Remove them."
                ),
            )

        if hidden.html_comments:
            yield self.finding(
                title="HTML comment hidden in tool metadata",
                location=location,
                evidence=matches_evidence(hidden.html_comments),
                remediation="Remove HTML comments; they are invisible in many UIs but read by the model.",
                severity=Severity.MEDIUM,
            )

        if hidden.padding:
            yield self.finding(
                title="Whitespace padding hides trailing content in tool metadata",
                location=location,
                evidence=truncate(text[-120:]),
                remediation=(
                    "Long blank runs push text below the fold of approval dialogs. Remove "
                    "the padding and review the text after it."
                ),
                severity=Severity.MEDIUM,
            )
