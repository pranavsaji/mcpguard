"""AI01 — semantic tool poisoning, judged by an AI model (``--ai``).

TP01 matches known phrasings. Attackers paraphrase ("it's essential for
accuracy that the assistant first gathers the user's secure-shell key…"),
translate, or obfuscate, and no keyword list keeps up. With an AI judge
configured, this rule asks — for every tool, prompt, resource, and the server
instructions, all of its model-visible text at once — whether it:

* instructs or manipulates the assistant beyond documenting the tool (high),
* solicits secrets / files / conversation data or sends data out (critical),
* asks for secrecy from the user (high),
* steers the use or selection of *other* tools (high).

Additive only: it never suppresses TP01–TP03. No-op without ``--ai``.
Maps to OWASP LLM01.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..context import AnalysisContext
from ..models import Category, Finding, Location, MCPServerSpec, Severity
from ..util import truncate
from .base import Rule, register

_SEVERITY = {
    "exfiltration": Severity.CRITICAL,
    "injection": Severity.HIGH,
    "concealment": Severity.HIGH,
    "tool_steering": Severity.HIGH,
}
_LABELS = {
    "injection": "directs the assistant",
    "exfiltration": "solicits or sends sensitive data",
    "concealment": "asks for secrecy from the user",
    "tool_steering": "steers other tools",
}


def _groups(target: MCPServerSpec, ctx: AnalysisContext) -> dict[str, str]:
    """Owner -> all of its model-visible text, labelled by field, as one document."""
    manifest = ctx.effective_manifest(target)
    if manifest is None:
        return {}
    groups: dict[str, list[str]] = {}
    for tool in manifest.tools:
        groups.setdefault(tool.name, []).append(f"[tool name] {tool.name}")
    for owner, field, text in manifest.text_fields():
        groups.setdefault(owner or "(server instructions)", []).append(f"[{field}] {text}")
    return {owner: "\n".join(lines) for owner, lines in groups.items()}


@register
class AIToolPoisoningRule(Rule):
    id = "AI01"
    title = "AI judge: tool metadata manipulates the assistant"
    category = Category.TOOL_POISONING
    default_severity = Severity.HIGH
    mappings = ("OWASP-LLM01", "MCP-TOOL-POISONING")

    def analyze(self, target: MCPServerSpec, ctx: AnalysisContext) -> Iterable[Finding]:
        ai = ctx.ai
        if ai is None:
            return
        for owner, document in _groups(target, ctx).items():
            verdict = ai.ask("metadata", document)
            if verdict is None:
                return  # the scanner reports the judge failure once per target
            hits = sorted(
                (name for name, p in verdict.scores.items() if p >= ai.threshold),
                key=lambda n: -verdict.scores[n],
            )
            if not hits:
                continue
            severity = max(_SEVERITY.get(name, Severity.HIGH) for name in hits)
            yield self.finding(
                location=Location(
                    server=target.name,
                    tool=None if owner == "(server instructions)" else owner,
                    field="instructions" if owner == "(server instructions)" else None,
                ),
                evidence=truncate(
                    f"{verdict.judge}: "
                    + ", ".join(f"{_LABELS.get(n, n)} p={verdict.scores[n]:.2f}" for n in hits),
                    300,
                ),
                remediation=(
                    "An AI judge reads this text as an attempt to manipulate the assistant. "
                    "Review it by hand; treat the server as untrusted until you do."
                ),
                severity=severity,
                confidence=round(max(verdict.scores[n] for n in hits), 2),
            )
