"""AI03 — tool capability vs. the server's stated purpose (``--ai``).

Excessive agency isn't "this tool is powerful" — a shell server *should* run
commands. It's "this tool is more powerful than this server needs": a weather
server that can execute shell commands, a calculator that makes arbitrary HTTP
requests. CAP01 can only see the power; with an AI judge this rule weighs each
tool against what the server says it is for (its name, launch package, and
instructions), and flags:

* capability beyond the stated purpose (excessive agency) — medium,
* a description revealing behavior different from, or hidden behind, the name
  and purpose ("get_time … also syncs contacts to our cloud") — high.

Only tool text and the server's name / package / instructions / URL (with any
credentials and query string removed) are sent to the judge — never env or headers.

No-op without ``--ai`` or without a manifest. Maps to OWASP Agentic excessive agency.
"""

from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import urlsplit

from ..context import AnalysisContext
from ..launchers import parse_launch
from ..models import Category, Finding, Location, MCPManifest, MCPServerSpec, Severity
from ..util import truncate
from .base import Rule, register


def redact_url(url: str) -> str:
    """``scheme://host/path`` only: credentials and query strings never reach a judge."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = f":{parts.port}" if parts.port else ""
    except ValueError:
        return "(unparseable url)"
    return f"{parts.scheme}://{host}{port}{parts.path}"


def stated_purpose(target: MCPServerSpec, manifest: MCPManifest) -> str:
    """What the server claims to be: its config name, package, and instructions."""
    parts = [f"server name: {target.name}"]
    launch = parse_launch(target.command, target.args)
    if launch is not None:
        parts.append(f"package: {launch.name}")
    elif target.url:
        parts.append(f"remote endpoint: {redact_url(target.url)}")
    if manifest.instructions:
        parts.append(f"server instructions: {manifest.instructions}")
    return "\n".join(parts)


@register
class AIPurposeRule(Rule):
    id = "AI03"
    title = "AI judge: tool exceeds the server's stated purpose"
    category = Category.EXCESSIVE_AGENCY
    default_severity = Severity.MEDIUM
    mappings = ("OWASP-AGENTIC-EXCESSIVE-AGENCY", "OWASP-ASI02")

    def analyze(self, target: MCPServerSpec, ctx: AnalysisContext) -> Iterable[Finding]:
        ai = ctx.ai
        manifest = ctx.effective_manifest(target)
        if ai is None or manifest is None or not manifest.tools:
            return
        purpose = stated_purpose(target, manifest)
        for tool in manifest.tools:
            verdict = ai.ask(
                "purpose",
                {"server_purpose": purpose, "tool": f"name: {tool.name}\ndescription: {tool.description}"},
            )
            if verdict is None:
                return
            mismatch = verdict.scores.get("mismatch", 0.0)
            excessive = verdict.scores.get("excessive", 0.0)
            location = Location(server=target.name, tool=tool.name)
            if mismatch >= ai.threshold:
                yield self.finding(
                    title="AI judge: tool description reveals hidden or mismatched behavior",
                    location=location,
                    evidence=truncate(f"{verdict.judge}: mismatch p={mismatch:.2f}; {tool.description}", 240),
                    remediation=(
                        "The tool does something its name and the server's purpose don't suggest. "
                        "Treat it as deceptive until reviewed."
                    ),
                    severity=Severity.HIGH,
                    confidence=round(mismatch, 2),
                )
            elif excessive >= ai.threshold:
                yield self.finding(
                    location=location,
                    evidence=truncate(
                        f"{verdict.judge}: excessive p={excessive:.2f}; purpose: "
                        f"{purpose.splitlines()[0]}; tool: {tool.name}",
                        240,
                    ),
                    remediation=(
                        "This server doesn't need this power for what it says it does. Remove or "
                        "disable the tool, or require approval for every call."
                    ),
                    confidence=round(excessive, 2),
                )
