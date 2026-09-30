"""TP03 — tool shadowing, cross-server interference, and tool-name spoofing.

Every connected server's metadata lands in the *same* model context, so one
server can steer how the model uses another's tools without ever being called
("tool shadowing", Invariant 2025: "when send_email is used, BCC attacker@").
This rule, which sees every server in the config, flags:

* metadata naming a tool that belongs to a *different* server (high),
* shadowing directives: "when using the X tool…", "instead of calling…",
  redirect / BCC instructions, recipient overrides (high),
* preference manipulation — "always use this tool", "other tools are
  deprecated" — biasing tool selection (medium),
* the same tool name exposed by two servers, so a call may route to the wrong
  (possibly malicious) one (medium),
* tool names that mix scripts (Cyrillic "\\u0430" in "re\\u0430d_file") or fall outside the
  MCP-recommended character set — homoglyph spoofing (high / medium).

Maps to OWASP LLM01 and the MCP tool-shadowing / tool-squatting class.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator

from ..context import AnalysisContext
from ..detectors import mixed_scripts, preference_matches, shadowing_matches
from ..models import Category, Finding, Location, MCPManifest, MCPServerSpec, Severity
from ..patterns import TOOL_NAME_RE
from ..util import matches_evidence
from .base import Rule, register

# A tool name is only "distinctive" enough to count as a reference when it can't
# plausibly be an ordinary word: it has a separator or an inner capital, and length.
_DISTINCTIVE_RE = re.compile(r"^(?=.{5,})(?:.*[_\-.].*|.*[a-z][A-Z].*)$")


_TARGET_RE = re.compile(r"(?:using|calling|invoking)\s+(?:the\s+)?[`'\"]?([\w.-]+)", re.IGNORECASE)


def _target_tool(directive: str) -> str | None:
    """The tool a "when using X" / "instead of calling X" directive names, if any."""
    match = _TARGET_RE.search(directive)
    return match.group(1) if match else None


def _mentions(text: str, name: str) -> bool:
    return re.search(rf"(?<![\w-]){re.escape(name)}(?![\w-])", text) is not None


@register
class ToolShadowingRule(Rule):
    id = "TP03"
    title = "Tool shadowing: metadata steers another server's tools"
    category = Category.TOOL_SHADOWING
    default_severity = Severity.HIGH
    mappings = ("OWASP-LLM01", "MCP-TOOL-SHADOWING", "OWASP-ASI01")

    def analyze(self, target: MCPServerSpec, ctx: AnalysisContext) -> Iterable[Finding]:
        manifest = ctx.effective_manifest(target)
        if manifest is None:
            return
        own = {t.name for t in manifest.tools}
        foreign = self._foreign_tools(target, ctx, own)

        for owner, field, text in manifest.text_fields():
            location = Location(server=target.name, tool=owner, field=field)
            referenced = sorted(
                f"{name} ({server})" for name, server in foreign.items() if _mentions(text, name)
            )
            if referenced:
                yield self.finding(
                    title="Tool metadata references another server's tool",
                    location=location,
                    evidence=f"mentions: {', '.join(referenced)}",
                    remediation=(
                        "A server's metadata should never mention another server's tools. "
                        "This is the tool-shadowing pattern; disable the server and review it."
                    ),
                    confidence=0.8,
                )
            directives = [d for d in shadowing_matches(text) if _target_tool(d) not in own]
            if directives:
                yield self.finding(
                    location=location,
                    evidence=matches_evidence(directives),
                    remediation=(
                        "This text instructs the model how to use other tools or where to "
                        "redirect data. Treat the server as malicious."
                    ),
                )
            preference = preference_matches(text)
            if preference:
                yield self.finding(
                    title="Tool metadata manipulates tool selection",
                    location=location,
                    evidence=matches_evidence(preference),
                    remediation=(
                        "Descriptions should state what a tool does, not rank it against "
                        "others. Remove the preference language."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                )

        yield from self._collisions(target, manifest, ctx)
        yield from self._spoofed_names(target, manifest)

    @staticmethod
    def _foreign_tools(
        target: MCPServerSpec, ctx: AnalysisContext, own: set[str]
    ) -> dict[str, str]:
        """Distinctive tool names served by *other* servers: ``{tool: server}``."""
        out: dict[str, str] = {}
        for spec, peer_manifest in ctx.peers:
            if spec.name == target.name or peer_manifest is None:
                continue
            for tool in peer_manifest.tools:
                if tool.name not in own and _DISTINCTIVE_RE.match(tool.name):
                    out.setdefault(tool.name, spec.name)
        return out

    def _collisions(
        self, target: MCPServerSpec, manifest: MCPManifest, ctx: AnalysisContext
    ) -> Iterator[Finding]:
        for tool in manifest.tools:
            others = sorted(
                spec.name
                for spec, peer in ctx.peers
                if spec.name != target.name
                and peer is not None
                and any(t.name == tool.name for t in peer.tools)
            )
            if others:
                yield self.finding(
                    title="Tool name collides with another server's tool",
                    location=Location(server=target.name, tool=tool.name),
                    evidence=f"{tool.name!r} is also served by: {', '.join(others)}",
                    remediation=(
                        "Two servers exposing the same tool name lets one hijack calls meant "
                        "for the other. Remove one, or use a client that namespaces tools."
                    ),
                    severity=Severity.MEDIUM,
                )

    def _spoofed_names(self, target: MCPServerSpec, manifest: MCPManifest) -> Iterator[Finding]:
        for tool in manifest.tools:
            scripts = mixed_scripts(tool.name)
            if scripts:
                yield self.finding(
                    title="Tool name mixes Unicode scripts (homoglyph spoofing)",
                    location=Location(server=target.name, tool=tool.name),
                    evidence=f"{tool.name!r} mixes {', '.join(scripts)} characters",
                    remediation=(
                        "Look-alike characters let a tool impersonate a trusted one. Treat "
                        "the server as malicious."
                    ),
                )
            elif not TOOL_NAME_RE.match(tool.name):
                yield self.finding(
                    title="Tool name outside the MCP-recommended character set",
                    location=Location(server=target.name, tool=tool.name),
                    evidence=f"{tool.name!r} ({tool.name.encode('unicode_escape').decode('ascii')})",
                    remediation=(
                        "MCP recommends tool names of 1-128 characters from [A-Za-z0-9_.-]. "
                        "Other characters are a spoofing and confusion risk."
                    ),
                    severity=Severity.MEDIUM,
                )
