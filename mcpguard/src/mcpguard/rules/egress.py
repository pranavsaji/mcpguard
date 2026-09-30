"""EGR01 — outbound destinations and exfiltration channels in server source.

The model can make exactly the right call and the server can still misbehave:
a tool that "sends an email" can copy it elsewhere, a tool that "searches docs"
can post them out. That happens inside the server process, where no tool-call
policy looks. When the server's source is on disk (see CMD01), this rule
answers the review question "what network destinations does it need?":

* a hard-coded BCC recipient in mail code, a request-collector / tunnel
  service, a chat-webhook endpoint, or a public IP literal — high,
* otherwise, one informational inventory of every host the source contacts,
  so it can be reviewed and pinned (``mcpguard lock`` records it; MAN02 flags a
  destination that appears after review).

Maps to OWASP ASI04 (agentic supply chain) and the MCP malicious-server class.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..context import AnalysisContext
from ..egress import collector_reason, iter_destinations
from ..models import Category, Finding, Location, MCPServerSpec, Severity
from ..util import truncate
from .base import Rule, register

_INVENTORY_LIMIT = 12


@register
class EgressRule(Rule):
    id = "EGR01"
    title = "Server source sends data to an exfiltration channel"
    category = Category.SUPPLY_CHAIN
    default_severity = Severity.HIGH
    mappings = ("MCP-MALICIOUS-SERVER", "OWASP-ASI04", "CWE-506")

    def analyze(self, target: MCPServerSpec, ctx: AnalysisContext) -> Iterable[Finding]:
        hosts: dict[str, None] = {}
        for dest in iter_destinations(target, ctx):
            hosts.setdefault(dest.host, None)
            reason = collector_reason(dest)
            if reason is None:
                continue
            yield self.finding(
                title=(
                    "Hard-coded hidden mail recipient in server source" if dest.kind == "bcc"
                    else self.title
                ),
                location=Location(server=target.name, path=dest.path, line=dest.line),
                evidence=truncate(f"{dest.value}: {reason} | {dest.snippet.strip()}", 300),
                remediation=(
                    "Nothing in a tool's description would reveal this. Remove the server, rotate "
                    "every credential and mailbox it touched, and report the package."
                ),
            )
        if hosts:
            listed = list(hosts)
            shown = ", ".join(sorted(listed)[:_INVENTORY_LIMIT])
            more = f" (+{len(listed) - _INVENTORY_LIMIT} more)" if len(listed) > _INVENTORY_LIMIT else ""
            yield self.finding(
                title="Outbound destinations in server source",
                location=Location(server=target.name, field="source"),
                evidence=f"{len(listed)} host(s): {shown}{more}",
                remediation=(
                    "Confirm each destination fits the server's purpose, restrict the process's "
                    "outbound network to them, and pin them with `mcpguard lock` so a new one is "
                    "flagged (MAN02)."
                ),
                severity=Severity.INFO,
            )
