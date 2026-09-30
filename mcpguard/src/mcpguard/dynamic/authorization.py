"""AUTH01 — unsafe OAuth authorization metadata on a remote MCP server (dynamic).

Runs with ``--connect`` against servers reached over HTTP (directly, or through a
bridge such as ``mcp-remote <url>``). The checks live in
:mod:`mcpguard.dynamic.oauth`; this rule turns its issues into findings:

* critical — shell metacharacters or non-web schemes in an endpoint a client
  launches (the CVE-2025-6514 class),
* high — plaintext http endpoints, issuer or resource mismatches (mix-up),
* medium — private-network endpoints on a public server, no PKCE S256,
* low — no RFC 9207 ``iss`` (MCP 2026-07-28), deprecated DCR only, broad scopes.

The reviewed issuers and scopes are pinned by ``mcpguard lock --connect``; MAN02
reports an authorization-server change or a wider scope set after review.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..context import AnalysisContext
from ..models import Category, Finding, Location, MCPServerSpec, Severity
from ..rules.base import Rule, RuleKind, register
from .oauth import analyze


@register
class AuthorizationMetadataRule(Rule):
    id = "AUTH01"
    title = "Unsafe OAuth authorization metadata"
    category = Category.INSECURE_TRANSPORT
    default_severity = Severity.HIGH
    mappings = ("MCP-AUTHORIZATION", "OWASP-ASI03", "RFC-9728", "RFC-8414", "RFC-9207")
    kind = RuleKind.DYNAMIC

    def analyze(self, target: MCPServerSpec, ctx: AnalysisContext) -> Iterable[Finding]:
        if ctx.auth_metadata is None:
            return
        for issue in analyze(ctx.auth_metadata):
            yield self.finding(
                title=issue.title,
                location=Location(server=target.name, field=f"oauth:{issue.field}"),
                evidence=issue.evidence,
                remediation=issue.remediation,
                severity=Severity.parse(issue.severity),
                confidence=0.0 if issue.severity == "info" else 1.0,
            )
