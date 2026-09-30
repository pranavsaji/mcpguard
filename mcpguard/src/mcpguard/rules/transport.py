"""NET01 — insecure transport to a remote MCP server.

Remote (Streamable HTTP / SSE) servers are reached over the network, directly
via ``url`` or through a local bridge such as ``npx mcp-remote <url>``. This
rule flags:

* plaintext ``http://`` to a non-loopback host — high: tokens and the tool
  manifest itself travel in the clear, so anyone on-path can read the session
  or rewrite tool descriptions in flight (a network-level rug pull),
* the legacy HTTP+SSE transport, deprecated by the MCP spec — low.

Credentials embedded in the URL are reported by SEC01.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from urllib.parse import urlparse

from ..context import AnalysisContext
from ..launchers import parse_launch
from ..models import Category, Finding, Location, MCPServerSpec, Severity, Transport
from ..patterns import LOOPBACK_HOST_RE
from .base import Rule, register

# Local bridges whose URL argument is the remote MCP endpoint.
BRIDGE_PACKAGES: frozenset[str] = frozenset({"mcp-remote", "supergateway", "mcp-proxy"})


def remote_endpoints(spec: MCPServerSpec) -> Iterator[tuple[str, str]]:
    """``(field, url)`` for every remote MCP endpoint this entry talks to."""
    if spec.url:
        yield "url", spec.url
    launch = parse_launch(spec.command, spec.args)
    if launch is not None and launch.name in BRIDGE_PACKAGES:
        for arg in spec.args:
            if arg.startswith(("http://", "https://")):
                yield "args", arg


@register
class TransportRule(Rule):
    id = "NET01"
    title = "Plaintext HTTP connection to a remote MCP server"
    category = Category.INSECURE_TRANSPORT
    default_severity = Severity.HIGH
    mappings = ("CWE-319", "MCP-TRANSPORT-SECURITY", "OWASP-ASI03")

    def analyze(self, target: MCPServerSpec, ctx: AnalysisContext) -> Iterable[Finding]:
        for field, url in remote_endpoints(target):
            try:
                parsed = urlparse(url)
                host = parsed.hostname or ""
            except ValueError:  # malformed (e.g. "http://[") - nothing to judge
                continue
            location = Location(server=target.name, field=field)
            if parsed.scheme == "http" and host and not LOOPBACK_HOST_RE.match(host):
                yield self.finding(
                    location=location,
                    evidence=f"{parsed.scheme}://{parsed.netloc.rsplit('@', 1)[-1]}{parsed.path}",
                    remediation=(
                        "Use https://. Over plaintext, tokens can be stolen and tool "
                        "descriptions rewritten in transit."
                    ),
                )
        if target.transport is Transport.SSE:
            yield self.finding(
                title="Deprecated HTTP+SSE transport",
                location=Location(server=target.name, field="url"),
                evidence=target.url or "type: sse",
                remediation=(
                    "The MCP spec replaced HTTP+SSE with Streamable HTTP. Move to it when the "
                    "server supports it."
                ),
                severity=Severity.LOW,
            )
