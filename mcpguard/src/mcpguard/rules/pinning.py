"""SUP01 — unpinned / remote-fetched server launch (supply-chain risk).

MCP servers are commonly launched with ``npx -y <pkg>`` or ``uvx <pkg>``, which
fetch and execute the *latest* published version at runtime. An attacker who
compromises the package (or a maintainer account) gets code execution on every
launch. This rule flags launches that are unpinned or fetch code from a URL.

Maps to MCP supply-chain CVEs / SLSA provenance gaps.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Iterator

from ..context import AnalysisContext
from ..models import Category, Finding, Location, MCPServerSpec, Severity
from ..patterns import NPM_PINNED_RE, PINNED_LAUNCHERS, REMOTE_FETCH_RE
from ..util import truncate
from .base import Rule, register


def _looks_pinned(package_token: str) -> bool:
    """True if an npm-style package token carries an explicit version pin."""
    return bool(NPM_PINNED_RE.search(package_token))


@register
class PinningRule(Rule):
    id = "SUP01"
    title = "Unpinned or remote-fetched MCP server"
    category = Category.SUPPLY_CHAIN
    default_severity = Severity.MEDIUM
    mappings = ("MCP-SUPPLY-CHAIN", "SLSA-PROVENANCE")

    def analyze(self, target: MCPServerSpec, ctx: AnalysisContext) -> Iterable[Finding]:
        if target.command is None:
            return
        launcher = os.path.basename(target.command).lower()
        location = Location(server=target.name, field="command")

        # Remote fetch-and-run anywhere in the command line is the worst case.
        remote = REMOTE_FETCH_RE.search(target.command_line)
        if remote:
            yield self.finding(
                title="MCP server fetches code from a remote URL at launch",
                location=location,
                evidence=truncate(target.command_line),
                remediation=(
                    "Do not fetch-and-execute remote code at launch. Vendor the server, "
                    "pin a version, and verify its integrity (hash / signature)."
                ),
                severity=Severity.HIGH,
            )
            return

        if launcher in PINNED_LAUNCHERS:
            yield from self._check_unpinned(target, launcher, location)

    def _check_unpinned(
        self, target: MCPServerSpec, launcher: str, location: Location
    ) -> Iterator[Finding]:
        # Find the package token: first arg that isn't a flag.
        package = next((a for a in target.args if not a.startswith("-")), None)
        if package is None or _looks_pinned(package):
            return
        yield self.finding(
            location=location,
            evidence=f"{launcher} {target.command_line.split(launcher, 1)[-1].strip()}".strip(),
            remediation=(
                f"Pin the package version (e.g. '{package}@1.2.3') so a compromised or "
                "malicious 'latest' release cannot execute on launch."
            ),
        )
