"""MAN01 — manifest drift / rug pull (dynamic).

An MCP server can advertise benign tools at review time, then mutate its tool
set or descriptions after it has earned trust (a "rug pull"). This dynamic rule
compares the *declared* manifest (the baseline you reviewed / committed) against
the *live* manifest enumerated at scan time and flags:

* tools present live but not declared (silently added capability), and
* tools whose description changed since the baseline (possible re-poisoning).

Requires a live connection (``--connect``); no-ops without both manifests.
Maps to the 2026 MCP rug-pull / manifest-drift class.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from ..context import AnalysisContext
from ..models import Category, Finding, Location, MCPManifest, MCPServerSpec, Severity
from ..rules.base import Rule, RuleKind, register
from ..util import truncate


@register
class ManifestDriftRule(Rule):
    id = "MAN01"
    title = "MCP server manifest drifted from baseline"
    category = Category.RUG_PULL
    default_severity = Severity.HIGH
    mappings = ("MCP-RUG-PULL", "MCP-MANIFEST-DRIFT")
    kind = RuleKind.DYNAMIC

    def analyze(self, target: MCPServerSpec, ctx: AnalysisContext) -> Iterable[Finding]:
        declared = target.manifest
        live = ctx.live_manifest
        if declared is None or live is None:
            return  # nothing to compare against
        yield from self._diff(target, declared, live)

    def _diff(
        self, target: MCPServerSpec, declared: MCPManifest, live: MCPManifest
    ) -> Iterator[Finding]:
        baseline = {t.name: t for t in declared.tools}
        for tool in live.tools:
            prior = baseline.get(tool.name)
            if prior is None:
                yield self.finding(
                    title="Undeclared tool appeared on live server",
                    location=Location(server=target.name, tool=tool.name),
                    evidence=f"tool {tool.name!r} is served live but absent from the reviewed baseline",
                    remediation=(
                        "Treat newly-appearing tools as untrusted. Re-review and re-pin "
                        "the server; a server adding tools post-approval is a rug-pull signal."
                    ),
                )
            elif prior.description != tool.description:
                yield self.finding(
                    title="Tool description changed since baseline",
                    location=Location(server=target.name, tool=tool.name, field="description"),
                    evidence=truncate(f"was: {prior.description!r} now: {tool.description!r}"),
                    remediation=(
                        "A tool's description changed after review. Re-inspect it for "
                        "injected instructions and re-pin the server version."
                    ),
                )
