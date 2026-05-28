"""CMD01 — remote-code-execution surface in local server source.

MCP's STDIO transport spawns local subprocesses, and many servers build shell
commands from inputs. This rule scans the server's on-disk source (when locatable
via ``source_path``) for classic RCE sinks: ``shell=True``, ``os.system``,
``eval``/``exec``, ``child_process.exec``, and ``curl | sh`` install lines.

Maps to the 2026 MCP STDIO RCE class.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..context import AnalysisContext
from ..models import Category, Finding, Location, MCPServerSpec, Severity
from ..patterns import RCE_SOURCE_PATTERNS
from ..util import iter_lines, truncate
from .base import Rule, register


@register
class CommandInjectionRule(Rule):
    id = "CMD01"
    title = "Command-execution sink in server source"
    category = Category.RCE_SURFACE
    default_severity = Severity.HIGH
    mappings = ("MCP-STDIO-RCE", "CWE-78")

    def analyze(self, target: MCPServerSpec, ctx: AnalysisContext) -> Iterable[Finding]:
        for path, text in ctx.iter_source_files(target):
            # One finding per (pattern, line) keeps reports actionable.
            for line_no, line in iter_lines(text):
                for label, pattern in RCE_SOURCE_PATTERNS.items():
                    if pattern.search(line):
                        yield self.finding(
                            title=f"RCE sink ({label})",
                            location=Location(server=target.name, path=path, line=line_no),
                            evidence=truncate(line),
                            remediation=(
                                "Avoid shell execution with untrusted input. Use argument "
                                "vectors (no shell=True), allow-list commands, and never "
                                "eval/exec request-derived strings."
                            ),
                        )
