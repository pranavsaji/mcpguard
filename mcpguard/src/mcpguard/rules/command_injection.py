"""CMD01 — remote-code-execution surface in local server source.

MCP's STDIO transport spawns local subprocesses, and many servers build shell
commands from inputs. This rule scans the server's on-disk source for classic RCE
sinks: ``shell=True``, ``os.system``, ``eval``/``exec``, ``child_process.exec``,
and ``curl | sh`` install lines.

Source is located from an explicit ``source_path``/``cwd``, a script argument
(``python server.py``), or a locally installed copy of an ``npx``/``uvx``
package (see :mod:`mcpguard.source_resolver`). Patterns are scoped to the
languages they belong to and matched against code with comments and string
contents blanked (see :mod:`mcpguard.source_mask`), so prose mentioning
``eval()`` and method calls like ``regex.exec(`` don't fire.

When the source of a server launched by an interpreter or package runner can't
be found, an ``INFO`` finding says so, so the missing coverage is visible rather
than silent.

Maps to the 2026 MCP STDIO RCE class.
"""

from __future__ import annotations

import os
from collections.abc import Iterable

from ..context import AnalysisContext
from ..launchers import command_basename
from ..models import Category, Finding, Location, MCPServerSpec, Severity
from ..patterns import RCE_SOURCE_PATTERNS, SOURCE_INTERPRETERS
from ..source_mask import mask_source
from ..util import truncate
from .base import Rule, register


def _expects_source(command: str | None) -> bool:
    """True for interpreters / package runners (``python3.12``, ``npx``, ``node.exe``)."""
    if not command:
        return False
    name = command_basename(command).removesuffix(".exe")
    return name in SOURCE_INTERPRETERS or name.rstrip("0123456789.") in SOURCE_INTERPRETERS


@register
class CommandInjectionRule(Rule):
    id = "CMD01"
    title = "Command-execution sink in server source"
    category = Category.RCE_SURFACE
    default_severity = Severity.HIGH
    mappings = ("MCP-STDIO-RCE", "CWE-78")

    def analyze(self, target: MCPServerSpec, ctx: AnalysisContext) -> Iterable[Finding]:
        if not target.source_path:
            if _expects_source(target.command):
                yield self._source_not_found(target)
            return

        for path, source in ctx.iter_source_files(target):
            ext = os.path.splitext(path)[1].lower()
            patterns = [
                p for p in RCE_SOURCE_PATTERNS if p.extensions is None or ext in p.extensions
            ]
            if not patterns:
                continue
            masked = mask_source(source, ext)
            views = {"code": masked.code.split("\n"), "text": masked.text.split("\n")}
            # One finding per (pattern, line) keeps reports actionable.
            for index, line in enumerate(source.split("\n")):
                for pattern in patterns:
                    if pattern.regex.search(views[pattern.view][index]):
                        yield self.finding(
                            title=f"RCE sink ({pattern.label})",
                            location=Location(server=target.name, path=path, line=index + 1),
                            evidence=truncate(line),
                            remediation=(
                                "Avoid shell execution with untrusted input. Use argument "
                                "vectors (no shell=True), allow-list commands, and never "
                                "eval/exec request-derived strings."
                            ),
                        )

    def _source_not_found(self, target: MCPServerSpec) -> Finding:
        return self.finding(
            title="Server source not found locally (RCE source scan skipped)",
            location=Location(server=target.name, field="command"),
            evidence=truncate(target.command_line),
            remediation=(
                "To scan this server's code, add a \"source_path\" (or \"cwd\") pointing at its "
                "source to the config entry, or install the package locally (e.g. run the "
                "npx/uvx command once) and re-scan."
            ),
            severity=Severity.INFO,
            confidence=0.0,
        )
