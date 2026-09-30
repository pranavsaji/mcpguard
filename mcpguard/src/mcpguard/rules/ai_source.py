"""AI02 — AI review of server source for injection flaws (``--ai``).

CMD01 finds dangerous *call shapes* (``shell=True``, ``os.system``); it can't
tell whether tool input actually reaches them, and it misses the many
equivalent spellings (``subprocess.run(["sh", "-c", cmd])``, ``spawn(cmd,
{shell: true})``) and whole flaw classes it has no pattern for. With an AI
judge configured, this rule reads the server's source — the same files CMD01
resolves from ``source_path`` / ``cwd`` / a locally installed package — and asks,
per file, whether tool input can reach:

* a shell / process / eval sink unvalidated (command injection, CWE-78) — high,
* a filesystem path outside an allowed directory (path traversal, CWE-22) — high,
* SQL built by string formatting (SQL injection, CWE-89) — high,
* an unrestricted outbound request target (SSRF, CWE-918) — medium.

To bound cost it only sends files that contain a relevant sink at all
(``SINK_HINT_RE``), at most ``MAX_FILES`` per server; long files are judged in
overlapping chunks. Anything skipped is reported, never silent. Mirrors the
2025–26 MCP server CVE classes (``mcp-server-git``, ``server-filesystem``,
``mcp-server-kubernetes``, archived ``server-postgres``).
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable

from ..context import AnalysisContext
from ..models import Category, Finding, Location, MCPServerSpec, Severity
from .base import Rule, register

MAX_FILES = 25
# A file worth an AI read has at least one sink an argument could reach.
SINK_HINT_RE = re.compile(
    r"subprocess|os\.system|popen|\bexecv?p?e?\b|\beval\b|child_process|execSync|execFile|\bspawn|"
    r"new\s+Function|Runtime\.getRuntime|ProcessBuilder|\bsh\s+-c\b|"
    r"open\(|readFile|writeFile|unlink|rmSync|fs\.|pathlib|shutil|"
    r"\.execute\(|\.query\(|cursor|SELECT\s|INSERT\s|UPDATE\s|DELETE\s|"
    r"requests\.|httpx|urllib|urlopen|fetch\(|axios|http\.get|https\.get|net/http",
    re.IGNORECASE,
)

_FLAWS: dict[str, tuple[str, Severity, str]] = {
    "command_injection": ("command injection", Severity.HIGH, "CWE-78"),
    "path_traversal": ("path traversal", Severity.HIGH, "CWE-22"),
    "sql_injection": ("SQL injection", Severity.HIGH, "CWE-89"),
    "ssrf": ("server-side request forgery", Severity.MEDIUM, "CWE-918"),
}


@register
class AISourceReviewRule(Rule):
    id = "AI02"
    title = "AI judge: tool input reaches a dangerous sink in server source"
    category = Category.RCE_SURFACE
    default_severity = Severity.HIGH
    mappings = ("MCP-STDIO-RCE", "CWE-78", "CWE-22", "CWE-89", "CWE-918")

    def analyze(self, target: MCPServerSpec, ctx: AnalysisContext) -> Iterable[Finding]:
        ai = ctx.ai
        if ai is None or not target.source_path:
            return
        candidates = [
            (path, text) for path, text in ctx.iter_source_files(target) if SINK_HINT_RE.search(text)
        ]
        root = target.source_path if os.path.isdir(target.source_path) else os.path.dirname(target.source_path)
        for path, text in candidates[:MAX_FILES]:
            rel = os.path.relpath(path, root) if root else path
            verdict = ai.ask("source", f"// file: {rel}\n{text}")
            if verdict is None:
                return  # reported once per target by the scanner (AI00)
            for question, (label, severity, cwe) in _FLAWS.items():
                p = verdict.scores.get(question, 0.0)
                if p >= ai.threshold:
                    yield self.finding(
                        title=f"AI judge: possible {label} in server source",
                        location=Location(server=target.name, path=path),
                        evidence=f"{verdict.judge}: {label} ({cwe}) p={p:.2f} in {rel}",
                        remediation=(
                            "An AI review believes tool input can reach this sink unvalidated. "
                            "Confirm by reading the data flow; use argument vectors, path "
                            "confinement, parameterized queries, or host allow-lists."
                        ),
                        severity=severity,
                        confidence=round(p, 2),
                    )
        if len(candidates) > MAX_FILES:
            yield self.finding(
                title="AI source review incomplete (file cap reached)",
                location=Location(server=target.name, path=target.source_path),
                evidence=f"reviewed {MAX_FILES} of {len(candidates)} files with sinks",
                remediation="Point source_path at the server's own code (not its dependencies).",
                severity=Severity.INFO,
                confidence=0.0,
            )
