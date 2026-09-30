"""SUP01 — unpinned / remote-fetched server launch (supply-chain risk).

MCP servers are commonly launched with ``npx -y <pkg>``, ``uvx <pkg>``, or
``docker run <image>``, which fetch and execute the *latest* published artifact
at runtime. An attacker who compromises the package, image, or a maintainer
account gets code execution on every launch — and a server that turns
malicious after approval is a rug pull. This rule flags launches that are
unpinned or fetch code from a URL.

Pins are recognized per ecosystem: ``pkg@1.2.3`` for npm runners (``npx``,
``bunx``), ``pkg==1.2.3`` / ``pkg@1.2.3`` for Python runners (``uvx``,
``pipx``), and ``image@sha256:<digest>`` for containers (a tag is mutable, so
only a digest is a pin). Local paths and built artifacts are not flagged.

Remote fetch-and-run means the *code* comes from a URL — a git / URL package
spec, a downloader in the command line, or ``deno run https://…``. A URL that
is merely an argument (``npx mcp-remote https://host/mcp``) is not a fetch.

Maps to MCP supply-chain CVEs / SLSA provenance gaps.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator

from ..context import AnalysisContext
from ..launchers import PackageLaunch, command_basename, parse_launch
from ..models import Category, Finding, Location, MCPServerSpec, Severity
from ..patterns import (
    CONTAINER_RUNTIMES,
    CONTAINER_VALUE_FLAGS,
    DOWNLOADER_RE,
    REMOTE_FETCH_RE,
    URL_SCRIPT_RUNNERS,
)
from ..util import truncate
from .base import Rule, register

_GIT_SPEC_RE = re.compile(r"(?:^|\s)(?:git\+|github:)", re.IGNORECASE)
_URL_RE = re.compile(r"https?://", re.IGNORECASE)


def _is_remote_fetch(target: MCPServerSpec, launch: PackageLaunch | None) -> bool:
    """True when the server's *code* is downloaded from a URL at launch."""
    if launch is not None and REMOTE_FETCH_RE.search(launch.spec):
        return True
    if any(_GIT_SPEC_RE.search(arg) for arg in target.args):
        return True
    line = target.command_line
    if DOWNLOADER_RE.search(line) and _URL_RE.search(line):
        return True
    runner = command_basename(target.command or "").removesuffix(".exe")
    return runner in URL_SCRIPT_RUNNERS and any(_URL_RE.match(a) for a in target.args)


def container_image(args: tuple[str, ...]) -> str | None:
    """The image a ``docker|podman run`` line starts, or ``None``."""
    if "run" not in args:
        return None
    rest = args[args.index("run") + 1 :]
    i = 0
    while i < len(rest):
        arg = rest[i]
        if arg.startswith("-"):
            takes_value = arg in CONTAINER_VALUE_FLAGS and "=" not in arg
            i += 2 if takes_value else 1
            continue
        return arg
    return None


@register
class PinningRule(Rule):
    id = "SUP01"
    title = "Unpinned or remote-fetched MCP server"
    category = Category.SUPPLY_CHAIN
    default_severity = Severity.MEDIUM
    mappings = ("MCP-SUPPLY-CHAIN", "SLSA-PROVENANCE", "OWASP-ASI04")

    def analyze(self, target: MCPServerSpec, ctx: AnalysisContext) -> Iterable[Finding]:
        if target.command is None:
            return
        location = Location(server=target.name, field="command")
        launch = parse_launch(target.command, target.args)

        # Remote fetch-and-run is the worst case.
        if _is_remote_fetch(target, launch):
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

        if command_basename(target.command).removesuffix(".exe") in CONTAINER_RUNTIMES:
            yield from self._container(target, location)
            return

        if launch is None or launch.is_local or launch.is_pinned:
            return
        example = f"{launch.name}@1.2.3" if launch.ecosystem == "npm" else f"{launch.name}==1.2.3"
        yield self.finding(
            location=location,
            evidence=truncate(target.command_line),
            remediation=(
                f"Pin the package version (e.g. '{example}') so a compromised or "
                "malicious 'latest' release cannot execute on launch."
            ),
        )

    def _container(self, target: MCPServerSpec, location: Location) -> Iterator[Finding]:
        image = container_image(target.args)
        if image is None or "@sha256:" in image:
            return
        tag = image.rsplit("/", 1)[-1].partition(":")[2]
        yield self.finding(
            title="MCP container image not pinned by digest",
            location=location,
            evidence=truncate(target.command_line),
            remediation=(
                f"Pin the image by digest (e.g. '{image.split(':')[0] if tag else image}"
                "@sha256:<digest>'); tags — including version tags — can be re-pushed."
            ),
            severity=Severity.MEDIUM if tag in ("", "latest") else Severity.LOW,
        )
