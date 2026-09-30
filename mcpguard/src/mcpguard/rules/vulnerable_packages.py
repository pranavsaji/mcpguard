"""SUP02 — known-vulnerable, malicious, or abandoned MCP server packages.

Matches the package an ``npx`` / ``bunx`` / ``uvx`` / ``pipx`` launch runs against
the offline advisory list in :mod:`mcpguard.advisories`:

* **malicious** packages are critical at any version,
* **vulnerable** packages are reported at the advisory's severity when the
  pinned (or locally installed) version is affected; unpinned launches of a
  package that has a fixed release get a low note to pin at or above the fix,
* **unfixed** vulnerabilities apply to every version,
* **archived** reference servers are a low-severity maintenance risk.

It also flags published indicators of compromise (campaign hosts, payload file
names) anywhere in the launch line, URL, or env. Maps to CWE-1395 / MCP supply chain.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable, Iterator

from ..advisories import ARCHIVED, MALICIOUS, UNFIXED, Advisory, find_advisories, version_matches
from ..context import AnalysisContext
from ..launchers import PackageLaunch, parse_launch
from ..models import Category, Finding, Location, MCPServerSpec, Severity
from ..patterns import IOC_SUBSTRINGS
from .base import Rule, register


def _installed_npm_version(spec: MCPServerSpec, launch: PackageLaunch) -> str | None:
    """Version of the locally installed copy CMD01 would scan, if it is this package."""
    if not spec.source_path or launch.ecosystem != "npm":
        return None
    manifest = os.path.join(spec.source_path, "package.json")
    try:
        with open(manifest, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    if isinstance(data, dict) and data.get("name") == launch.name:
        version = data.get("version")
        return version if isinstance(version, str) else None
    return None


@register
class VulnerablePackageRule(Rule):
    id = "SUP02"
    title = "MCP server package has a known vulnerability"
    category = Category.VULNERABLE_COMPONENT
    default_severity = Severity.HIGH
    mappings = ("CWE-1395", "MCP-SUPPLY-CHAIN", "OWASP-ASI04")

    def analyze(self, target: MCPServerSpec, ctx: AnalysisContext) -> Iterable[Finding]:
        yield from self._iocs(target)
        launch = parse_launch(target.command, target.args)
        if launch is None or launch.is_local:
            return
        version = launch.version or _installed_npm_version(target, launch)
        for advisory in find_advisories(launch.ecosystem, launch.name):
            finding = self._assess(target, launch, version, advisory)
            if finding is not None:
                yield finding

    def _assess(
        self, target: MCPServerSpec, launch: PackageLaunch, version: str | None, adv: Advisory
    ) -> Finding | None:
        location = Location(server=target.name, field="command")
        ids = f" [{', '.join(adv.ids)}]" if adv.ids else ""
        where = f"{launch.name}@{version}" if version else f"{launch.name} (unpinned)"
        evidence = f"{where}: {adv.summary}{ids}"
        severity = Severity.parse(adv.severity)

        if adv.kind == MALICIOUS:
            return self.finding(
                title="MCP server package is known malware",
                location=location,
                evidence=evidence,
                remediation=(
                    f"Remove this server immediately and rotate every credential it could reach. "
                    f"Source: {adv.url}"
                ),
                severity=Severity.CRITICAL,
            )
        if adv.kind == ARCHIVED:
            return self.finding(
                title="MCP server package is archived / unmaintained",
                location=location,
                evidence=evidence,
                remediation=f"Migrate to a maintained server. Source: {adv.url}",
                severity=severity,
            )
        if adv.kind == UNFIXED or (version is not None and version_matches(version, adv.affected)):
            fix = f"Upgrade to {adv.fixed} or later" if adv.fixed else "No fixed release exists; replace it"
            return self.finding(
                location=location,
                evidence=evidence,
                remediation=f"{fix}. Source: {adv.url}",
                severity=severity,
            )
        if version is None and adv.fixed:
            return self.finding(
                title="Unpinned launch of a package with a known vulnerability",
                location=location,
                evidence=evidence,
                remediation=(
                    f"Versions {' or '.join(adv.affected)} are affected. Pin to "
                    f"{launch.name}@{adv.fixed} or later so a stale cache can't run a "
                    f"vulnerable build. Source: {adv.url}"
                ),
                severity=Severity.LOW,
                confidence=0.5,
            )
        return None

    def _iocs(self, target: MCPServerSpec) -> Iterator[Finding]:
        haystack = " ".join([target.command_line, target.url or "", *target.env.values()]).lower()
        for needle, description in IOC_SUBSTRINGS.items():
            if needle.lower() in haystack:
                yield self.finding(
                    title="Known MCP attack-campaign indicator in server config",
                    location=Location(server=target.name),
                    evidence=f"{needle}: {description}",
                    remediation=(
                        "This config references infrastructure from a documented MCP attack "
                        "campaign. Remove the server, check how it was added, and rotate secrets."
                    ),
                    severity=Severity.CRITICAL,
                )
