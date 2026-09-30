"""SUP03 — publisher provenance: brand impersonation and typosquats.

``postmark-mcp`` (Sep 2025) was not a vulnerable package: it was a package that
*looked like* Postmark's, published by someone else, which BCC'd every email to
the attacker. SUP02 catches it by name now that it's documented; this rule
catches the shape before an advisory exists. For the package an ``npx`` /
``bunx`` / ``uvx`` / ``pipx`` launch runs, it flags:

* **scope lookalikes** — an npm scope that imitates a trusted publisher
  (``@modeIcontextprotocol``, ``@model-context-protocol``) — high,
* **name lookalikes** — a homoglyph / separator variant of a well-known server
  package (``mcp-rernote``) — high; one edit away from one — medium,
* **brand impersonation** — an MCP package named after a vendor (Postmark,
  Stripe, GitHub…) that isn't published under that vendor's scope — low, as a
  prompt to check who actually published it.

Exact well-known names are never flagged, and names inside a trusted scope are
not typosquat-checked: only the scope owner can publish there. Offline and
deterministic; the reference lists live in :mod:`mcpguard.patterns`.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..advisories import canonical_package
from ..context import AnalysisContext
from ..launchers import parse_launch
from ..models import Category, Finding, Location, MCPServerSpec, Severity
from ..patterns import BRAND_PUBLISHERS, REMOTE_FETCH_RE, TRUSTED_SCOPES, WELL_KNOWN_PACKAGES
from ..util import words
from .base import Rule, register

_MIN_TYPO_LENGTH = 8  # shorter names collide with legitimate ones too often


def skeleton(name: str) -> str:
    """A name with separators dropped and common lookalike characters folded."""
    folded = name.lower().replace("rn", "m").replace("vv", "w")
    folded = folded.translate(str.maketrans("01i35", "olles"))
    return "".join(c for c in folded if c not in "-_.")


def edit_distance(a: str, b: str, limit: int = 2) -> int:
    """Optimal-string-alignment distance, returning ``limit + 1`` once it's exceeded."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


def _scope(name: str) -> str | None:
    return name.split("/", 1)[0] if name.startswith("@") and "/" in name else None


@register
class ProvenanceRule(Rule):
    id = "SUP03"
    title = "MCP server package imitates a trusted publisher"
    category = Category.SUPPLY_CHAIN
    default_severity = Severity.HIGH
    mappings = ("MCP-SUPPLY-CHAIN", "OWASP-ASI04", "CWE-1357")

    def analyze(self, target: MCPServerSpec, ctx: AnalysisContext) -> Iterable[Finding]:
        launch = parse_launch(target.command, target.args)
        # Local paths have no publisher; URL / git specs are SUP01's (fetch-and-run).
        if launch is None or launch.is_local or REMOTE_FETCH_RE.search(launch.spec):
            return
        eco = launch.ecosystem
        name = canonical_package(eco, launch.name)
        known = {canonical_package(eco, k) for k in WELL_KNOWN_PACKAGES.get(eco, frozenset())}
        if name in known:
            return
        location = Location(server=target.name, field="command")
        scope = _scope(name)
        verify = (
            "Confirm the publisher before running it: check the package's repository, "
            "maintainers, and release history against the vendor's own documentation."
        )

        if scope is not None and scope not in TRUSTED_SCOPES:
            for trusted in sorted(TRUSTED_SCOPES):
                if skeleton(scope) == skeleton(trusted) or (
                    len(trusted) >= 12 and edit_distance(scope, trusted) <= 2
                ):
                    yield self.finding(
                        title="npm scope imitates a trusted MCP publisher",
                        location=location,
                        evidence=f"{launch.name}: scope {scope} looks like {trusted}",
                        remediation=f"This is not {trusted}. Remove the server. {verify}",
                    )
                    return

        if scope is None or scope not in TRUSTED_SCOPES:
            for known_name in sorted(known):
                if len(known_name) < _MIN_TYPO_LENGTH:
                    continue
                if skeleton(name) == skeleton(known_name):
                    yield self.finding(
                        title="Package name is a lookalike of a well-known MCP server",
                        location=location,
                        evidence=f"{launch.name} looks like {known_name}",
                        remediation=f"Did you mean {known_name}? {verify}",
                    )
                    return
                if edit_distance(name, known_name, 1) == 1:
                    yield self.finding(
                        title="Package name is one edit from a well-known MCP server",
                        location=location,
                        evidence=f"{launch.name} vs {known_name}",
                        remediation=f"Did you mean {known_name}? {verify}",
                        severity=Severity.MEDIUM,
                        confidence=0.6,
                    )
                    return

        name_words = set(words(name))
        if "mcp" not in name_words:
            return
        raw = launch.name.lower()
        for brand in sorted(BRAND_PUBLISHERS):
            if brand not in name_words:
                continue
            publishers = BRAND_PUBLISHERS[brand]
            if any(raw.startswith(p) or name.startswith(canonical_package(eco, p)) for p in publishers):
                return
            official = " or ".join(publishers) if publishers else "no verified package scope"
            yield self.finding(
                title=f"MCP package named after {brand.title()} is not from its publisher",
                location=location,
                evidence=f"{launch.name}: {brand.title()} publishes under {official}",
                remediation=(
                    f"Brand names are free to register: postmark-mcp impersonated Postmark and "
                    f"stole mail. {verify}"
                ),
                severity=Severity.LOW,
                confidence=0.4,
            )
            return
