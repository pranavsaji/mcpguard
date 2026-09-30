"""SEC01 — plaintext secrets in server configuration.

MCP server configs routinely carry live credentials pasted in by hand. This
rule looks everywhere a config can hold one:

* ``env`` values matching a vendor key format (critical), or whose *name*
  implies a secret and whose value is not a placeholder / ``${VAR}`` (high),
* HTTP ``headers`` — ``Authorization: Bearer <literal>``, ``X-API-Key`` — (high,
  critical for vendor formats),
* launch ``args`` — ``--api-key sk-...``, ``--token=...``, or any vendor-format key,
* the server ``url`` — ``user:password@`` userinfo and ``?api_key=`` query
  parameters, which end up in logs, shell history, and proxies.

Evidence is always redacted. Maps to CWE-798 (hardcoded credentials).
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from ..context import AnalysisContext
from ..models import Category, Finding, Location, MCPServerSpec, Severity
from ..patterns import (
    AUTH_HEADER_NAME_RE,
    SECRET_FLAG_RE,
    SECRET_NAME_RE,
    SECRET_VALUE_PATTERNS,
    URL_SECRET_PARAM_RE,
    URL_USERINFO_RE,
    looks_like_placeholder,
)
from .base import Rule, register


def _redact(value: str) -> str:
    """Show only enough of a secret to identify it, never the whole thing."""
    if len(value) <= 8:
        return value[0] + "***" if value else "***"
    return f"{value[:4]}…{value[-2:]} ({len(value)} chars)"


def _vendor(value: str) -> str | None:
    """The vendor whose key format ``value`` contains, if any."""
    return next((v for v, pattern in SECRET_VALUE_PATTERNS.items() if pattern.search(value)), None)


def _is_reference(value: str) -> bool:
    """A placeholder, ``${VAR}`` reference, or a header template like ``Bearer ${TOKEN}``."""
    stripped = value.strip()
    if looks_like_placeholder(stripped):
        return True
    scheme, _, rest = stripped.partition(" ")
    return bool(rest) and scheme.lower() in ("bearer", "basic", "token") and looks_like_placeholder(rest)


@register
class SecretsRule(Rule):
    id = "SEC01"
    title = "Plaintext secret in server config env"
    category = Category.SECRETS
    default_severity = Severity.HIGH
    mappings = ("CWE-798", "MCP-SECRETS")

    def analyze(self, target: MCPServerSpec, ctx: AnalysisContext) -> Iterable[Finding]:
        for key, value in target.env.items():
            yield from self._inspect(target, key, value)
        for name, value in target.headers.items():
            yield from self._header(target, name, value)
        yield from self._args(target)
        if target.url:
            yield from self._url(target, "url", target.url)

    def _inspect(self, target: MCPServerSpec, key: str, value: str) -> Iterator[Finding]:
        if not value or looks_like_placeholder(value):
            return
        location = Location(server=target.name, field=f"env:{key}")

        # 1) Value matches a known vendor format -> high confidence regardless of name.
        vendor = _vendor(value)
        if vendor:
            yield self._vendor_finding(location, vendor, f"{key}={_redact(value)}", key)
            return

        # 2) Name implies a secret and value looks real -> medium/high confidence.
        if SECRET_NAME_RE.search(key):
            yield self.finding(
                location=location,
                evidence=f"{key}={_redact(value)}",
                remediation=(
                    "This env var name implies a credential. Do not store its value in "
                    "the config; reference \"${%s}\" and inject from a secret manager." % key
                ),
                confidence=0.6,
            )

    def _header(self, target: MCPServerSpec, name: str, value: str) -> Iterator[Finding]:
        if not value or _is_reference(value):
            return
        location = Location(server=target.name, field=f"header:{name}")
        vendor = _vendor(value)
        if vendor:
            yield self._vendor_finding(location, vendor, f"{name}: {_redact(value)}", name)
        elif AUTH_HEADER_NAME_RE.match(name) or SECRET_NAME_RE.search(name):
            yield self.finding(
                title="Plaintext credential in server config header",
                location=location,
                evidence=f"{name}: {_redact(value)}",
                remediation=(
                    "Don't hardcode auth headers. Use \"Bearer ${TOKEN}\" with the token "
                    "injected from the environment or a secret manager, or use OAuth."
                ),
                confidence=0.8,
            )

    def _args(self, target: MCPServerSpec) -> Iterator[Finding]:
        args = target.args
        for i, arg in enumerate(args):
            location = Location(server=target.name, field="args")
            flag = SECRET_FLAG_RE.match(arg)
            value = None
            if flag:
                value = flag.group(1) if flag.group(1) is not None else (
                    args[i + 1] if i + 1 < len(args) else None
                )
            vendor = _vendor(arg)
            if vendor:
                yield self._vendor_finding(location, vendor, _redact(arg), "SECRET")
            elif value and not value.startswith("-") and not _is_reference(value):
                yield self.finding(
                    title="Plaintext secret passed as a launch argument",
                    location=location,
                    evidence=f"{arg.partition('=')[0]} {_redact(value)}",
                    remediation=(
                        "Arguments are visible to every local user via the process list and "
                        "land in logs. Pass the secret through an env var reference instead."
                    ),
                    confidence=0.7,
                )
            if arg.startswith(("http://", "https://")):
                yield from self._url(target, "args", arg)

    def _url(self, target: MCPServerSpec, field: str, url: str) -> Iterator[Finding]:
        location = Location(server=target.name, field=field)
        for pattern, what in ((URL_USERINFO_RE, "password in URL"), (URL_SECRET_PARAM_RE, "secret in URL query")):
            match = pattern.search(url)
            if match and not _is_reference(match.group(1)):
                vendor = _vendor(match.group(1))
                yield self.finding(
                    title=f"Credential embedded in server URL ({what})",
                    location=location,
                    evidence=_redact(match.group(1)),
                    remediation=(
                        "URLs are logged by proxies, shells, and clients. Send the credential "
                        "in an Authorization header sourced from the environment instead."
                    ),
                    severity=Severity.CRITICAL if vendor else Severity.HIGH,
                )

    def _vendor_finding(self, location: Location, vendor: str, evidence: str, name: str) -> Finding:
        return self.finding(
            title=f"Hardcoded {vendor} in config",
            location=location,
            evidence=evidence,
            remediation=(
                "Move the secret out of the config. Reference it via an "
                "environment variable (e.g. \"${%s}\") and inject at runtime "
                "from a secret manager." % name
            ),
            severity=Severity.CRITICAL,
        )
