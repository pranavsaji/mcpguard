"""HDR01 / CACHE01 — risky use of the MCP 2026-07-28 protocol surface.

The 2026-07-28 revision moved MCP toward stateless requests and mirrored
routing data into HTTP headers so gateways can apply rules before a call
reaches a server. Two of its new tool-list features are also new attack
surface:

* **HDR01 — ``x-mcp-header``.** A tool's ``inputSchema`` may mark a parameter
  to be mirrored into an ``Mcp-Param-{name}`` request header (SEP-2243).
  Clients MUST drop a tool whose designation breaks the spec's constraints
  (non-token name, CR/LF, duplicates, a non-primitive or ``number`` parameter,
  a property not reachable through ``properties`` alone), so a malformed one is
  either a broken server or a header-injection probe. A credential-bearing
  parameter mirrored into a header is copied into every proxy, WAF, and access
  log on the path.
* **CACHE01 — ``ttlMs`` / ``cacheScope``.** List results now carry cache hints
  (SEP-2549). A cached list is not a reviewed list: a long lifetime means a
  client keeps serving yesterday's tool definitions, and ``cacheScope:
  "public"`` on an authenticated server lets shared intermediaries cache (and
  replay) a per-user catalog.

Both read the effective manifest, so they run on declared manifests and on
``--connect`` enumerations alike.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from ..context import AnalysisContext
from ..models import Category, Finding, Location, MCPServerSpec, MCPTool, Severity
from ..patterns import (
    AUTH_HEADER_NAME_RE,
    HEADER_PARAM_TYPES,
    HTTP_TOKEN_RE,
    LONG_CACHE_TTL_MS,
    SECRET_NAME_RE,
    URL_SECRET_PARAM_RE,
    URL_USERINFO_RE,
)
from ..util import truncate
from .base import Rule, register

HEADER_KEY = "x-mcp-header"
_MAX_DEPTH = 32


def _reachable(
    schema: object, path: str = "", raw: str = "", depth: int = 0
) -> Iterator[tuple[str, str, dict[str, object]]]:
    """``(path, raw schema path, property schema)`` for every property reachable
    via ``properties`` alone (``a.b`` / ``properties.a.properties.b``)."""
    if depth > _MAX_DEPTH or not isinstance(schema, dict):
        return
    props = schema.get("properties")
    if not isinstance(props, dict):
        return
    for name, sub in props.items():
        if isinstance(sub, dict):
            child = f"{path}.{name}" if path else str(name)
            child_raw = f"{raw}.properties.{name}" if raw else f"properties.{name}"
            yield child, child_raw, sub
            yield from _reachable(sub, child, child_raw, depth + 1)


def _all_designations(node: object, path: str = "", depth: int = 0) -> Iterator[str]:
    """Paths of every ``x-mcp-header`` key anywhere in a schema."""
    if depth > _MAX_DEPTH:
        return
    if isinstance(node, dict):
        for key, value in node.items():
            child = f"{path}.{key}" if path else str(key)
            if key == HEADER_KEY:
                yield path or "<root>"
            yield from _all_designations(value, child, depth + 1)
    elif isinstance(node, list):
        for index, item in enumerate(node):
            yield from _all_designations(item, f"{path}[{index}]", depth + 1)


def _type_problem(prop: dict[str, object]) -> str | None:
    declared = prop.get("type")
    types = [declared] if isinstance(declared, str) else declared if isinstance(declared, list) else []
    concrete = [t for t in types if t != "null"]
    if not concrete:
        return "the parameter declares no primitive type"
    bad = [str(t) for t in concrete if not (isinstance(t, str) and t in HEADER_PARAM_TYPES)]
    if bad:
        return f"type {'/'.join(bad)} cannot be mirrored (string, integer, boolean only)"
    return None


def _is_secret_param(path: str, prop: dict[str, object]) -> bool:
    name = path.rsplit(".", 1)[-1]
    description = prop.get("description")
    return bool(SECRET_NAME_RE.search(name)) or (
        isinstance(description, str) and bool(SECRET_NAME_RE.search(description))
    )


@register
class HeaderMirroringRule(Rule):
    id = "HDR01"
    title = "Invalid x-mcp-header designation (clients must reject this tool)"
    category = Category.INSECURE_TRANSPORT
    default_severity = Severity.MEDIUM
    mappings = ("MCP-2026-07-28-SEP-2243", "OWASP-ASI03", "CWE-113")

    def analyze(self, target: MCPServerSpec, ctx: AnalysisContext) -> Iterable[Finding]:
        manifest = ctx.effective_manifest(target)
        if manifest is None:
            return
        for tool in manifest.tools:
            yield from self._check_tool(target, tool)

    def _check_tool(self, target: MCPServerSpec, tool: MCPTool) -> Iterator[Finding]:
        schema = tool.input_schema
        valid_paths: set[str] = set()
        seen: dict[str, str] = {}  # lowercased header name -> first parameter path
        for path, raw, prop in _reachable(schema):
            if HEADER_KEY not in prop:
                continue
            valid_paths.add(raw)
            value = prop[HEADER_KEY]
            location = Location(server=target.name, tool=tool.name, field=f"param:{path}")
            if isinstance(value, str) and any(c in value for c in "\r\n\x00"):
                yield self.finding(
                    title="x-mcp-header value contains control characters (header injection)",
                    location=location,
                    evidence=f"{HEADER_KEY}={value!r}",
                    remediation=(
                        "A header name carrying CR/LF can split the HTTP request a client sends. "
                        "Treat the server as hostile; conforming clients must drop this tool."
                    ),
                    severity=Severity.HIGH,
                )
                continue
            problem = self._value_problem(value, seen, path) or _type_problem(prop)
            if problem:
                yield self.finding(
                    location=location,
                    evidence=truncate(f"{HEADER_KEY}={value!r}: {problem}", 300),
                    remediation=(
                        "Fix the tool definition: the header name must be a unique HTTP token on "
                        "a string / integer / boolean parameter. Until then clients drop the tool."
                    ),
                )
            elif _is_secret_param(path, prop):
                yield self.finding(
                    title="Credential-bearing parameter mirrored into an HTTP header",
                    location=location,
                    evidence=f"{path} -> Mcp-Param-{value}",
                    remediation=(
                        "Headers are copied into proxy, WAF, CDN, and access logs. Do not mirror "
                        "secrets; pass them in the body or through the authorization flow."
                    ),
                )
        for path in _all_designations(schema):
            if path not in valid_paths:
                yield self.finding(
                    location=Location(server=target.name, tool=tool.name, field=f"inputSchema.{path}"),
                    evidence=(
                        f"{HEADER_KEY} at {path}: not reachable from the schema root through "
                        "'properties' alone (items / anyOf / $ref / if-then are not allowed)"
                    ),
                    remediation=(
                        "Move the designation onto a top-level or nested 'properties' parameter, "
                        "or remove it. Clients must reject tools with misplaced designations."
                    ),
                )

    @staticmethod
    def _value_problem(value: object, seen: dict[str, str], path: str) -> str | None:
        if not isinstance(value, str) or not value:
            return "the header name must be a non-empty string"
        if not HTTP_TOKEN_RE.match(value):
            return "the header name is not an HTTP field-name token"
        first = seen.setdefault(value.lower(), path)
        if first != path:
            return f"duplicates the header name used by {first} (case-insensitive)"
        return None


def _authenticated(spec: MCPServerSpec) -> str | None:
    """Evidence that requests to this server carry credentials, if any."""
    for name in spec.headers:
        if AUTH_HEADER_NAME_RE.match(name):
            return f"{name} header"
    if spec.url and (URL_USERINFO_RE.match(spec.url) or URL_SECRET_PARAM_RE.search(spec.url)):
        return "credentials in the URL"
    for index, arg in enumerate(spec.args):
        if arg == "--header" and index + 1 < len(spec.args):
            header = spec.args[index + 1].split(":", 1)[0].strip()
            if AUTH_HEADER_NAME_RE.match(header):
                return f"{header} header (bridge argument)"
    return None


@register
class CacheHintRule(Rule):
    id = "CACHE01"
    title = "Tool list cache hint weakens change detection"
    category = Category.RUG_PULL
    default_severity = Severity.LOW
    mappings = ("MCP-2026-07-28-SEP-2549", "MCP-RUG-PULL", "OWASP-ASI04")

    def analyze(self, target: MCPServerSpec, ctx: AnalysisContext) -> Iterable[Finding]:
        manifest = ctx.effective_manifest(target)
        if manifest is None:
            return
        location = Location(server=target.name, field="cacheScope")
        auth = _authenticated(target)
        if manifest.cache_scope == "public" and auth:
            yield self.finding(
                title="Authenticated tool list marked cacheScope: public",
                location=location,
                evidence=f"cacheScope=public; requests carry {auth}",
                remediation=(
                    "Shared caches may store this per-user catalog and serve it to other users, "
                    "and a poisoned copy outlives the fix. Serve authenticated lists with "
                    "cacheScope: private."
                ),
                severity=Severity.MEDIUM,
            )
        if manifest.ttl_ms is not None and manifest.ttl_ms > LONG_CACHE_TTL_MS:
            hours = manifest.ttl_ms / 3_600_000
            yield self.finding(
                location=Location(server=target.name, field="ttlMs"),
                evidence=f"ttlMs={manifest.ttl_ms} (~{hours:.0f}h)",
                remediation=(
                    "Clients may keep serving a cached tool list this long, so a changed "
                    "definition is invisible to them until it expires. A cached list is not a "
                    "reviewed one: pin it with `mcpguard lock` and re-check on every connect."
                ),
            )
