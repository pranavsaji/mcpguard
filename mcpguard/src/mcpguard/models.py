"""Core domain models for MCPGuard.

This module is the stable contract every other component depends on:

* MCP domain objects (:class:`MCPServerSpec`, :class:`MCPTool`,
  :class:`MCPManifest`) describe *what* is being scanned.
* Finding objects (:class:`Severity`, :class:`Category`, :class:`Finding`,
  :class:`Report`) describe *what was discovered*.

Everything here is pure stdlib and immutable where practical, so models can be
freely shared between threads, serialized, and compared in tests.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum, IntEnum

__all__ = [
    "Severity",
    "Category",
    "Location",
    "Finding",
    "Report",
    "MCPTool",
    "MCPResource",
    "MCPPrompt",
    "MCPManifest",
    "MCPServerSpec",
    "Transport",
]


class Severity(IntEnum):
    """Ordered severity levels.

    Implemented as :class:`IntEnum` so findings can be compared and filtered by
    a minimum threshold (``finding.severity >= Severity.HIGH``).
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | Severity) -> Severity:
        """Parse a case-insensitive name (``"high"``) into a :class:`Severity`."""
        if isinstance(value, Severity):
            return value
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:  # pragma: no cover - exercised via CLI tests
            valid = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {value!r}; expected one of: {valid}") from exc

    def __str__(self) -> str:
        return self.name.lower()


class Category(str, Enum):
    """The class of weakness a finding belongs to.

    Subclassing :class:`str` makes categories JSON-serializable and ergonomic to
    compare against plain strings in tests.
    """

    TOOL_POISONING = "tool_poisoning"
    HIDDEN_CONTENT = "hidden_content"
    EXCESSIVE_AGENCY = "excessive_agency"
    RCE_SURFACE = "rce_surface"
    SECRETS = "secrets"
    SUPPLY_CHAIN = "supply_chain"
    RUG_PULL = "rug_pull"
    MANIFEST_DRIFT = "manifest_drift"
    TOOL_SHADOWING = "tool_shadowing"
    TOXIC_FLOW = "toxic_flow"
    VULNERABLE_COMPONENT = "vulnerable_component"
    INSECURE_CONFIG = "insecure_config"
    INSECURE_TRANSPORT = "insecure_transport"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class Location:
    """Where a finding was observed, as specifically as the rule can pinpoint.

    All fields are optional; a rule fills in whatever it knows. ``__str__``
    renders a compact, human-readable breadcrumb.
    """

    server: str | None = None
    tool: str | None = None
    field: str | None = None
    path: str | None = None
    line: int | None = None

    def __str__(self) -> str:
        parts: list[str] = []
        if self.server:
            parts.append(f"server={self.server}")
        if self.tool:
            parts.append(f"tool={self.tool}")
        if self.field:
            parts.append(f"field={self.field}")
        if self.path:
            loc = self.path if self.line is None else f"{self.path}:{self.line}"
            parts.append(loc)
        return " ".join(parts) if parts else "<unknown>"

    def to_dict(self) -> dict[str, object]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass(frozen=True, slots=True)
class Finding:
    """A single security observation produced by a rule.

    Findings are immutable and hashable so they can be deduplicated and compared
    deterministically in tests.
    """

    rule_id: str
    title: str
    severity: Severity
    category: Category
    location: Location
    evidence: str
    remediation: str
    mappings: tuple[str, ...] = ()
    confidence: float = 1.0

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be in [0, 1], got {self.confidence}")
        if not self.rule_id:
            raise ValueError("rule_id must be non-empty")

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": str(self.severity),
            "category": str(self.category),
            "location": self.location.to_dict(),
            "evidence": self.evidence,
            "remediation": self.remediation,
            "mappings": list(self.mappings),
            "confidence": self.confidence,
        }


@dataclass
class Report:
    """The result of scanning one target: an ordered set of findings + helpers."""

    target: str
    findings: list[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def extend(self, findings: list[Finding]) -> None:
        self.findings.extend(findings)

    def sorted(self) -> list[Finding]:
        """Findings ordered by descending severity, then rule id (stable)."""
        return sorted(self.findings, key=lambda f: (-int(f.severity), f.rule_id))

    def filter(self, min_severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity >= min_severity]

    @property
    def max_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)

    def counts(self) -> dict[str, int]:
        """Count of findings per severity name (omitting zero buckets)."""
        out: dict[str, int] = {}
        for f in self.findings:
            out[str(f.severity)] = out.get(str(f.severity), 0) + 1
        return out

    def failed(self, threshold: Severity) -> bool:
        """True if any finding is at or above ``threshold`` (CI gate signal)."""
        return any(f.severity >= threshold for f in self.findings)

    def exit_code(self, threshold: Severity) -> int:
        return 1 if self.failed(threshold) else 0

    def to_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "summary": {
                "total": len(self.findings),
                "by_severity": self.counts(),
                "max_severity": str(self.max_severity) if self.max_severity else None,
            },
            "findings": [f.to_dict() for f in self.sorted()],
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False)


# --------------------------------------------------------------------------- #
# MCP domain models                                                           #
# --------------------------------------------------------------------------- #


class Transport(str, Enum):
    """How a client talks to an MCP server."""

    STDIO = "stdio"
    HTTP = "http"
    SSE = "sse"
    UNKNOWN = "unknown"

    def __str__(self) -> str:
        return self.value


# Keywords holding a map of *named* subschemas; their keys are names, not keywords.
_NAMED_SUBSCHEMA_KEYS: frozenset[str] = frozenset(
    {"properties", "patternProperties", "$defs", "definitions", "dependentSchemas", "dependencies"}
)
# Standard JSON Schema keywords. Any *other* key is itself model-visible text.
_SCHEMA_KEYWORDS: frozenset[str] = frozenset({
    "$schema", "$id", "$ref", "$anchor", "$dynamicRef", "$dynamicAnchor", "$comment", "$vocabulary",
    "type", "title", "description", "default", "examples", "enum", "const", "format", "pattern",
    "required", "items", "prefixItems", "additionalItems", "additionalProperties", "contains",
    "minContains", "maxContains", "propertyNames", "unevaluatedItems", "unevaluatedProperties",
    "anyOf", "oneOf", "allOf", "not", "if", "then", "else", "minimum", "maximum",
    "exclusiveMinimum", "exclusiveMaximum", "multipleOf", "minLength", "maxLength", "minItems",
    "maxItems", "uniqueItems", "minProperties", "maxProperties", "dependentRequired",
    "contentEncoding", "contentMediaType", "contentSchema", "readOnly", "writeOnly", "deprecated",
    "nullable", *_NAMED_SUBSCHEMA_KEYS,
})
_MAX_SCHEMA_DEPTH = 32


def schema_text_fields(schema: object, prefix: str = "") -> list[tuple[str, str]]:
    """Every model-visible string in a JSON schema as ``(path, text)`` pairs.

    Walks *every* string value (descriptions, titles, defaults, enums, examples,
    ``required`` entries, even ``type``), every non-keyword key, and every
    property / definition name, at any depth and through any composition
    keyword. This is the "Full-Schema Poisoning" surface: the model reads the
    whole schema, so an injection in a nested enum or an unknown ``x-`` key is
    as live as one in a description. Paths read like ``q.title`` /
    ``opts.mode.enum`` / ``q.<name>`` (a property name) / ``q.x-note#key``.
    """
    out: list[tuple[str, str]] = []
    _walk_schema(schema, prefix, out, 0)
    return out


def _walk_schema(node: object, path: str, out: list[tuple[str, str]], depth: int) -> None:
    if depth > _MAX_SCHEMA_DEPTH:
        return
    if isinstance(node, str):
        if node:
            out.append((path, node))
    elif isinstance(node, list):
        scalars = [str(v) for v in node if isinstance(v, (str, int, float)) and not isinstance(v, bool)]
        if any(scalars):
            out.append((path, " | ".join(scalars)))
        for index, item in enumerate(node):
            if isinstance(item, (dict, list)):
                _walk_schema(item, f"{path}[{index}]", out, depth + 1)
    elif isinstance(node, dict):
        for raw_key, value in node.items():
            key = str(raw_key)
            child = f"{path}.{key}" if path else key
            if key in _NAMED_SUBSCHEMA_KEYS and isinstance(value, dict):
                for raw_name, sub in value.items():
                    name = str(raw_name)
                    named = f"{path}.{name}" if path else name
                    out.append((f"{named}.<name>", name))
                    _walk_schema(sub, named, out, depth + 1)
                continue
            if key not in _SCHEMA_KEYWORDS:
                out.append((f"{child}#key", key))
            _walk_schema(value, child, out, depth + 1)


@dataclass(frozen=True, slots=True)
class MCPTool:
    """A tool advertised by an MCP server.

    ``annotations`` are the MCP behavior hints (``readOnlyHint``,
    ``destructiveHint``, ``openWorldHint``, ``title``); ``output_schema`` is the
    structured-output schema. Both are model-visible and carried for analysis.
    """

    name: str
    description: str = ""
    input_schema: dict[str, object] = field(default_factory=dict)
    title: str = ""
    annotations: dict[str, object] = field(default_factory=dict)
    output_schema: dict[str, object] = field(default_factory=dict)

    @property
    def parameter_descriptions(self) -> dict[str, str]:
        """Map of ``parameter name -> description`` pulled from the JSON schema."""
        props = self.input_schema.get("properties")
        if not isinstance(props, dict):
            return {}
        out: dict[str, str] = {}
        for pname, pschema in props.items():
            if isinstance(pschema, dict):
                desc = pschema.get("description")
                if isinstance(desc, str):
                    out[str(pname)] = desc
        return out

    def text_fields(self) -> list[tuple[str, str]]:
        """Every model-visible text field as ``(field label, text)``.

        The description, title, annotation title, and every string anywhere in
        the input and output schemas (see :func:`schema_text_fields`).
        """
        fields: list[tuple[str, str]] = [("description", self.description)]
        if self.title:
            fields.append(("title", self.title))
        ann_title = self.annotations.get("title")
        if isinstance(ann_title, str) and ann_title:
            fields.append(("annotations.title", ann_title))
        # Walk ``properties`` as a map so paths start at the parameter name.
        for path, text in schema_text_fields({"properties": self.input_schema.get("properties")}):
            if path.endswith(".<name>"):
                fields.append((f"param:{path.removesuffix('.<name>')}#name", text))
            else:  # "q.description" -> "param:q"; "q.enum" -> "param:q.enum"
                fields.append((f"param:{path.removesuffix('.description')}", text))
        rest = {k: v for k, v in self.input_schema.items() if k != "properties"}
        fields.extend((f"inputSchema.{p}", t) for p, t in schema_text_fields(rest))
        fields.extend((f"outputSchema.{p}", t) for p, t in schema_text_fields(self.output_schema))
        return [(label, text) for label, text in fields if text]


@dataclass(frozen=True, slots=True)
class MCPResource:
    uri: str
    name: str = ""
    description: str = ""


@dataclass(frozen=True, slots=True)
class MCPPrompt:
    """A prompt template; ``arguments`` maps argument name -> description."""

    name: str
    description: str = ""
    arguments: dict[str, str] = field(default_factory=dict)

    def text_fields(self) -> list[tuple[str, str]]:
        fields = [("description", self.description)]
        fields.extend((f"arg:{name}", desc) for name, desc in self.arguments.items())
        return [(label, text) for label, text in fields if text]


@dataclass(frozen=True, slots=True)
class MCPManifest:
    """The advertised surface of an MCP server (tools/resources/prompts).

    May be sourced statically (from a declared manifest) or dynamically (by
    connecting and enumerating). ``instructions`` is the server-level system
    prompt many servers expose.
    """

    instructions: str = ""
    tools: tuple[MCPTool, ...] = ()
    resources: tuple[MCPResource, ...] = ()
    prompts: tuple[MCPPrompt, ...] = ()

    def text_fields(self) -> list[tuple[str | None, str, str]]:
        """Every model-visible string as ``(owner, field, text)``.

        ``owner`` is the tool / prompt / resource the text belongs to (``None``
        for server instructions). This is the full metadata attack surface that
        the poisoning, hidden-content, and shadowing rules scan.
        """
        out: list[tuple[str | None, str, str]] = []
        if self.instructions:
            out.append((None, "instructions", self.instructions))
        for tool in self.tools:
            out.extend((tool.name, label, text) for label, text in tool.text_fields())
        for prompt in self.prompts:
            out.extend((prompt.name, label, text) for label, text in prompt.text_fields())
        for resource in self.resources:
            if resource.description:
                out.append((resource.name or resource.uri, "description", resource.description))
        return out


@dataclass(frozen=True, slots=True)
class MCPServerSpec:
    """A scan target: one MCP server, however it was declared.

    ``command``/``args``/``env`` describe a local STDIO server; ``url`` describes
    a remote one (with any HTTP ``headers``, e.g. auth). ``source_path`` points at on-disk source if we can locate it
    (enables source-level RCE analysis). ``manifest`` is attached when known.
    """

    name: str
    transport: Transport = Transport.UNKNOWN
    command: str | None = None
    args: tuple[str, ...] = ()
    env: dict[str, str] = field(default_factory=dict)
    url: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    source_path: str | None = None
    manifest: MCPManifest | None = None

    @property
    def command_line(self) -> str:
        """The full command line as a single string (for pattern matching)."""
        parts = [self.command, *self.args] if self.command else list(self.args)
        return " ".join(p for p in parts if p)
