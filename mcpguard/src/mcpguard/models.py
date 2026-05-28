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


@dataclass(frozen=True, slots=True)
class MCPTool:
    """A tool advertised by an MCP server."""

    name: str
    description: str = ""
    input_schema: dict[str, object] = field(default_factory=dict)

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


@dataclass(frozen=True, slots=True)
class MCPResource:
    uri: str
    name: str = ""
    description: str = ""


@dataclass(frozen=True, slots=True)
class MCPPrompt:
    name: str
    description: str = ""


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


@dataclass(frozen=True, slots=True)
class MCPServerSpec:
    """A scan target: one MCP server, however it was declared.

    ``command``/``args``/``env`` describe a local STDIO server; ``url`` describes
    a remote one. ``source_path`` points at on-disk source if we can locate it
    (enables source-level RCE analysis). ``manifest`` is attached when known.
    """

    name: str
    transport: Transport = Transport.UNKNOWN
    command: str | None = None
    args: tuple[str, ...] = ()
    env: dict[str, str] = field(default_factory=dict)
    url: str | None = None
    source_path: str | None = None
    manifest: MCPManifest | None = None

    @property
    def command_line(self) -> str:
        """The full command line as a single string (for pattern matching)."""
        parts = [self.command, *self.args] if self.command else list(self.args)
        return " ".join(p for p in parts if p)
