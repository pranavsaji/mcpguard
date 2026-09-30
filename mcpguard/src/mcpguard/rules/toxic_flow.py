"""FLOW01 — toxic flow / "lethal trifecta" across the configured servers.

Indirect prompt injection needs no malicious server: a benign tool reads text an
attacker wrote (a GitHub issue, an email, a web page), the model obeys it, and
other benign tools carry out the theft — the GitHub-MCP and Supabase-MCP
incidents (2025). The payload arrives at run time, so it can't be scanned for;
what *can* be found before deployment is the combination of capabilities that
makes it exploitable. This rule classifies every tool in the config into:

* **untrusted input** — reads third-party-authored content (the injection entry),
* **private data** — reaches data the user would not want leaked,
* **external sink** — can move data off the machine (the exfiltration path),
* **code execution** — (from CAP01's vocabulary) turns injected text into commands.

It flags the whole-config *lethal trifecta* (untrusted + private + sink) and
untrusted input co-resident with code execution. The finding is reported on each
server that contributes an untrusted-input tool — the entry point to lock down.

Tool roles come from the effective manifest (declared or ``--connect``) — tool
names, plus an AI judge's reading of name + description with ``--ai``; servers
with no manifest fall back to a small table of well-known packages, at lower
severity and confidence. Maps to OWASP LLM01 (indirect) and Agentic excessive agency.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..context import AnalysisContext
from ..launchers import command_basename, parse_launch
from ..models import Category, Finding, Location, MCPManifest, MCPServerSpec, MCPTool, Severity
from ..patterns import (
    CAPABILITY_KEYWORDS,
    CONTAINER_RUNTIMES,
    EXTERNAL_SINK_KEYWORDS,
    KNOWN_SERVER_ROLES,
    PRIVATE_DATA_KEYWORDS,
    UNTRUSTED_INPUT_KEYWORDS,
)
from ..util import contains_phrase, keyword_phrases, normalize_word, truncate, words
from .base import Rule, register
from .pinning import container_image

if TYPE_CHECKING:
    from ..ai import AIConfig

UNTRUSTED, PRIVATE, SINK, EXEC = "untrusted", "private", "sink", "exec"

_ROLE_PHRASES: dict[str, tuple[tuple[str, ...], ...]] = {
    UNTRUSTED: keyword_phrases(UNTRUSTED_INPUT_KEYWORDS),
    PRIVATE: keyword_phrases(PRIVATE_DATA_KEYWORDS),
    SINK: keyword_phrases(EXTERNAL_SINK_KEYWORDS),
    EXEC: keyword_phrases(
        CAPABILITY_KEYWORDS["code execution"] + CAPABILITY_KEYWORDS["shell / command"]
    ),
}


def tool_roles(tool: MCPTool) -> set[str]:
    """Roles inferred from a tool's *name* (descriptions are too noisy for this)."""
    name_words = [normalize_word(w) for w in words(tool.name)]
    roles = {
        role
        for role, phrases in _ROLE_PHRASES.items()
        if any(contains_phrase(name_words, phrase) for phrase in phrases)
    }
    # openWorldHint=true means the tool touches the outside world by its own account.
    if tool.annotations.get("openWorldHint") is True and roles & {PRIVATE, SINK}:
        roles.add(SINK)
    return roles


def _known_package(spec: MCPServerSpec) -> str | None:
    launch = parse_launch(spec.command, spec.args)
    if launch is not None:
        return launch.name
    if spec.command and command_basename(spec.command) in CONTAINER_RUNTIMES:
        image = container_image(spec.args)
        if image:
            return image.split("@", 1)[0].rsplit(":", 1)[0] if "/" in image else image
    return None


@dataclass
class _Flow:
    # role -> [(server name, label, inferred from package name?)]
    tools: dict[str, list[tuple[str, str, bool]]] = field(default_factory=dict)

    def add(self, role: str, server: str, label: str, inferred: bool) -> None:
        self.tools.setdefault(role, []).append((server, label, inferred))

    def labels(self, role: str, server: str | None = None) -> list[str]:
        return [label for srv, label, _ in self.tools.get(role, []) if server in (None, srv)]

    def has(self, role: str, *, manifest_only: bool = False) -> bool:
        return any(not inferred or not manifest_only for _, _, inferred in self.tools.get(role, []))


_AI_ROLES = {
    "untrusted_input": UNTRUSTED,
    "private_data": PRIVATE,
    "external_sink": SINK,
    "code_exec": EXEC,
}


def ai_tool_roles(tool: MCPTool, ai: AIConfig) -> set[str]:
    """Roles an AI judge reads from the tool's name and description (``--ai``)."""
    verdict = ai.ask("roles", f"name: {tool.name}\ndescription: {tool.description}")
    if verdict is None:
        return set()
    return {role for q, role in _AI_ROLES.items() if verdict.scores.get(q, 0.0) >= ai.role_threshold}


def _classify_config(
    peers: tuple[tuple[MCPServerSpec, MCPManifest | None], ...],
    ai: AIConfig | None = None,
) -> tuple[_Flow, dict[str, set[str]]]:
    """Roles across the whole config, plus each server's own role set."""
    flow = _Flow()
    per_server = {spec.name: _server_roles(spec, manifest, flow, ai) for spec, manifest in peers}
    return flow, per_server


def _server_roles(
    spec: MCPServerSpec, manifest: MCPManifest | None, flow: _Flow, ai: AIConfig | None = None
) -> set[str]:
    roles: set[str] = set()
    if manifest is not None and manifest.tools:
        for tool in manifest.tools:
            inferred = tool_roles(tool) | (ai_tool_roles(tool, ai) if ai is not None else set())
            for role in inferred:
                roles.add(role)
                flow.add(role, spec.name, f"{spec.name}/{tool.name}", False)
        return roles
    package = _known_package(spec)
    if package and package in KNOWN_SERVER_ROLES:
        for role in KNOWN_SERVER_ROLES[package]:
            roles.add(role)
            flow.add(role, spec.name, f"{spec.name} ({package})", True)
    return roles


def _summarize(labels: list[str]) -> str:
    return ", ".join(labels[:4]) + (f" (+{len(labels) - 4} more)" if len(labels) > 4 else "")


@register
class ToxicFlowRule(Rule):
    id = "FLOW01"
    title = "Lethal trifecta: untrusted input + private data + exfiltration path"
    category = Category.TOXIC_FLOW
    default_severity = Severity.HIGH
    mappings = (
        "OWASP-LLM01", "MCP-TOXIC-FLOW", "OWASP-AGENTIC-EXCESSIVE-AGENCY", "OWASP-ASI01", "OWASP-ASI02",
    )

    def analyze(self, target: MCPServerSpec, ctx: AnalysisContext) -> Iterable[Finding]:
        peers = ctx.peers or ((target, ctx.effective_manifest(target)),)
        flow, per_server = _classify_config(peers, ctx.ai)
        if UNTRUSTED not in per_server.get(target.name, set()):
            return  # only report on the servers that let attacker text in

        entry = _summarize(flow.labels(UNTRUSTED, target.name))
        location = Location(server=target.name)

        if flow.has(PRIVATE) and flow.has(SINK):
            # Full confidence only when every leg is backed by a real manifest.
            observed = all(flow.has(r, manifest_only=True) for r in (UNTRUSTED, PRIVATE, SINK))
            yield self.finding(
                location=location,
                evidence=truncate(
                    f"untrusted input: {entry}; private data: {_summarize(flow.labels(PRIVATE))}; "
                    f"exfiltration: {_summarize(flow.labels(SINK))}",
                    400,
                ),
                remediation=(
                    "Injected text read by one tool can drive the others to leak private data. "
                    "Split these servers across separate agent sessions, remove one leg of the "
                    "trifecta, or require human approval for every sink call."
                ),
                severity=Severity.HIGH if observed else Severity.MEDIUM,
                confidence=0.6 if observed else 0.4,
            )
        if flow.has(EXEC):
            observed = flow.has(UNTRUSTED, manifest_only=True) and flow.has(EXEC, manifest_only=True)
            yield self.finding(
                title="Untrusted input can reach code execution",
                location=location,
                evidence=truncate(
                    f"untrusted input: {entry}; code execution: {_summarize(flow.labels(EXEC))}",
                    400,
                ),
                remediation=(
                    "Text an attacker controls can become a command. Sandbox the execution tool "
                    "and require human approval for it, or remove the untrusted-input tool."
                ),
                severity=Severity.HIGH if observed else Severity.MEDIUM,
                confidence=0.6 if observed else 0.4,
            )
