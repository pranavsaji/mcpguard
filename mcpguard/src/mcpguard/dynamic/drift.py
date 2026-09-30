"""MAN01 — manifest drift / rug pull (dynamic).

An MCP server can advertise benign tools at review time, then mutate its surface
after it has earned trust (a "rug pull"). This dynamic rule compares the
*declared* manifest (the baseline you reviewed / committed) against the *live*
manifest enumerated at scan time and flags:

* tools present live but not declared (silently added capability),
* tools declared but missing live (swapped out or renamed),
* tool descriptions that changed (possible re-poisoning),
* tool input schemas that changed — new parameters or changed parameter
  descriptions are high severity (a new injection surface); other schema changes
  are medium. Skipped for tools whose baseline records no schema.
* server ``instructions`` that changed, and prompts / resources that were added,
  removed, or re-described — each section is compared only when the baseline
  declares it, so a baseline that records tools alone isn't flooded with noise.

The baseline is the reviewed lockfile (``--baseline mcpguard.lock.json``, see
:mod:`mcpguard.lockfile`) when given, else the manifest declared in the config.
The current state is the live manifest (``--connect``), else — when a lockfile
supplies the baseline — the declared manifest. No-ops without both sides.

MAN02 (below) covers what changes *around* the manifest: a server's launch
line or URL changing since review (a package / version / image swap), and
servers that were never reviewed at all.

Maps to the MCP rug-pull / manifest-drift class.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Sequence
from typing import TYPE_CHECKING

from ..context import AnalysisContext
from ..lockfile import launch_identity, manifest_dict
from ..models import Category, Finding, Location, MCPManifest, MCPServerSpec, MCPTool, Severity
from ..rules.base import Rule, register
from ..util import canonical_json as _canonical
from ..util import truncate

if TYPE_CHECKING:
    from ..ai import AIConfig

_REREVIEW = "Re-review the server before trusting it again, and re-pin its version."


def _properties(tool: MCPTool) -> dict[str, object]:
    props = tool.input_schema.get("properties")
    return props if isinstance(props, dict) else {}


def _prompts(manifest: MCPManifest) -> list[tuple[str, str]]:
    """Prompts keyed by name; arguments are folded in so their drift is caught too."""
    return [
        (p.name, p.description + (f" args={_canonical(p.arguments)}" if p.arguments else ""))
        for p in manifest.prompts
    ]


@register
class ManifestDriftRule(Rule):
    id = "MAN01"
    title = "MCP server manifest drifted from baseline"
    category = Category.RUG_PULL
    default_severity = Severity.HIGH
    mappings = ("MCP-RUG-PULL", "MCP-MANIFEST-DRIFT")

    def analyze(self, target: MCPServerSpec, ctx: AnalysisContext) -> Iterable[Finding]:
        locked = ctx.baseline_for(target)
        if locked is not None and locked.manifest is not None:
            declared: MCPManifest | None = locked.manifest
            live = ctx.live_manifest if ctx.live_manifest is not None else target.manifest
        else:
            declared, live = target.manifest, ctx.live_manifest
        if declared is None or live is None:
            return  # nothing to compare against
        # A lockfile records the whole reviewed manifest, so a field that was empty
        # there was *empty at review*: anything added since is drift. A declared
        # manifest in a config is often partial, so there only recorded fields count.
        strict = locked is not None and locked.manifest is not None
        findings = [
            *self._diff_tools(target, declared, live, strict, ctx.ai),
            *self._diff_instructions(target, declared, live, strict, ctx.ai),
            *self._diff_named(target, "prompt", _prompts(declared), _prompts(live), strict),
            *self._diff_named(
                target, "resource", [(r.uri, r.description) for r in declared.resources],
                [(r.uri, r.description) for r in live.resources], strict,
            ),
        ]
        if strict and not findings and _canonical(manifest_dict(declared)) != _canonical(
            manifest_dict(live)
        ):
            findings.append(self.finding(
                title="MCP server manifest changed since baseline",
                location=Location(server=target.name),
                evidence="manifest hash differs from the reviewed lockfile",
                remediation=_REREVIEW,
            ))
        yield from findings

    # --- tools ------------------------------------------------------------------

    def _diff_tools(
        self,
        target: MCPServerSpec,
        declared: MCPManifest,
        live: MCPManifest,
        strict: bool,
        ctx_ai: AIConfig | None = None,
    ) -> Iterator[Finding]:
        baseline = {t.name: t for t in declared.tools}
        live_names = {t.name for t in live.tools}
        for tool in live.tools:
            prior = baseline.get(tool.name)
            if prior is None:
                yield self.finding(
                    title="Undeclared tool appeared on live server",
                    location=Location(server=target.name, tool=tool.name),
                    evidence=f"tool {tool.name!r} is served live but absent from the reviewed baseline",
                    remediation=(
                        "Treat newly-appearing tools as untrusted. Re-review and re-pin "
                        "the server; a server adding tools post-approval is a rug-pull signal."
                    ),
                )
                continue
            if prior.description != tool.description:
                yield from self._semantic(
                    target, ctx_ai, prior.description, tool.description, tool.name, "description"
                )
                yield self.finding(
                    title="Tool description changed since baseline",
                    location=Location(server=target.name, tool=tool.name, field="description"),
                    evidence=truncate(f"was: {prior.description!r} now: {tool.description!r}"),
                    remediation=(
                        "A tool's description changed after review. Re-inspect it for "
                        "injected instructions and re-pin the server version."
                    ),
                )
            yield from self._diff_schema(target, prior, tool, strict)
            yield from self._diff_extras(target, prior, tool, strict)

        for name in baseline:
            if name not in live_names:
                yield self.finding(
                    title="Declared tool missing from live server",
                    location=Location(server=target.name, tool=name),
                    evidence=f"tool {name!r} is in the reviewed baseline but not served live",
                    remediation=(
                        "A reviewed tool disappeared; it may have been renamed or swapped for "
                        "a different implementation. " + _REREVIEW
                    ),
                    severity=Severity.MEDIUM,
                )

    def _diff_schema(
        self, target: MCPServerSpec, prior: MCPTool, tool: MCPTool, strict: bool
    ) -> Iterator[Finding]:
        if (not strict and not prior.input_schema) or _canonical(prior.input_schema) == _canonical(
            tool.input_schema
        ):
            return
        before, after = _properties(prior), _properties(tool)
        added = sorted(set(after) - set(before))
        removed = sorted(set(before) - set(after))
        old_desc, new_desc = prior.parameter_descriptions, tool.parameter_descriptions
        redescribed = sorted(
            p for p in set(before) & set(after) if old_desc.get(p) != new_desc.get(p)
        )
        retyped = sorted(
            p
            for p in set(before) & set(after)
            if p not in redescribed and _canonical(before[p]) != _canonical(after[p])
        )

        details = [
            f"{label}: {', '.join(names)}"
            for label, names in (
                ("added params", added),
                ("removed params", removed),
                ("re-described params", redescribed),
                ("changed params", retyped),
            )
            if names
        ] or ["schema changed outside parameter definitions"]
        yield self.finding(
            title="Tool input schema changed since baseline",
            location=Location(server=target.name, tool=tool.name, field="inputSchema"),
            evidence=truncate("; ".join(details)),
            remediation=(
                "A tool's parameters changed after review. New or re-described parameters "
                "are fresh places to hide instructions. " + _REREVIEW
            ),
            severity=Severity.HIGH if added or redescribed else Severity.MEDIUM,
        )

    def _diff_extras(
        self, target: MCPServerSpec, prior: MCPTool, tool: MCPTool, strict: bool
    ) -> Iterator[Finding]:
        """Annotations, output schema, and title — compared when the baseline recorded them."""
        if (strict or prior.annotations) and _canonical(prior.annotations) != _canonical(tool.annotations):
            changed = sorted(
                k for k in set(prior.annotations) | set(tool.annotations)
                if prior.annotations.get(k) != tool.annotations.get(k)
            )
            yield self.finding(
                title="Tool annotations changed since baseline",
                location=Location(server=target.name, tool=tool.name, field="annotations"),
                evidence=truncate(
                    "; ".join(
                        f"{k}: {prior.annotations.get(k)!r} -> {tool.annotations.get(k)!r}"
                        for k in changed
                    )
                ),
                remediation=(
                    "Behavior hints (readOnlyHint, destructiveHint, ...) changed after review; "
                    "clients may now auto-approve a tool that became dangerous. " + _REREVIEW
                ),
            )
        if (strict or prior.output_schema) and _canonical(prior.output_schema) != _canonical(tool.output_schema):
            yield self.finding(
                title="Tool output schema changed since baseline",
                location=Location(server=target.name, tool=tool.name, field="outputSchema"),
                evidence="outputSchema differs from the reviewed baseline",
                remediation="Re-inspect the output schema for injected text. " + _REREVIEW,
                severity=Severity.MEDIUM,
            )
        if (strict or prior.title) and prior.title != tool.title:
            yield self.finding(
                title="Tool title changed since baseline",
                location=Location(server=target.name, tool=tool.name, field="title"),
                evidence=truncate(f"was: {prior.title!r} now: {tool.title!r}"),
                remediation="Re-inspect the title for injected text. " + _REREVIEW,
                severity=Severity.MEDIUM,
            )

    def _semantic(
        self,
        target: MCPServerSpec,
        ai: AIConfig | None,
        before: str,
        after: str,
        tool: str | None,
        field: str,
    ) -> Iterator[Finding]:
        """With ``--ai``: escalate a text change that adds model-directed behavior."""
        if ai is None:
            return
        verdict = ai.ask("drift", {"before": before, "after": after})
        if verdict is None:
            return
        p = verdict.scores.get("adds_instructions", 0.0)
        if p >= ai.threshold:
            yield self.finding(
                title="Changed text adds model-directed behavior (AI judge)",
                location=Location(server=target.name, tool=tool, field=field),
                evidence=f"{verdict.judge}: adds instructions / data flows / secrecy p={p:.2f}",
                remediation=(
                    "An AI judge reads this post-review change as adding behavior, not fixing "
                    "wording — the rug-pull pattern. " + _REREVIEW
                ),
                severity=Severity.CRITICAL,
                confidence=round(p, 2),
            )

    # --- instructions / prompts / resources -----------------------------------------

    def _diff_instructions(
        self,
        target: MCPServerSpec,
        declared: MCPManifest,
        live: MCPManifest,
        strict: bool,
        ctx_ai: AIConfig | None = None,
    ) -> Iterator[Finding]:
        if (strict or declared.instructions) and declared.instructions != live.instructions:
            yield from self._semantic(
                target, ctx_ai, declared.instructions, live.instructions, None, "instructions"
            )
            yield self.finding(
                title="Server instructions changed since baseline",
                location=Location(server=target.name, field="instructions"),
                evidence=truncate(f"was: {declared.instructions!r} now: {live.instructions!r}"),
                remediation=(
                    "The server-level instructions the model reads changed after review. "
                    "Re-inspect them for injected directives. " + _REREVIEW
                ),
            )

    def _diff_named(
        self,
        target: MCPServerSpec,
        kind: str,
        declared: Sequence[tuple[str, str]],
        live: Sequence[tuple[str, str]],
        strict: bool,
    ) -> Iterator[Finding]:
        if not declared and not strict:
            return
        baseline = dict(declared)
        current = dict(live)
        for key, description in current.items():
            if key not in baseline:
                yield self.finding(
                    title=f"Undeclared {kind} appeared on live server",
                    location=Location(server=target.name, tool=key),
                    evidence=f"{kind} {key!r} is served live but absent from the reviewed baseline",
                    remediation=f"Treat the new {kind} as untrusted. " + _REREVIEW,
                )
            elif baseline[key] != description:
                yield self.finding(
                    title=f"{kind.capitalize()} description changed since baseline",
                    location=Location(server=target.name, tool=key, field="description"),
                    evidence=truncate(f"was: {baseline[key]!r} now: {description!r}"),
                    remediation=f"Re-inspect the {kind} for injected instructions. " + _REREVIEW,
                )
        for key in baseline:
            if key not in current:
                yield self.finding(
                    title=f"Declared {kind} missing from live server",
                    location=Location(server=target.name, tool=key),
                    evidence=f"{kind} {key!r} is in the reviewed baseline but not served live",
                    remediation=_REREVIEW,
                    severity=Severity.MEDIUM,
                )


@register
class LaunchDriftRule(Rule):
    """MAN02 — server launch line or inventory changed since the reviewed baseline."""

    id = "MAN02"
    title = "MCP server changed since the reviewed baseline"
    category = Category.RUG_PULL
    default_severity = Severity.HIGH
    mappings = ("MCP-RUG-PULL", "MCP-SUPPLY-CHAIN")

    def analyze(self, target: MCPServerSpec, ctx: AnalysisContext) -> Iterable[Finding]:
        if ctx.baseline is None:
            return  # no --baseline: nothing reviewed to compare against
        locked = ctx.baseline_for(target)
        if locked is None:
            yield self.finding(
                title="MCP server not in the reviewed baseline",
                location=Location(server=target.name),
                evidence=truncate(launch_identity(target)),
                remediation=(
                    "This server was added after the baseline was reviewed. Review it, then "
                    "re-run `mcpguard lock` to approve it."
                ),
                severity=Severity.MEDIUM,
            )
            return
        current = launch_identity(target)
        if locked.launch and locked.launch != current:
            yield self.finding(
                location=Location(server=target.name, field="command"),
                evidence=truncate(f"was: {locked.launch!r} now: {current!r}", 300),
                remediation=(
                    "The command, package, version, image, URL, or env names changed since "
                    "review — the shape of a supply-chain swap. " + _REREVIEW
                ),
            )
