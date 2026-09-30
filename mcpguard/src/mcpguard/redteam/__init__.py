"""Red-team suite: measure what each detection layer catches, and what it wrongly flags.

Every case is an attack or a *hard* benign lookalike, on one surface:

* ``metadata`` — a tool manifest (tool poisoning, schema poisoning, smuggling, shadowing)
* ``output``   — a tool result (indirect prompt injection)
* ``config``   — an MCP client config (secrets, launch config, supply chain, transport)
* ``drift``    — a reviewed ``before`` config and a later ``after`` (rug pulls)
* ``flow``     — a multi-server config (toxic flows / lethal trifecta)
* ``source``   — server source files (command injection, path traversal, SQLi, SSRF)
* ``purpose``  — a server whose tools may exceed what its stated purpose needs

Each case is run through three layers: **static** (deterministic rules only),
**ai** (findings contributed by the AI judge), and **combined** (what a scan
with ``--ai`` reports). A case is *detected* by a layer when that layer yields a
finding at or above ``MEDIUM`` from a rule relevant to its surface.

``expect_static`` pins the deterministic outcome per case, so the suite doubles
as a regression test (``mcpguard redteam`` exits 1 on any change). Cases the
deterministic layer is *known* to miss — paraphrases, other languages,
obfuscation — carry ``expect_static: false``: they are what the AI layer is for.
"""

from __future__ import annotations

import json
import math
import os
import tempfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..config_parser import parse_config, parse_manifest
from ..lockfile import build_lock, load_lock
from ..models import Finding, MCPServerSpec, Severity
from ..scanner import scan_specs

if TYPE_CHECKING:
    from ..ai import AIConfig

__all__ = ["CaseResult", "RedTeamCase", "SuiteResult", "load_cases", "render_result", "run_suite"]

DETECT_AT = Severity.MEDIUM
BUNDLED_CASES = os.path.join(os.path.dirname(__file__), "cases.jsonl")

# Rules whose findings count as "detected" per surface. Capability and hygiene
# notes (CAP01 on a legitimately powerful tool, SUP01 on a demo config) are real
# findings but not detections of the attack under test.
RELEVANT_RULES: dict[str, frozenset[str]] = {
    "metadata": frozenset({"TP01", "TP02", "TP03", "AI01"}),
    "output": frozenset({"IPI01", "IPI02"}),
    "config": frozenset({"SEC01", "CFG01", "NET01", "SUP01", "SUP02"}),
    "drift": frozenset({"MAN01", "MAN02"}),
    "flow": frozenset({"FLOW01"}),
    "source": frozenset({"CMD01", "AI02"}),
    "purpose": frozenset({"AI03"}),
}
AI_RULES = frozenset({"AI01", "AI02", "AI03", "IPI02"})
SURFACES = tuple(RELEVANT_RULES)


@dataclass(frozen=True)
class RedTeamCase:
    id: str
    category: str
    technique: str
    surface: str
    label: str  # "attack" | "benign"
    payload: Any
    expect_static: bool | None = None
    source: str = ""

    @property
    def is_attack(self) -> bool:
        return self.label == "attack"


@dataclass
class CaseResult:
    case: RedTeamCase
    static: bool
    ai: bool | None  # None when no AI layer ran
    combined: bool
    evidence: str = ""

    @property
    def regression(self) -> bool:
        return self.case.expect_static is not None and self.static != self.case.expect_static


@dataclass
class SuiteResult:
    results: list[CaseResult] = field(default_factory=list)
    judge: str | None = None
    ai_errors: list[str] = field(default_factory=list)

    @property
    def regressions(self) -> list[CaseResult]:
        return [r for r in self.results if r.regression]

    def _layer(self, r: CaseResult, layer: str) -> bool | None:
        return {"static": r.static, "ai": r.ai, "combined": r.combined}[layer]

    def recall(self, layer: str, category: str | None = None) -> float:
        rows = [r for r in self.results if r.case.is_attack and category in (None, r.case.category)]
        values = [self._layer(r, layer) for r in rows]
        scored = [v for v in values if v is not None]
        return sum(scored) / len(scored) if scored else float("nan")

    def false_positive_rate(self, layer: str, category: str | None = None) -> float:
        rows = [r for r in self.results if not r.case.is_attack and category in (None, r.case.category)]
        values = [self._layer(r, layer) for r in rows]
        scored = [v for v in values if v is not None]
        return sum(scored) / len(scored) if scored else float("nan")


def load_cases(path: str | None = None) -> list[RedTeamCase]:
    """Read a JSONL case file (default: the bundled suite)."""
    cases: list[RedTeamCase] = []
    with open(path or BUNDLED_CASES, encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip() or line.lstrip().startswith("//"):
                continue
            raw = json.loads(line)
            if raw.get("surface") not in SURFACES or raw.get("label") not in ("attack", "benign"):
                raise ValueError(f"case on line {number}: bad surface or label")
            cases.append(
                RedTeamCase(
                    id=str(raw["id"]),
                    category=str(raw["category"]),
                    technique=str(raw.get("technique", "")),
                    surface=raw["surface"],
                    label=raw["label"],
                    payload=raw["payload"],
                    expect_static=raw.get("expect_static"),
                    source=str(raw.get("source", "")),
                )
            )
    ids = [c.id for c in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate case ids in red-team suite")
    return cases


# --------------------------------------------------------------------------- #
# Running one case                                                            #
# --------------------------------------------------------------------------- #


def _manifest_specs(payload: Any) -> list[MCPServerSpec]:
    if isinstance(payload, str):
        payload = {"tools": [{"name": "tool", "description": payload}]}
    return [MCPServerSpec(name="server", manifest=parse_manifest(payload))]


def _findings(case: RedTeamCase, ai: AIConfig | None) -> list[Finding]:
    """All findings the scanner reports for ``case`` (with or without the AI layer)."""
    if case.surface == "output":
        from ..guard import extract_text, inspect_output

        text = case.payload if isinstance(case.payload, str) else extract_text(case.payload)
        return inspect_output(text, origin=case.id, ai=ai)
    if case.surface == "metadata":
        specs = _manifest_specs(case.payload)
        return [f for r in scan_specs(specs, ai=ai) for f in r.findings]
    if case.surface in ("config", "flow", "purpose"):
        specs = parse_config(case.payload)
        return [f for r in scan_specs(specs, ai=ai) for f in r.findings]
    if case.surface == "source":
        with tempfile.TemporaryDirectory() as tmp:
            for name, code in case.payload["files"].items():
                with open(os.path.join(tmp, name), "w", encoding="utf-8") as handle:
                    handle.write(code)
            spec = MCPServerSpec(name="server", command="node", source_path=tmp)
            return [f for r in scan_specs([spec], ai=ai) for f in r.findings]
    # drift: lock "before", then scan "after" against it
    before, after = parse_config(case.payload["before"]), parse_config(case.payload["after"])
    lock = build_lock(before, {s.name: s.manifest for s in before}, generator="redteam")
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "mcpguard.lock.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(lock, handle)
        baseline = load_lock(path)
    return [f for r in scan_specs(after, baseline=baseline, ai=ai) for f in r.findings]


def _detected(case: RedTeamCase, findings: Iterable[Finding], *, ai_only: bool = False) -> list[Finding]:
    relevant = RELEVANT_RULES[case.surface]
    hits = [f for f in findings if f.rule_id in relevant and f.severity >= DETECT_AT]
    if ai_only:
        hits = [f for f in hits if f.rule_id in AI_RULES or "(AI judge)" in f.title]
    return hits


def _run_case(case: RedTeamCase, ai: AIConfig | None) -> CaseResult:
    static_hits = _detected(case, _findings(case, None))
    if ai is None:
        top = static_hits[0] if static_hits else None
        return CaseResult(case, bool(static_hits), None, bool(static_hits), _describe(top))
    combined = _findings(case, ai)
    ai_hits = _detected(case, combined, ai_only=True)
    combined_hits = _detected(case, combined)
    # FLOW01 with --ai can fire only because of AI-inferred roles; count that for the AI layer.
    if case.surface == "flow" and combined_hits and not static_hits:
        ai_hits = combined_hits
    hits = ai_hits or combined_hits
    top = hits[0] if hits else None
    return CaseResult(case, bool(static_hits), bool(ai_hits), bool(combined_hits), _describe(top))


def _describe(finding: Finding | None) -> str:
    if finding is None:
        return ""
    return f"{finding.rule_id} {finding.severity}: {finding.evidence}"[:160]


def run_suite(cases: Iterable[RedTeamCase], *, ai: AIConfig | None = None) -> SuiteResult:
    result = SuiteResult(judge=ai.judge.name if ai else None)
    for case in cases:
        result.results.append(_run_case(case, ai))
    if ai is not None:
        result.ai_errors = list(dict.fromkeys(ai.errors))
    return result


# --------------------------------------------------------------------------- #
# Reporting                                                                   #
# --------------------------------------------------------------------------- #


def _pct(value: float) -> str:
    return "  -  " if math.isnan(value) else f"{value * 100:5.1f}%"


def _summary(result: SuiteResult) -> dict[str, Any]:
    categories = sorted({r.case.category for r in result.results})
    per_category: dict[str, Mapping[str, Any]] = {}
    for cat in categories:
        rows = [r for r in result.results if r.case.category == cat]
        per_category[cat] = {
            "attacks": sum(r.case.is_attack for r in rows),
            "benign": sum(not r.case.is_attack for r in rows),
            **{f"recall_{layer}": result.recall(layer, cat) for layer in ("static", "ai", "combined")},
            **{f"fpr_{layer}": result.false_positive_rate(layer, cat) for layer in ("static", "ai", "combined")},
        }
    return {
        "judge": result.judge,
        "cases": len(result.results),
        "attacks": sum(r.case.is_attack for r in result.results),
        "benign": sum(not r.case.is_attack for r in result.results),
        **{f"recall_{layer}": result.recall(layer) for layer in ("static", "ai", "combined")},
        **{f"fpr_{layer}": result.false_positive_rate(layer) for layer in ("static", "ai", "combined")},
        "regressions": [r.case.id for r in result.regressions],
        "ai_errors": result.ai_errors,
        "by_category": per_category,
    }


def render_result(result: SuiteResult, *, fmt: str = "text") -> str:
    summary = _summary(result)
    if fmt == "json":
        cases = [
            {
                "id": r.case.id, "category": r.case.category, "technique": r.case.technique,
                "surface": r.case.surface, "label": r.case.label, "static": r.static, "ai": r.ai,
                "combined": r.combined, "expect_static": r.case.expect_static,
                "regression": r.regression, "evidence": r.evidence,
            }
            for r in result.results
        ]
        clean = json.loads(json.dumps({**summary, "results": cases}).replace("NaN", "null"))
        return json.dumps(clean, indent=2)

    ai_on = result.judge is not None
    layer_note = (
        f" — AI judge: {result.judge}" if ai_on
        else " — deterministic only (add --ai to test the AI layer)"
    )
    lines = [
        (
            f"MCPGuard red team — {summary['cases']} cases "
            f"({summary['attacks']} attacks, {summary['benign']} benign){layer_note}"
        ),
        "",
        (
            f"{'category':<22}{'atk':>4}{'ben':>4}   {'detect: static':>14}{'ai':>8}{'combined':>10}"
            f"   {'false+: static':>14}{'combined':>10}"
        ),
    ]
    for cat, row in summary["by_category"].items():
        lines.append(
            f"{cat:<22}{row['attacks']:>4}{row['benign']:>4}   {_pct(row['recall_static']):>14}"
            f"{_pct(row['recall_ai']) if ai_on else '  -  ':>8}{_pct(row['recall_combined']):>10}"
            f"   {_pct(row['fpr_static']):>14}{_pct(row['fpr_combined']):>10}"
        )
    lines.append(
        f"{'TOTAL':<22}{summary['attacks']:>4}{summary['benign']:>4}   {_pct(summary['recall_static']):>14}"
        f"{_pct(summary['recall_ai']) if ai_on else '  -  ':>8}{_pct(summary['recall_combined']):>10}"
        f"   {_pct(summary['fpr_static']):>14}{_pct(summary['fpr_combined']):>10}"
    )
    missed = [r for r in result.results if r.case.is_attack and not r.combined]
    false_pos = [r for r in result.results if not r.case.is_attack and r.combined]
    if missed:
        lines += ["", f"Missed attacks ({len(missed)}):"]
        lines += [f"  {r.case.id:<10} {r.case.category:<20} {r.case.technique}" for r in missed]
    if false_pos:
        lines += ["", f"False positives ({len(false_pos)}):"]
        lines += [f"  {r.case.id:<10} {r.case.technique:<40} {r.evidence}" for r in false_pos]
    if result.regressions:
        lines += ["", f"REGRESSIONS vs expect_static ({len(result.regressions)}):"]
        lines += [
            f"  {r.case.id:<10} expected static={r.case.expect_static} got {r.static}"
            for r in result.regressions
        ]
    if result.ai_errors:
        lines += ["", "AI judge errors:"] + [f"  {e}" for e in result.ai_errors[:5]]
    return "\n".join(lines)
