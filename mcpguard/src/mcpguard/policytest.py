"""``mcpguard policy-test``: replay hostile scenarios through a policy.

"Did the model say no?" is the wrong test. The question is whether any
forbidden read, write, or send would actually *execute*. A scenario is a
sequence of steps against one fresh session:

* ``{"call": {"server", "tool", "arguments", "headers"?}, "expect": "allow|ask|deny"}``
  — a call the model proposes, and the decision the policy must reach,
* ``{"output": {"server", "tool", "result"}, "expect_taint"?: bool}``
  — a tool result entering the session (scanned by the output guard; injected
  instructions taint the session, as the ``check-output`` hook does live).

A decision *weaker* than expected (a deny that came back allow or ask) is a
security failure; a *stronger* one is over-blocking. Both fail the run, so the
file works as a regression test while models, prompts, and policies change.
Scenario files are JSONL; lines starting with ``//`` are comments.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .guard import extract_text, inspect_output
from .models import Severity
from .policy import ALLOW, ASK, DENY, Policy, evaluate, parse_call
from .session import MemorySessionStore

__all__ = ["PolicyTestResult", "load_scenarios", "render", "run_scenarios", "taint_label"]

_RANK = {ALLOW: 0, ASK: 1, DENY: 2}


@dataclass(frozen=True)
class StepResult:
    scenario: str
    index: int
    tool: str
    expected: str
    actual: str
    detail: str

    @property
    def ok(self) -> bool:
        return self.expected == self.actual

    @property
    def under_enforced(self) -> bool:
        """The policy let through more than it should have: the security failure."""
        return self.expected in _RANK and self.actual in _RANK and _RANK[self.actual] < _RANK[self.expected]


@dataclass
class PolicyTestResult:
    steps: list[StepResult] = field(default_factory=list)
    scenarios: int = 0

    @property
    def failures(self) -> list[StepResult]:
        return [s for s in self.steps if not s.ok]

    @property
    def forbidden_executed(self) -> list[StepResult]:
        """Expected deny, got allow: the call would run with no one asked."""
        return [s for s in self.steps if s.expected == DENY and s.actual == ALLOW]

    @property
    def under_enforced(self) -> list[StepResult]:
        """Any decision weaker than expected (deny -> ask, ask -> allow, deny -> allow)."""
        return [s for s in self.steps if s.under_enforced]


def load_scenarios(path: str) -> list[dict[str, Any]]:
    scenarios: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            try:
                data = json.loads(line)
            except ValueError as exc:
                raise ValueError(f"{path}:{number}: invalid JSON: {exc}") from exc
            if not isinstance(data, dict) or not isinstance(data.get("steps"), list):
                raise ValueError(f"{path}:{number}: a scenario needs a \"steps\" list")  # noqa: TRY004
            for index, step in enumerate(data["steps"], 1):
                if isinstance(step, dict) and "call" in step and step.get("expect") not in _RANK:
                    raise ValueError(
                        f"{path}:{number}: step {index} needs \"expect\": allow, ask, or deny"
                    )
            scenarios.append(data)
    return scenarios


def taint_label(tool: str, titles: list[str]) -> str:
    return f"{tool}: {'; '.join(titles[:2])}"


def run_scenarios(policy: Policy, scenarios: list[dict[str, Any]]) -> PolicyTestResult:
    result = PolicyTestResult(scenarios=len(scenarios))
    for number, scenario in enumerate(scenarios, 1):
        sid = str(scenario.get("id") or f"scenario-{number}")
        user = scenario.get("user") if isinstance(scenario.get("user"), str) else None
        store = MemorySessionStore()
        with store.transaction(sid) as session:
            for index, step in enumerate(scenario["steps"], 1):
                if not isinstance(step, dict):
                    continue
                if isinstance(step.get("output"), dict):
                    result.steps.extend(_output_step(sid, index, step, session.taint))
                elif isinstance(step.get("call"), dict):
                    call = parse_call({**step["call"], "session_id": sid}, user=user)
                    decision = evaluate(policy, call, session)
                    detail = "; ".join(f"{r.check}: {r.message}" for r in decision.deciding)
                    result.steps.append(StepResult(
                        sid, index, call.name, str(step.get("expect", "")), decision.decision, detail,
                    ))
    return result


def _output_step(sid: str, index: int, step: dict[str, Any], taint: list[str]) -> list[StepResult]:
    out = step["output"]
    server, tool = str(out.get("server", "")), str(out.get("tool", "tool"))
    name = f"{server}/{tool}" if server else tool
    findings = [
        f for f in inspect_output(extract_text(out.get("result")), origin=name)
        if f.severity >= Severity.HIGH
    ]
    if findings:
        taint.append(taint_label(name, [f.title for f in findings]))
    if "expect_taint" not in step:
        return []
    actual = "tainted" if findings else "clean"
    expected = "tainted" if step["expect_taint"] else "clean"
    return [StepResult(sid, index, f"{name} (output)", expected, actual,
                       "; ".join(f.title for f in findings))]


def render(result: PolicyTestResult, *, fmt: str = "text") -> str:
    if fmt == "json":
        return json.dumps({
            "scenarios": result.scenarios,
            "steps": len(result.steps),
            "failures": len(result.failures),
            "forbidden_executed": len(result.forbidden_executed),
            "under_enforced": len(result.under_enforced),
            "ok": not result.failures,
            "results": [
                {"scenario": s.scenario, "step": s.index, "tool": s.tool, "expected": s.expected,
                 "actual": s.actual, "ok": s.ok, "under_enforced": s.under_enforced, "detail": s.detail}
                for s in result.steps
            ],
        }, indent=2)
    lines = [f"MCPGuard policy-test — {result.scenarios} scenario(s), {len(result.steps)} checked step(s)", ""]
    current = None
    for step in result.steps:
        if step.scenario != current:
            current = step.scenario
            lines.append(f"● {current}")
        mark = "ok  " if step.ok else "FAIL"
        note = "" if step.ok else (
            "  <- forbidden call would run" if step.under_enforced else "  <- over-blocked"
        )
        lines.append(f"  {mark} step {step.index}: {step.tool}: expected {step.expected}, got {step.actual}{note}")
        if not step.ok and step.detail:
            lines.append(f"       {step.detail[:300]}")
    failed = result.failures
    lines.append("")
    lines.append(
        f"Summary: {len(result.steps) - len(failed)}/{len(result.steps)} steps as expected; "
        f"{len(result.forbidden_executed)} forbidden call(s) would execute, "
        f"{len(result.under_enforced) - len(result.forbidden_executed)} other decision(s) weaker than expected — "
        + ("PASS" if not failed else "FAIL")
    )
    return "\n".join(lines)
