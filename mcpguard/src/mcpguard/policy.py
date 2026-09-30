"""Runtime policy gate: decide on a tool call *before* it runs (POL01).

Scanning finds servers that could be abused, and the output guard flags
injected text, but a model that reads hostile text will sooner or later propose
the wrong call. Whether that call *runs* is the application's decision, and it
has to be made before the tool gets the data or the credential. This module
makes that decision deterministically, from a JSON policy file:

    who is the user · what is the operation · which records · where does the
    data go · has this session already read untrusted text and private data?

Each check yields ``allow`` / ``ask`` / ``deny``; the most restrictive wins, so
an allow rule can never override a deny from another check. Built-in checks
(each configurable, or ``"off"``):

=================  =======  ======================================================
check              default  fires when
=================  =======  ======================================================
``canary``         deny     an argument carries a planted canary value
``secrets``        deny     an argument carries a live credential (SEC01 formats)
``sensitive_paths``deny     an argument names ~/.ssh, .env, cloud credentials…
``destinations``   ask      a URL / email / host outside ``destinations.allow``
``baseline``       deny     the tool or its arguments differ from the reviewed
                            lockfile (unknown tool, undeclared parameter…)
``headers``        deny     ``Mcp-Method`` / ``Mcp-Name`` / ``Mcp-Param-*`` HTTP
                            headers disagree with the JSON-RPC body (2026-07-28)
``trifecta``       ask      a send, after this session read untrusted text *and*
                            private data (the lethal trifecta, at run time)
``tainted_sink``   deny     a send, after a tool output in this session carried
                            injected instructions
``duplicate``      ask      the same side-effecting call was already let through
=================  =======  ======================================================

``ask`` carries what a person needs to decide — the destination and the data
leaving — not "Approve tool call?". A decision the gate can't reach (bad
policy, internal error) resolves to the policy's ``fail`` mode, ``deny`` by
default: the check is never silently skipped to keep the agent moving.
"""

from __future__ import annotations

import base64
import binascii
import fnmatch
import hashlib
import json
import os
import re
import time
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any

from .argcheck import check_arguments
from .lockfile import LockEntry, load_lock
from .models import MCPTool
from .patterns import SECRET_VALUE_PATTERNS, SENSITIVE_PATH_RE
from .session import CallRecord, SessionState
from .util import canonical_json, truncate

__all__ = [
    "ALLOW",
    "ASK",
    "CHECKS",
    "DENY",
    "Decision",
    "Policy",
    "PolicyError",
    "Reason",
    "ToolCall",
    "evaluate",
    "load_policy",
    "parse_call",
    "parse_policy",
]

ALLOW, ASK, DENY = "allow", "ask", "deny"
OFF = "off"
_RANK = {ALLOW: 0, ASK: 1, DENY: 2}
POLICY_VERSION = 1

CHECKS: dict[str, str] = {
    "canary": DENY,
    "secrets": DENY,
    "sensitive_paths": DENY,
    "destinations": ASK,
    "baseline": DENY,
    "headers": DENY,
    "trifecta": ASK,
    "tainted_sink": DENY,
    "duplicate": ASK,
}
ROLES = ("untrusted", "private", "sink", "exec")


class PolicyError(ValueError):
    """The policy file is missing, unreadable, or malformed."""


# --------------------------------------------------------------------------- #
# The call                                                                    #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ToolCall:
    """A proposed tool call, however it reached the gate."""

    tool: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    server: str = ""
    session_id: str | None = None
    user: str | None = None
    method: str = "tools/call"
    headers: Mapping[str, str] = field(default_factory=dict)

    @property
    def name(self) -> str:
        """``server/tool`` — the name policy globs match."""
        return f"{self.server}/{self.tool}" if self.server else self.tool

    @property
    def digest(self) -> str:
        return hashlib.sha256(
            canonical_json({"tool": self.name, "arguments": self.arguments}).encode(
                "utf-8", "surrogatepass"
            )
        ).hexdigest()


def parse_call(data: Mapping[str, Any], *, server: str = "", user: str | None = None) -> ToolCall:
    """A :class:`ToolCall` from a Claude Code ``PreToolUse`` event, a JSON-RPC
    ``tools/call`` request (optionally with the HTTP ``headers`` a gateway saw),
    or a plain ``{"server", "tool", "arguments"}`` object.

    ``user`` and ``server`` given by the operator (CLI / environment) win over the
    payload's: a caller must not be able to name itself into another identity.
    """
    if "tool_name" in data:  # Claude Code hook event: mcp__<server>__<tool>
        raw = str(data.get("tool_name") or "")
        srv, tool = server, raw
        if raw.startswith("mcp__") and "__" in raw[5:]:
            srv, tool = raw[5:].split("__", 1)
        args = data.get("tool_input")
        return ToolCall(
            tool=tool, server=srv, arguments=args if isinstance(args, dict) else {},
            session_id=_opt_str(data.get("session_id")), user=user or _opt_str(data.get("user")),
        )
    if isinstance(data.get("params"), dict):  # JSON-RPC request
        params = data["params"]
        args = params.get("arguments")
        headers = data.get("headers")
        return ToolCall(
            tool=str(params.get("name", "")), arguments=args if isinstance(args, dict) else {},
            server=server or str(data.get("server") or ""), method=str(data.get("method", "")),
            session_id=_opt_str(data.get("session_id")), user=user or _opt_str(data.get("user")),
            headers={str(k): str(v) for k, v in headers.items()} if isinstance(headers, dict) else {},
        )
    args = data.get("arguments")
    headers = data.get("headers")
    return ToolCall(
        tool=str(data.get("tool", "")), arguments=args if isinstance(args, dict) else {},
        server=server or str(data.get("server") or ""), session_id=_opt_str(data.get("session_id")),
        user=user or _opt_str(data.get("user")),
        headers={str(k): str(v) for k, v in headers.items()} if isinstance(headers, dict) else {},
    )


def _opt_str(value: object) -> str | None:
    return str(value) if isinstance(value, (str, int)) and str(value) else None


# --------------------------------------------------------------------------- #
# The policy                                                                  #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Condition:
    arg: str
    op: str
    value: Any

    def holds(self, arguments: Mapping[str, Any], *, every: bool = False) -> bool:
        """True when the condition holds for the argument's value(s).

        A path can resolve to several values (a list of recipients). ``every`` — used
        for ``allow`` rules — requires all of them to satisfy it, so one approved
        recipient can't carry an unapproved one through; restricting rules fire on any.
        """
        values = list(_arg_strings(arguments)) if self.arg == "*" else _lookup(arguments, self.arg)
        if self.op == "exists":
            return bool(values) == bool(self.value)
        check = all if every else any
        return bool(values) and check(self._one(v) for v in values)

    def _one(self, actual: Any) -> bool:
        op, want = self.op, self.value
        if op == "equals":
            return bool(actual == want)
        if op == "not_equals":
            return bool(actual != want)
        if op == "in":
            return actual in want
        if op == "not_in":
            return actual not in want
        if op in ("matches", "not_matches"):
            hit = isinstance(actual, str) and re.search(str(want), actual) is not None
            return hit if op == "matches" else not hit
        if op in ("gt", "gte", "lt", "lte"):
            if isinstance(actual, bool) or not isinstance(actual, (int, float)):
                return False
            return bool({"gt": actual > want, "gte": actual >= want,
                         "lt": actual < want, "lte": actual <= want}[op])
        return False


_OPS = ("equals", "not_equals", "in", "not_in", "matches", "not_matches", "gt", "gte", "lt", "lte", "exists")


@dataclass(frozen=True)
class PolicyRule:
    id: str
    decision: str
    tools: tuple[str, ...] = ("*",)
    users: tuple[str, ...] = ()
    except_users: tuple[str, ...] = ()
    roles: tuple[str, ...] = ()
    when: tuple[Condition, ...] = ()
    reason: str = ""

    def matches(self, call: ToolCall, roles: set[str]) -> bool:
        if not _glob_any(self.tools, call):
            return False
        if self.users and (call.user or "") not in self.users:
            return False
        if self.except_users and (call.user or "") in self.except_users:
            return False
        if self.roles and not roles & set(self.roles):
            return False
        every = self.decision == ALLOW
        return all(c.holds(call.arguments, every=every) for c in self.when)


@dataclass(frozen=True)
class Policy:
    default: str = ASK
    fail: str = DENY
    rules: tuple[PolicyRule, ...] = ()
    checks: Mapping[str, str] = field(default_factory=lambda: dict(CHECKS))
    destinations_allow: tuple[str, ...] = ()
    destination_tools: tuple[str, ...] = ("*",)
    canaries: tuple[str, ...] = ()
    roles: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    baseline: Mapping[str, LockEntry] | None = None
    audit_log: str | None = None
    state_dir: str | None = None

    def check(self, name: str) -> str:
        return self.checks.get(name, OFF)


def load_policy(path: str) -> Policy:
    """Read and validate a policy file; relative paths inside it resolve beside it."""
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError, RecursionError) as exc:
        raise PolicyError(f"cannot read policy {path!r}: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError(f"{path!r}: a policy must be a JSON object")
    return parse_policy(data, base_dir=os.path.dirname(os.path.abspath(path)))


def parse_policy(data: Mapping[str, Any], *, base_dir: str | None = None) -> Policy:
    if data.get("mcpguard_policy") != POLICY_VERSION:
        raise PolicyError(f"not an mcpguard v{POLICY_VERSION} policy (\"mcpguard_policy\": 1)")

    def rel(p: object, key: str) -> str | None:
        if p is None:
            return None
        if not isinstance(p, str) or not p:
            raise PolicyError(f"{key} must be a path string")
        return p if os.path.isabs(p) or base_dir is None else os.path.join(base_dir, p)

    checks = dict(CHECKS)
    raw_checks = data.get("checks", {})
    if not isinstance(raw_checks, dict):
        raise PolicyError("checks must be an object of {check: allow|ask|deny|off}")
    for name, value in raw_checks.items():
        if name not in CHECKS:
            raise PolicyError(f"unknown check {name!r}; expected one of {', '.join(CHECKS)}")
        checks[name] = _decision(value, f"checks.{name}", allow_off=True)

    dest = data.get("destinations", {})
    if not isinstance(dest, dict):
        raise PolicyError("destinations must be an object")
    if "unknown" in dest:
        checks["destinations"] = _decision(dest["unknown"], "destinations.unknown", allow_off=True)

    roles_raw = data.get("roles", {})
    if not isinstance(roles_raw, dict):
        raise PolicyError("roles must map a tool glob to a list of roles")
    roles: dict[str, tuple[str, ...]] = {}
    for glob, values in roles_raw.items():
        listed = _str_list(values, f"roles.{glob}")
        bad = [r for r in listed if r not in ROLES]
        if bad:
            raise PolicyError(f"roles.{glob}: unknown role(s) {bad}; expected {', '.join(ROLES)}")
        roles[str(glob)] = tuple(listed)

    baseline_path = rel(data.get("baseline"), "baseline")
    baseline = None
    if baseline_path:
        from .config_parser import ConfigError

        try:
            baseline = load_lock(baseline_path)
        except ConfigError as exc:
            raise PolicyError(str(exc)) from exc

    session = data.get("session", {})
    if not isinstance(session, dict):
        raise PolicyError("session must be an object")
    return Policy(
        default=_decision(data.get("default", ASK), "default"),
        fail=_decision(data.get("fail", DENY), "fail"),
        rules=tuple(_rule(r, i) for i, r in enumerate(_list(data.get("rules", []), "rules"))),
        checks=checks,
        destinations_allow=tuple(s.lower() for s in _str_list(dest.get("allow", []), "destinations.allow")),
        destination_tools=tuple(_str_list(dest.get("tools", ["*"]), "destinations.tools")),
        canaries=tuple(_str_list(data.get("canaries", []), "canaries")),
        roles=roles,
        baseline=baseline,
        audit_log=rel(data.get("audit_log"), "audit_log"),
        state_dir=rel(session.get("state_dir"), "session.state_dir"),
    )


def _rule(raw: object, index: int) -> PolicyRule:
    if not isinstance(raw, dict):
        raise PolicyError(f"rules[{index}] must be an object")
    rid = str(raw.get("id") or f"rule-{index + 1}")
    when_raw = raw.get("when", [])
    conditions = [when_raw] if isinstance(when_raw, dict) else _list(when_raw, f"{rid}.when")
    roles = _str_list(raw.get("roles", []), f"{rid}.roles")
    if any(r not in ROLES for r in roles):
        raise PolicyError(f"{rid}.roles: expected any of {', '.join(ROLES)}")
    return PolicyRule(
        id=rid,
        decision=_decision(raw.get("decision"), f"{rid}.decision"),
        tools=tuple(_str_list(raw.get("tools", ["*"]), f"{rid}.tools")) or ("*",),
        users=tuple(_str_list(raw.get("users", []), f"{rid}.users")),
        except_users=tuple(_str_list(raw.get("except_users", []), f"{rid}.except_users")),
        roles=tuple(roles),
        when=tuple(_condition(c, f"{rid}.when") for c in conditions),
        reason=str(raw.get("reason", "")),
    )


def _condition(raw: object, where: str) -> Condition:
    if not isinstance(raw, dict) or not isinstance(raw.get("arg"), str):
        raise PolicyError(f"{where}: each condition needs an \"arg\" (a dotted path, or \"*\")")
    ops = [k for k in raw if k != "arg"]
    if len(ops) != 1 or ops[0] not in _OPS:
        raise PolicyError(f"{where}: exactly one operator of {', '.join(_OPS)} per condition")
    op, value = ops[0], raw[ops[0]]
    if op in ("in", "not_in") and not isinstance(value, list):
        raise PolicyError(f"{where}: {op} takes a list")
    if op in ("gt", "gte", "lt", "lte") and (isinstance(value, bool) or not isinstance(value, (int, float))):
        raise PolicyError(f"{where}: {op} takes a number")
    if op in ("matches", "not_matches"):
        try:
            re.compile(str(value))
        except (re.error, OverflowError, RecursionError) as exc:
            raise PolicyError(f"{where}: invalid regex {value!r}: {exc}") from exc
    return Condition(arg=str(raw["arg"]), op=op, value=value)


def _decision(value: object, where: str, *, allow_off: bool = False) -> str:
    allowed = (ALLOW, ASK, DENY, OFF) if allow_off else (ALLOW, ASK, DENY)
    if value not in allowed:
        raise PolicyError(f"{where} must be one of {', '.join(allowed)}, got {value!r}")
    return str(value)


def _list(value: object, where: str) -> list[Any]:
    if not isinstance(value, list):
        raise PolicyError(f"{where} must be a list")
    return value


def _str_list(value: object, where: str) -> list[str]:
    items = [value] if isinstance(value, str) else _list(value, where)
    if not all(isinstance(v, str) for v in items):
        raise PolicyError(f"{where} must be a list of strings")
    return [str(v) for v in items]


# --------------------------------------------------------------------------- #
# The decision                                                                #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Reason:
    check: str  # "rule:<id>", "default", or a built-in check name
    decision: str
    message: str


@dataclass(frozen=True)
class CallDestination:
    kind: str  # "url" | "email" | "host" | "unparsed"
    value: str  # for the confirmation: URL without its query string, the address, the host
    host: str  # normalized host / mail domain; "" when unreadable (never on an allow-list)
    audit: str  # value-free form for logs and reasons: scheme://host, the address, the host


@dataclass
class Decision:
    decision: str
    call: ToolCall
    reasons: list[Reason] = field(default_factory=list)
    roles: tuple[str, ...] = ()
    destinations: list[CallDestination] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)

    @property
    def deciding(self) -> list[Reason]:
        """The reasons that produced the final decision."""
        return [r for r in self.reasons if r.decision == self.decision]

    def message(self) -> str:
        """What a person reviewing this call needs to see."""
        lines = [f"MCPGuard {self.decision.upper()}: {self.call.name}"]
        lines.extend(f"- {r.message}" for r in self.deciding)
        if self.decision == ASK:
            lines.append(describe_effect(self))
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "server": self.call.server,
            "tool": self.call.tool,
            "user": self.call.user,
            "session": self.call.session_id,
            "roles": list(self.roles),
            "reasons": [{"check": r.check, "decision": r.decision, "message": r.message} for r in self.reasons],
            "destinations": [d.audit for d in self.destinations],
            "resources": self.resources,
            "arguments": sorted(_audit_key(str(k)) for k in self.call.arguments),
            "arguments_sha256": self.call.digest,
        }


def evaluate(policy: Policy, call: ToolCall, session: SessionState | None = None) -> Decision:
    """Decide on ``call``. Never raises: an internal error resolves to ``policy.fail``."""
    try:
        return _evaluate(policy, call, session)
    except Exception as exc:  # noqa: BLE001 - the gate must answer; a crash must not fail open
        return Decision(
            decision=policy.fail, call=call,
            reasons=[Reason("error", policy.fail, f"policy evaluation failed ({type(exc).__name__}: {exc})")],
        )


def _evaluate(policy: Policy, call: ToolCall, session: SessionState | None) -> Decision:
    tool_def = _baseline_tool(policy, call)
    roles = call_roles(policy, call, tool_def)
    decision = Decision(
        decision=ALLOW, call=call, roles=tuple(sorted(roles)),
        destinations=_destinations(call.arguments), resources=_resources(call.arguments),
    )
    reasons = decision.reasons

    matched = [r for r in policy.rules if r.matches(call, roles)]
    for rule in matched:
        reasons.append(Reason(f"rule:{rule.id}", rule.decision, rule.reason or f"policy rule {rule.id}"))
    if not matched:
        reasons.append(Reason("default", policy.default, f"no policy rule covers {call.name}"))

    for check, message in _builtin_checks(policy, call, decision, tool_def, roles, session):
        level = policy.check(check)
        if level != OFF:
            reasons.append(Reason(check, level, message))

    decision.decision = max((r.decision for r in reasons), key=_RANK.__getitem__)
    if session is not None and decision.decision != DENY:
        session.record(CallRecord(call.name, decision.roles, call.digest, decision.decision, time.time()))
    return decision


def _builtin_checks(
    policy: Policy, call: ToolCall, decision: Decision, tool_def: MCPTool | None,
    roles: set[str], session: SessionState | None,
) -> Iterator[tuple[str, str]]:
    strings = list(_arg_strings(call.arguments))
    for canary in policy.canaries:
        if any(canary in s for s in strings):
            # Never echo the canary: the reason reaches the model, which would learn the marker.
            yield "canary", "an argument carries a planted canary value: an exfiltration path is live"
            break
    for label, pattern in SECRET_VALUE_PATTERNS.items():
        if any(pattern.search(s) for s in strings):
            yield "secrets", f"an argument carries a credential ({label})"
            break
    hits = sum(1 for s in strings if SENSITIVE_PATH_RE.search(s))
    if hits:
        yield "sensitive_paths", (
            f"{hits} argument value(s) name sensitive files (SSH keys, .env, cloud or MCP credentials)"
        )

    if policy.destinations_allow and _glob_any(policy.destination_tools, call):
        unknown = [d for d in decision.destinations if not _destination_allowed(d, policy.destinations_allow)]
        if unknown:
            yield "destinations", "destination not on the approved list: " + ", ".join(
                d.audit for d in unknown[:5]
            )

    if policy.baseline is not None:
        yield from _baseline_problems(policy.baseline, call, tool_def)
    yield from _header_problems(call, tool_def)

    if session is not None and "sink" in roles:
        if session.taint:
            yield "tainted_sink", (
                "this session read a tool output carrying injected instructions "
                f"({truncate('; '.join(session.taint[-2:]), 200)}) and now proposes a send"
            )
        # The proposed call's own roles count: a fetch after a private read can carry
        # the data out in its URL, completing the trifecta by itself.
        seen = session.roles_seen() | roles
        if {"untrusted", "private"} <= seen:
            yield "trifecta", (
                "this session read untrusted content ("
                + ", ".join(session.tools_with("untrusted")[:3])
                + ") and private data ("
                + ", ".join(session.tools_with("private")[:3])
                + ") and now proposes a send: the lethal trifecta"
            )
    if session is not None and _side_effecting(call, roles, tool_def):
        prior = session.seen_digest(call.digest)
        if prior is not None:
            yield "duplicate", (
                f"an identical call was already {'allowed' if prior.decision == ALLOW else 'confirmed'} "
                "in this session; a retry would repeat its effect"
            )


# --- roles -------------------------------------------------------------------------


_SIDE_EFFECT_WORDS = frozenset({
    "send", "post", "create", "delete", "remove", "update", "write", "publish", "upload", "pay",
    "transfer", "charge", "refund", "email", "message", "reply", "forward", "push", "merge", "deploy",
    "execute", "exec", "run", "drop", "insert", "set", "put", "patch", "invite", "share", "export",
})


def call_roles(policy: Policy, call: ToolCall, tool_def: MCPTool | None = None) -> set[str]:
    """Roles for the call: explicit ``roles`` globs in the policy win; else inferred."""
    explicit = [roles for glob, roles in policy.roles.items() if _glob(glob, call)]
    if explicit:
        return {r for roles in explicit for r in roles}
    from .rules.toxic_flow import tool_roles

    return tool_roles(tool_def if tool_def is not None else MCPTool(name=call.tool))


def _side_effecting(call: ToolCall, roles: set[str], tool_def: MCPTool | None) -> bool:
    if "sink" in roles or "exec" in roles:
        return True
    if tool_def is not None and tool_def.annotations.get("readOnlyHint") is True:
        return False  # a hint, but only a reason *not* to ask about a retry
    return bool(set(re.findall(r"[a-z]+", call.tool.lower())) & _SIDE_EFFECT_WORDS)


# --- baseline / headers ------------------------------------------------------------


def _baseline_tool(policy: Policy, call: ToolCall) -> MCPTool | None:
    if policy.baseline is None:
        return None
    entry = policy.baseline.get(call.server)
    if entry is None or entry.manifest is None:
        return None
    return next((t for t in entry.manifest.tools if t.name == call.tool), None)


def _baseline_problems(
    baseline: Mapping[str, LockEntry], call: ToolCall, tool_def: MCPTool | None
) -> Iterator[tuple[str, str]]:
    entry = baseline.get(call.server)
    if entry is None:
        yield "baseline", f"server {call.server or '(unknown)'!r} was never reviewed (not in the lockfile)"
        return
    if entry.manifest is None:
        yield "baseline", f"the lockfile has no tool manifest for {call.server!r} (lock it with --connect)"
        return
    if tool_def is None:
        yield "baseline", f"tool {call.tool!r} is not in the reviewed manifest for {call.server!r}"
        return
    problems = check_arguments(dict(call.arguments), tool_def.input_schema)
    if problems:
        yield "baseline", "arguments differ from the reviewed schema: " + "; ".join(problems[:4])


_B64_SENTINEL = re.compile(r"^=\?base64\?(.*)\?=$", re.DOTALL)


def _header_value(raw: str) -> str:
    match = _B64_SENTINEL.match(raw)
    if not match:
        return raw
    try:
        return base64.b64decode(match.group(1), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return "\x00<undecodable base64 header>"


def _header_problems(call: ToolCall, tool_def: MCPTool | None) -> Iterator[tuple[str, str]]:
    """Gateway checks for MCP 2026-07-28 request headers vs the JSON-RPC body."""
    if not call.headers:
        return
    headers = {k.lower(): v for k, v in call.headers.items()}
    version = headers.get("mcp-protocol-version", "")
    modern = version >= "2026-07-28"
    method = headers.get("mcp-method")
    if method is None and modern:
        yield "headers", "Mcp-Method header missing (required from 2026-07-28)"
    elif method is not None and method != call.method:
        yield "headers", f"Mcp-Method header {method!r} does not match the body method {call.method!r}"
    name = headers.get("mcp-name")
    if name is None and modern and call.method == "tools/call":
        yield "headers", "Mcp-Name header missing (required for tools/call from 2026-07-28)"
    elif name is not None and _header_value(name) != call.tool:
        yield "headers", (
            f"Mcp-Name header {truncate(_header_value(name), 80)!r} does not match the body tool "
            f"{call.tool!r}: a router and the server would act on different calls"
        )
    if tool_def is None:
        return
    props = tool_def.input_schema.get("properties")
    for pname, pschema in (props.items() if isinstance(props, dict) else []):
        if not isinstance(pschema, dict) or not isinstance(pschema.get("x-mcp-header"), str):
            continue
        header = headers.get(f"mcp-param-{str(pschema['x-mcp-header']).lower()}")
        value = call.arguments.get(pname)
        if value is None:
            continue
        expected = str(value).lower() if isinstance(value, bool) else str(value)
        if header is None and modern:
            yield "headers", f"Mcp-Param-{pschema['x-mcp-header']} header missing for argument {pname!r}"
        elif header is not None and _header_value(header) != expected:
            yield "headers", f"Mcp-Param-{pschema['x-mcp-header']} header does not match argument {pname!r}"


# --- argument inspection -----------------------------------------------------------
#
# Arguments are attacker-influenced (the model proposes them after reading hostile
# text), so extraction errs toward *unknown*: a URL the parser can't read
# unambiguously, or a destination-shaped argument that yields no host, is a
# destination that is not on the allow-list.

MAX_DEPTH = 32
_URL_RE = re.compile(r"(?<![\w+.-])(?:[a-z][a-z0-9+.-]{1,31}:)?//[^\s\"'<>`]+", re.IGNORECASE)
# "@domain" with *something* before the "@" (so decorators and @mentions aren't mail).
_AT_DOMAIN_RE = re.compile(r"(?<=[^\s@,;<>()\[\]{}])@([^\s@,;<>()\"'`/\\?#]+)")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_-]{1,63}\.)+[a-z][a-z0-9-]{1,62}$", re.IGNORECASE)
# Argument names whose value *is* a destination.
_DEST_KEY_WORDS = frozenset({
    "url", "uri", "href", "link", "endpoint", "webhook", "callback", "host", "hostname",
    "domain", "to", "cc", "bcc", "recipient", "recipients", "email", "emails",
})
_RESOURCE_ARG_RE = re.compile(
    r"(?:^|_)(?:ids?|uri|url|path|file|table|account|record|customer|ticket|case|repo|resource|"
    r"project|issue)s?$",
    re.IGNORECASE,
)
_MAX_URL = 4096


class _TooDeep(ValueError):
    """Arguments nested past MAX_DEPTH: refuse to judge what can't be fully read."""


def _arg_strings(value: Any, depth: int = 0) -> Iterator[str]:
    """Every string in the arguments — values *and* keys, at any depth up to MAX_DEPTH."""
    if depth > MAX_DEPTH:
        raise _TooDeep(f"arguments nested deeper than {MAX_DEPTH} levels")
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for key, item in value.items():
            yield str(key)
            yield from _arg_strings(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            yield from _arg_strings(item, depth + 1)


def _walk(value: Any, key: str = "", depth: int = 0) -> Iterator[tuple[str, Any]]:
    """``(argument key, scalar value)`` pairs, keyed by the nearest enclosing key."""
    if depth > MAX_DEPTH:
        raise _TooDeep(f"arguments nested deeper than {MAX_DEPTH} levels")
    if isinstance(value, Mapping):
        for k, item in value.items():
            yield from _walk(item, str(k), depth + 1)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item, key, depth + 1)
    else:
        yield key, value


def _lookup(arguments: Mapping[str, Any], path: str) -> list[Any]:
    current: list[Any] = [arguments]
    for part in path.split("."):
        nxt: list[Any] = []
        for node in current:
            if isinstance(node, Mapping) and part in node:
                item = node[part]
                nxt.extend(item if isinstance(item, list) else [item])
        current = nxt
    return current


def _norm_host(host: str) -> str:
    return host.strip().strip("[]").rstrip(".").lower()


def _url_destination(url: str) -> CallDestination:
    """A destination for one URL; ambiguous forms come back with no host (never allowed)."""
    from urllib.parse import urlsplit

    shown = truncate(url.split("?", 1)[0].split("#", 1)[0], 200)
    if len(url) > _MAX_URL or "\\" in url or any(ord(c) < 0x20 for c in url):
        return CallDestination("url", shown, "", "(unparseable URL)")
    authority = url.split("//", 1)[1].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in authority:  # userinfo: parsers disagree on which side is the host
        return CallDestination("url", shown, "", "(URL with embedded credentials)")
    try:
        host = urlsplit(url).hostname
    except ValueError:
        host = None
    if not host:
        return CallDestination("url", shown, "", "(unparseable URL)")
    scheme = url.split("//", 1)[0].rstrip(":").lower() or "//"
    return CallDestination("url", shown, _norm_host(host), f"{scheme}://{_norm_host(host)}")


def _text_destinations(text: str) -> Iterator[CallDestination]:
    for match in _URL_RE.finditer(text):
        yield _url_destination(match.group(0).rstrip(".,;)"))
    for match in _AT_DOMAIN_RE.finditer(_URL_RE.sub(" ", text)):
        domain = _norm_host(match.group(1).rstrip(".,;:!)"))
        if _DOMAIN_RE.match(domain) or _is_ip(domain):
            start = text.rfind(" ", 0, match.start()) + 1
            address = truncate(text[start:match.end()].strip("<>\"'"), 120).lower()
            yield CallDestination("email", address, domain, address)


def _is_ip(text: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _bare_host(value: str) -> str | None:
    """``evil.example/x``, ``host:8080``, ``203.0.113.9`` — a host written without a scheme."""
    head = value.strip().split("/", 1)[0].split("?", 1)[0]
    if head.startswith("[") and "]" in head:
        head = head[1:head.index("]")]
    elif head.count(":") == 1:
        head = head.split(":", 1)[0]
    host = _norm_host(head)
    return host if _DOMAIN_RE.match(host) or _is_ip(host) else None


def _destinations(arguments: Mapping[str, Any]) -> list[CallDestination]:
    found: dict[str, CallDestination] = {}

    def add(dest: CallDestination) -> None:
        found.setdefault(dest.audit if dest.host else dest.value, dest)

    for text in _arg_strings(arguments):  # values and keys, at every depth
        for dest in _text_destinations(text):
            add(dest)
    for key, value in _walk(arguments):
        if not isinstance(value, str) or not value.strip():
            continue
        words = re.findall(r"[a-z]+", re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", key).lower())
        if not words or words[-1] not in _DEST_KEY_WORDS:
            continue
        if any(True for _ in _text_destinations(value)):
            continue
        host = _bare_host(value)
        if host is not None:
            add(CallDestination("host", host, host, host))
        else:  # a destination argument we can't read: unknown, never allowed
            add(CallDestination("unparsed", truncate(value, 80), "", f"(unreadable {key!r} value)"))
    return list(found.values())


def _destination_allowed(dest: CallDestination, allow: tuple[str, ...]) -> bool:
    if not dest.host:
        return False
    host = dest.host
    for raw in allow:
        entry = raw.rstrip(".")
        if "@" in entry:  # an exact address, or "*@domain"
            if dest.kind == "email" and fnmatch.fnmatchcase(dest.value, entry):
                return True
            continue
        if entry.startswith("*."):
            if host.endswith(entry[1:]):
                return True
        elif host == entry or host.endswith("." + entry):
            return True
    return False


def _resources(arguments: Mapping[str, Any]) -> list[str]:
    out: dict[str, None] = {}
    for key, value in _walk(arguments):
        if key and _RESOURCE_ARG_RE.search(key) and isinstance(value, (str, int)) and not isinstance(value, bool):
            text = str(value).split("?", 1)[0].split("#", 1)[0]
            text = re.sub(r"//[^/@\s]*@", "//", text)  # URL userinfo
            out.setdefault(f"{key}={truncate(redact(text), 80)}", None)
    return list(out)[:10]


def _audit_key(name: str) -> str:
    """An argument *name* for the audit log: masked if it's credential-shaped, capped."""
    masked = redact(name)
    return masked if len(masked) <= 64 else "sha256:" + hashlib.sha256(masked.encode()).hexdigest()[:16]


def redact(text: str) -> str:
    """Mask credential-shaped substrings (for audit logs and confirmation text)."""
    for pattern in SECRET_VALUE_PATTERNS.values():
        text = pattern.sub("[redacted]", text)
    return text


def describe_effect(decision: Decision) -> str:
    """The confirmation text: where the data goes and what leaves, not "Approve?"."""
    parts: list[str] = []
    if decision.destinations:
        parts.append("Destination: " + ", ".join(d.value for d in decision.destinations[:5]))
    shown = []
    for key, value in list(decision.call.arguments.items())[:6]:
        text = value if isinstance(value, str) else canonical_json(value)
        size = f" ({len(text)} chars)" if len(text) > 120 else ""
        shown.append(f"{key}={truncate(redact(text), 120)!r}{size}")
    parts.append("Data: " + (", ".join(shown) if shown else "(no arguments)"))
    return "\n".join(parts)


def _glob(pattern: str, call: ToolCall) -> bool:
    return fnmatch.fnmatchcase(call.name, pattern) or (
        "/" not in pattern and fnmatch.fnmatchcase(call.tool, pattern)
    )


def _glob_any(patterns: tuple[str, ...], call: ToolCall) -> bool:
    return any(_glob(p, call) for p in patterns)


# --------------------------------------------------------------------------- #
# Audit                                                                       #
# --------------------------------------------------------------------------- #


def audit(decision: Decision, path: str) -> None:
    """Append one JSON line per decision. Argument *values* are never logged —
    only their names, a digest, destinations (query strings stripped), and
    resource identifiers with credentials masked."""
    record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **decision.to_dict()}
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    line = json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n"
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, line.encode("ascii"))
    finally:
        os.close(fd)
