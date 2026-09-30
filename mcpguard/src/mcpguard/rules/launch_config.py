"""CFG01 — dangerous server launch configuration.

A config entry *is* code execution: its ``command``, ``args``, and ``env`` run on
the developer's machine with their privileges. Beyond the package itself, the
way it is launched can hand an attacker the host. This rule flags:

* env that injects code into the process (``LD_PRELOAD``, ``DYLD_INSERT_LIBRARIES``,
  ``NODE_OPTIONS=--require``, ``BASH_ENV``, ...) — high,
* env that disables TLS verification (``NODE_TLS_REJECT_UNAUTHORIZED=0``) — high,
* LLM API base-URL overrides pointing at a non-vendor host (the server's API key
  goes wherever it points) — medium,
* package-registry overrides (``--extra-index-url``, ``PIP_INDEX_URL``): the
  dependency-confusion / malicious-mirror vector — medium,
* launching through ``sudo`` / ``doas`` — high,
* containers that get the host: ``--privileged``, a mounted Docker socket, the
  host root, ``--cap-add ALL|SYS_ADMIN``, ``--security-opt ...=unconfined`` (high),
  host network / PID namespaces and whole-home mounts (medium),
* a path argument exposing the whole disk (high) or whole home directory (medium),
* binding a local server to every interface (``--host 0.0.0.0``) — medium.

Maps to CWE-250 / CWE-426 and the MCP spec's "local server compromise" guidance.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from urllib.parse import urlparse

from ..context import AnalysisContext
from ..launchers import command_basename
from ..models import Category, Finding, Location, MCPServerSpec, Severity
from ..patterns import (
    ALL_INTERFACES_RE,
    API_BASE_URL_ENV,
    CODE_INJECTION_ENV,
    CODE_LOADING_OPTION_ENV,
    CONTAINER_RUNTIMES,
    DANGEROUS_CAPS,
    DOCKER_SOCKET_RE,
    HOME_PATH_RE,
    HOST_FLAGS,
    PRIVILEGE_ESCALATION_COMMANDS,
    REGISTRY_OVERRIDE_ENV,
    REGISTRY_OVERRIDE_FLAGS,
    ROOT_PATH_RE,
    TLS_DISABLE_ENV,
)
from ..util import truncate
from .base import Rule, register


def _hostname(url: str) -> str:
    """Lowercased host of ``url``; empty when it is malformed (never raises)."""
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _flag_values(args: tuple[str, ...], flags: frozenset[str]) -> Iterator[tuple[str, str]]:
    """``(flag, value)`` for every ``--flag value`` / ``--flag=value`` in ``args``."""
    for i, arg in enumerate(args):
        flag, eq, inline = arg.partition("=")
        if flag in flags:
            if eq:
                yield flag, inline
            elif i + 1 < len(args):
                yield flag, args[i + 1]


@register
class LaunchConfigRule(Rule):
    id = "CFG01"
    title = "Dangerous MCP server launch configuration"
    category = Category.INSECURE_CONFIG
    default_severity = Severity.HIGH
    mappings = ("CWE-250", "MCP-LOCAL-SERVER-COMPROMISE", "OWASP-ASI05")

    def analyze(self, target: MCPServerSpec, ctx: AnalysisContext) -> Iterable[Finding]:
        yield from self._env(target)
        if not target.command:
            return
        command = command_basename(target.command).removesuffix(".exe")
        args = target.args
        if command in PRIVILEGE_ESCALATION_COMMANDS:
            yield self.finding(
                title="MCP server launched with elevated privileges",
                location=Location(server=target.name, field="command"),
                evidence=truncate(target.command_line),
                remediation=(
                    "Never run an MCP server as root. Anything that steers it — including "
                    "prompt injection — then acts with full control of the machine."
                ),
            )
            args = args[1:] if args else args
            command = command_basename(target.args[0]) if target.args else command
        if command in CONTAINER_RUNTIMES:
            yield from self._container(target, args)
        else:
            yield from self._paths(target, args)
        yield from self._registry_flags(target, args)
        for flag, value in _flag_values(args, HOST_FLAGS):
            if ALL_INTERFACES_RE.match(value):
                yield self._bind_all(target, f"{flag} {value}")

    # --- env ------------------------------------------------------------------------

    def _env(self, target: MCPServerSpec) -> Iterator[Finding]:
        for key, value in target.env.items():
            upper = key.upper()
            location = Location(server=target.name, field=f"env:{key}")
            reason = CODE_INJECTION_ENV.get(upper)
            loader = CODE_LOADING_OPTION_ENV.get(upper)
            if (reason and value.strip()) or (loader and loader.search(value)):
                yield self.finding(
                    title="Env var injects code into the MCP server process",
                    location=location,
                    evidence=truncate(f"{key}={value}"),
                    remediation=(
                        f"{key} {reason or 'loads extra code at startup'}. Remove it; nothing "
                        "in an MCP config needs to load code into the server out-of-band."
                    ),
                )
            tls = TLS_DISABLE_ENV.get(upper)
            if tls and tls.search(value):
                yield self.finding(
                    title="TLS certificate verification disabled",
                    location=location,
                    evidence=f"{key}={value!r}",
                    remediation=(
                        "Disabling verification lets anyone on the network intercept the "
                        "server's traffic and tokens. Trust a specific CA instead."
                    ),
                )
            hosts = API_BASE_URL_ENV.get(upper)
            if hosts and value.strip() and not value.startswith("${"):
                host = _hostname(value)
                if host and host not in hosts and host not in ("localhost", "127.0.0.1"):
                    yield self.finding(
                        title="LLM API base URL redirected to a non-vendor host",
                        location=location,
                        evidence=f"{key}={truncate(value, 100)}",
                        remediation=(
                            "The server's API key is sent to whatever this points at. Confirm "
                            "the host is a proxy you operate; otherwise remove the override."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=0.5,
                    )
            if upper in REGISTRY_OVERRIDE_ENV and value.strip():
                yield self._registry(target, location, f"{key}={value}")

    # --- args -----------------------------------------------------------------------

    def _registry_flags(self, target: MCPServerSpec, args: tuple[str, ...]) -> Iterator[Finding]:
        for flag, value in _flag_values(args, REGISTRY_OVERRIDE_FLAGS):
            if value.startswith(("http://", "https://", "file:")):
                yield self._registry(
                    target, Location(server=target.name, field="args"), f"{flag} {value}"
                )

    def _registry(self, target: MCPServerSpec, location: Location, evidence: str) -> Finding:
        return self.finding(
            title="Package registry overridden for the MCP server",
            location=location,
            evidence=truncate(evidence),
            remediation=(
                "A non-default (or extra) index can serve a look-alike package — the "
                "dependency-confusion vector. Use only a registry you control, never an "
                "extra index alongside the public one."
            ),
            severity=Severity.MEDIUM,
            confidence=0.6,
        )

    def _paths(self, target: MCPServerSpec, args: tuple[str, ...]) -> Iterator[Finding]:
        for arg in args:
            value = arg.partition("=")[2] if arg.startswith("-") and "=" in arg else arg
            if ROOT_PATH_RE.match(value):
                yield self.finding(
                    title="MCP server given access to the entire filesystem",
                    location=Location(server=target.name, field="args"),
                    evidence=truncate(target.command_line),
                    remediation=(
                        "Scope the server to the specific project directories it needs; a "
                        "root path exposes SSH keys, cloud credentials, and every other secret."
                    ),
                )
            elif HOME_PATH_RE.match(value):
                yield self.finding(
                    title="MCP server given access to the whole home directory",
                    location=Location(server=target.name, field="args"),
                    evidence=truncate(target.command_line),
                    remediation=(
                        "The home directory holds ~/.ssh, ~/.aws, browser profiles, and MCP "
                        "configs. Scope the server to the project directories it needs."
                    ),
                    severity=Severity.MEDIUM,
                )

    def _container(self, target: MCPServerSpec, args: tuple[str, ...]) -> Iterator[Finding]:
        location = Location(server=target.name, field="args")

        def hit(title: str, evidence: str, fix: str, severity: Severity = Severity.HIGH) -> Finding:
            return self.finding(
                title=title, location=location, evidence=truncate(evidence),
                remediation=fix, severity=severity,
            )

        if "--privileged" in args:
            yield hit(
                "MCP container runs --privileged", "--privileged",
                "A privileged container is root on the host. Drop --privileged.",
            )
        mounts = [v for _, v in _flag_values(args, frozenset({"-v", "--volume", "--mount"}))]
        for mount in mounts:
            source = re.sub(r"^(?:type=\w+,)?(?:source|src)=", "", mount).split(":")[0].split(",")[0]
            if DOCKER_SOCKET_RE.search(mount):
                yield hit(
                    "Docker socket mounted into the MCP container", mount,
                    "The Docker socket grants root on the host. Never mount it into a server.",
                )
            elif ROOT_PATH_RE.match(source):
                yield hit(
                    "Host root filesystem mounted into the MCP container", mount,
                    "Mount only the specific directories the server needs, read-only if possible.",
                )
            elif HOME_PATH_RE.match(source):
                yield hit(
                    "Whole home directory mounted into the MCP container", mount,
                    "Mount only the project directories the server needs.", Severity.MEDIUM,
                )
        for flag, value in _flag_values(args, frozenset({"--cap-add"})):
            if value.upper().removeprefix("CAP_") in DANGEROUS_CAPS:
                yield hit(
                    "MCP container granted a dangerous capability", f"{flag} {value}",
                    "Drop the added capability; it enables container escape.",
                )
        for flag, value in _flag_values(args, frozenset({"--security-opt"})):
            if "unconfined" in value or value.strip() in ("no-new-privileges=false",):
                yield hit(
                    "MCP container security profile disabled", f"{flag} {value}",
                    "Keep the default seccomp / AppArmor profiles.",
                )
        for flag, value in _flag_values(args, frozenset({"--network", "--net", "--pid", "--ipc", "--uts"})):
            if value == "host":
                yield hit(
                    "MCP container shares a host namespace", f"{flag}={value}",
                    "Host namespaces remove container isolation. Use the default namespaces "
                    "and publish only the ports the server needs.", Severity.MEDIUM,
                )
        for _, value in _flag_values(args, frozenset({"-p", "--publish"})):
            if value.count(":") == 1 or value.startswith("0.0.0.0:"):
                yield self._bind_all(target, f"-p {value} (publishes on all interfaces)")

    def _bind_all(self, target: MCPServerSpec, evidence: str) -> Finding:
        return self.finding(
            title="MCP server listens on all network interfaces",
            location=Location(server=target.name, field="args"),
            evidence=truncate(evidence),
            remediation=(
                "Bind local servers to 127.0.0.1. Listening on every interface exposes the "
                "server to the network and to DNS-rebinding from any web page."
            ),
            severity=Severity.MEDIUM,
        )

