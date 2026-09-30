"""Understand package-runner launch lines (``npx``, ``bunx``, ``uvx``, ``pipx``).

Shared by the pinning rule (is the package version-pinned?) and the source
resolver (where is that package installed locally?), so both agree on which
argument is the package.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from .patterns import (
    LOCAL_PACKAGE_RE,
    NPM_LAUNCHERS,
    NPM_PINNED_RE,
    PACKAGE_FLAGS,
    PINNED_LAUNCHERS,
    PY_PINNED_RE,
    VALUE_FLAGS,
)

__all__ = ["PackageLaunch", "command_basename", "parse_launch"]

# Where a Python requirement's name ends: extras, version operators, markers.
_PY_NAME_END_RE = re.compile(r"[\[=<>!~@;\s]")


@dataclass(frozen=True, slots=True)
class PackageLaunch:
    """The package a runner will fetch and execute."""

    launcher: str  # "npx" | "bunx" | "uvx" | "pipx"
    spec: str  # the package token exactly as written, e.g. "pkg@1.2.3"

    @property
    def ecosystem(self) -> str:
        return "npm" if self.launcher in NPM_LAUNCHERS else "pypi"

    @property
    def is_local(self) -> bool:
        """A filesystem path or built artifact: nothing is fetched from a registry."""
        return bool(LOCAL_PACKAGE_RE.search(self.spec))

    @property
    def is_pinned(self) -> bool:
        pattern = NPM_PINNED_RE if self.ecosystem == "npm" else PY_PINNED_RE
        return bool(pattern.search(self.spec))

    @property
    def name(self) -> str:
        """Package name with any version / extras stripped."""
        if self.ecosystem == "npm":
            at = self.spec.rfind("@")
            return self.spec[:at] if at > 0 else self.spec  # keep a leading @scope
        return _PY_NAME_END_RE.split(self.spec, maxsplit=1)[0]

    @property
    def version(self) -> str | None:
        """The pinned version, if any."""
        pattern = NPM_PINNED_RE if self.ecosystem == "npm" else PY_PINNED_RE
        match = pattern.search(self.spec)
        return match.group(0).lstrip("=@ ") if match else None


def command_basename(command: str) -> str:
    """Lowercased executable name, splitting on both / and \\ so Windows paths in a
    config are understood on any OS (``C:\\node\\npx`` -> ``npx``)."""
    return re.split(r"[\\/]", command)[-1].lower()


def parse_launch(command: str | None, args: Sequence[str]) -> PackageLaunch | None:
    """Return the package a runner launch line executes, or ``None``.

    Honors package-defining flags (``npx -p pkg``, ``uvx --from pkg``,
    ``pipx run --spec pkg``), skips flags that take a value (``uvx --python
    3.12 pkg``), and skips ``pipx``'s ``run`` subcommand.
    """
    if not command:
        return None
    launcher = command_basename(command)
    if launcher not in PINNED_LAUNCHERS:
        return None

    package_flags = PACKAGE_FLAGS.get(launcher, frozenset())
    value_flags = VALUE_FLAGS.get(launcher, frozenset())
    rest = list(args)
    if launcher == "pipx" and rest[:1] == ["run"]:
        rest = rest[1:]

    i = 0
    while i < len(rest):
        arg = rest[i]
        flag, eq, inline_value = arg.partition("=")
        if arg.startswith("-"):
            takes_value = flag in package_flags or flag in value_flags
            value = inline_value if eq else (rest[i + 1] if i + 1 < len(rest) else None)
            if flag in package_flags and value:
                return PackageLaunch(launcher=launcher, spec=value)
            i += 2 if takes_value and not eq else 1
            continue
        return PackageLaunch(launcher=launcher, spec=arg)
    return None
