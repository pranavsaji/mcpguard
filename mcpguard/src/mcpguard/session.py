"""Per-session memory for the runtime policy gate.

A single tool call rarely looks dangerous on its own; the sequence does. "A
broad data read followed by an email" and the lethal trifecta (untrusted text,
then private data, then a send) are only visible across calls, and "would a
retry send the same email twice?" needs the calls that came before. This module
keeps that history per agent session:

* the tool calls the gate let through (canonical name, inferred roles, and a
  digest of the arguments — never the argument values themselves),
* which tools contributed each role (kept for the whole session, so a flood of
  harmless calls can't push an early untrusted read out of the trifecta check),
* taint: tool outputs in which the output guard found injected instructions.

A state file that exists but can't be read raises :class:`SessionStateError`: a
reset would silently drop taint, so the gate fails closed instead. A missing or
expired file is simply a new session.

:class:`FileSessionStore` persists one small JSON file per session so separate
hook processes share it; files are written atomically and locked where the OS
supports it. :class:`MemorySessionStore` backs tests and ``policy-test``.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import tempfile
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any, Protocol

__all__ = [
    "CallRecord",
    "FileSessionStore",
    "MemorySessionStore",
    "SessionState",
    "SessionStateError",
    "SessionStore",
    "default_state_dir",
]

MAX_CALLS = 500  # oldest calls are dropped past this (duplicate detection window)
MAX_ROLE_TOOLS = 20  # tools remembered per role, for explanations
SESSION_TTL_SECONDS = 24 * 3600  # a session file older than this starts fresh


class SessionStateError(OSError):
    """A session state file exists but is unreadable or malformed."""


@dataclass(frozen=True)
class CallRecord:
    tool: str  # canonical "server/tool"
    roles: tuple[str, ...]
    digest: str  # sha256 of the canonical call (tool + arguments)
    decision: str
    at: float


@dataclass
class SessionState:
    session_id: str
    calls: list[CallRecord] = field(default_factory=list)
    taint: list[str] = field(default_factory=list)  # "server/tool: finding title"
    role_tools: dict[str, list[str]] = field(default_factory=dict)  # role -> tools, whole session

    def roles_seen(self) -> set[str]:
        return {role for role, tools in self.role_tools.items() if tools}

    def tools_with(self, role: str) -> list[str]:
        return list(self.role_tools.get(role, []))

    def seen_digest(self, digest: str) -> CallRecord | None:
        return next((c for c in reversed(self.calls) if c.digest == digest), None)

    def record(self, record: CallRecord) -> None:
        self.calls.append(record)
        del self.calls[:-MAX_CALLS]
        for role in record.roles:
            tools = self.role_tools.setdefault(role, [])
            if record.tool not in tools and len(tools) < MAX_ROLE_TOOLS:
                tools.append(record.tool)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "updated": time.time(),
            "calls": [
                {"tool": c.tool, "roles": list(c.roles), "digest": c.digest,
                 "decision": c.decision, "at": c.at}
                for c in self.calls
            ],
            "taint": self.taint,
            "role_tools": self.role_tools,
        }

    @classmethod
    def from_dict(cls, session_id: str, data: dict[str, Any]) -> SessionState:
        """Parse persisted state; raises :class:`SessionStateError` on malformed data."""
        try:
            return cls._from_dict(session_id, data)
        except (TypeError, ValueError, AttributeError, KeyError) as exc:
            raise SessionStateError(f"malformed session state: {exc}") from exc

    @classmethod
    def _from_dict(cls, session_id: str, data: dict[str, Any]) -> SessionState:
        calls = [
            CallRecord(
                tool=str(c.get("tool", "")),
                roles=tuple(str(r) for r in c.get("roles", []) if isinstance(r, str)),
                digest=str(c.get("digest", "")),
                decision=str(c.get("decision", "")),
                at=float(c.get("at", 0.0)),
            )
            for c in data.get("calls", [])
            if isinstance(c, dict)
        ]
        taint = [str(t) for t in data.get("taint", []) if isinstance(t, str)]
        role_tools = {
            str(role): [str(t) for t in tools if isinstance(t, str)][:MAX_ROLE_TOOLS]
            for role, tools in dict(data.get("role_tools", {})).items()
            if isinstance(tools, list)
        }
        return cls(session_id=session_id, calls=calls[-MAX_CALLS:], taint=taint, role_tools=role_tools)


class SessionStore(Protocol):
    def transaction(self, session_id: str) -> contextlib.AbstractContextManager[SessionState]:
        """Load a session's state, and save it when the block exits cleanly."""
        ...


class MemorySessionStore:
    """In-process store (tests, ``policy-test``)."""

    def __init__(self) -> None:
        self._states: dict[str, SessionState] = {}

    @contextlib.contextmanager
    def transaction(self, session_id: str) -> Iterator[SessionState]:
        yield self._states.setdefault(session_id, SessionState(session_id))


def default_state_dir() -> str:
    return os.environ.get("MCPGUARD_STATE_DIR") or os.path.join(
        os.path.expanduser("~"), ".mcpguard", "sessions"
    )


class FileSessionStore:
    """One JSON file per session under ``directory`` (created ``0700``)."""

    def __init__(self, directory: str) -> None:
        self.directory = directory

    def _path(self, session_id: str) -> str:
        # Hash the id: it comes from the hook event and must not steer the path.
        name = hashlib.sha256(session_id.encode("utf-8", "surrogatepass")).hexdigest()[:32]
        return os.path.join(self.directory, f"{name}.json")

    @contextlib.contextmanager
    def transaction(self, session_id: str) -> Iterator[SessionState]:
        os.makedirs(self.directory, mode=0o700, exist_ok=True)
        path = self._path(session_id)
        with _locked(path + ".lock"):
            state = self._load(session_id, path)
            yield state
            self._save(state, path)

    @staticmethod
    def _load(session_id: str, path: str) -> SessionState:
        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
        except FileNotFoundError:
            return SessionState(session_id)
        except (OSError, ValueError, RecursionError) as exc:
            raise SessionStateError(f"unreadable session state {path}: {exc}") from exc
        updated = data.get("updated") if isinstance(data, dict) else None
        if isinstance(updated, bool) or not isinstance(updated, (int, float)):
            raise SessionStateError(f"malformed session state {path}")
        if time.time() - updated > SESSION_TTL_SECONDS:
            return SessionState(session_id)
        return SessionState.from_dict(session_id, data)

    def _save(self, state: SessionState, path: str) -> None:
        fd, tmp = tempfile.mkstemp(dir=self.directory, prefix=".session-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(state.to_dict(), handle, separators=(",", ":"))
            os.replace(tmp, path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise


@contextlib.contextmanager
def _locked(path: str) -> Iterator[None]:
    """An exclusive advisory lock on ``path`` (POSIX); a no-op where unsupported."""
    try:
        import fcntl
    except ImportError:  # pragma: no cover - Windows
        yield
        return
    with open(path, "a", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
