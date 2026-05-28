"""Small, dependency-free helpers shared across rules."""

from __future__ import annotations

from collections.abc import Iterator
from re import Pattern


def truncate(text: str, limit: int = 160) -> str:
    """Collapse whitespace and cap length for use as finding evidence."""
    collapsed = " ".join(text.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 1].rstrip() + "…"


def first_match(patterns: Pattern[str] | tuple[Pattern[str], ...], text: str) -> str | None:
    """Return the first matched substring across ``patterns``, or ``None``."""
    pats = (patterns,) if not isinstance(patterns, tuple) else patterns
    for pat in pats:
        match = pat.search(text)
        if match:
            return match.group(0)
    return None


def iter_lines(text: str) -> Iterator[tuple[int, str]]:
    """Yield ``(1-based line number, line)`` for ``text``."""
    for index, line in enumerate(text.splitlines(), start=1):
        yield index, line
