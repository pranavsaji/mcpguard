"""Small, dependency-free helpers shared across rules."""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from re import Pattern


def truncate(text: str, limit: int = 160) -> str:
    """Collapse whitespace and cap length for use as finding evidence."""
    collapsed = " ".join(text.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 1].rstrip() + "…"


def all_matches(patterns: Pattern[str] | tuple[Pattern[str], ...], text: str) -> list[str]:
    """Every distinct matched substring across ``patterns``, in order of first appearance."""
    pats = (patterns,) if not isinstance(patterns, tuple) else patterns
    found: dict[str, None] = {}
    for pat in pats:
        for match in pat.finditer(text):
            found.setdefault(" ".join(match.group(0).split()), None)
            if len(found) >= MAX_MATCHES:
                break
    # Overlapping patterns can match nested spans; keep only the longest.
    return [m for m in found if not any(m != other and m in other for other in found)]


# Evidence shows only a handful of matches; capping keeps hostile inputs linear.
MAX_MATCHES = 50


def matches_evidence(matches: list[str], limit: int = 300) -> str:
    """Render one or more matches as finding evidence, noting the count when >1."""
    if len(matches) == 1:
        return truncate(matches[0], limit)
    return truncate(f"{len(matches)} matches: " + " | ".join(matches), limit)


_WORD_RE = re.compile(r"[a-z0-9]+")
# camelCase / PascalCase boundaries, including acronyms: "HTTPRequest" -> "HTTP Request".
_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def words(text: str) -> list[str]:
    """Lowercased alphanumeric words, in order (splits snake_case, camelCase, kebab)."""
    return _WORD_RE.findall(_CAMEL_RE.sub(" ", text).lower())


def normalize_word(word: str) -> str:
    """Fold a simple plural ("webhooks" -> "webhook") without mangling "process"."""
    if len(word) > 3 and word.endswith("s") and not word.endswith("ss"):
        return word[:-1]
    return word


def contains_phrase(haystack: Sequence[str], phrase: Sequence[str]) -> bool:
    """True if ``phrase`` occurs as consecutive entries of ``haystack``."""
    n = len(phrase)
    return any(list(haystack[i : i + n]) == list(phrase) for i in range(len(haystack) - n + 1))


def keyword_phrases(keywords: Sequence[str]) -> tuple[tuple[str, ...], ...]:
    """Pre-split keywords ("write_file") into normalized word phrases."""
    return tuple(tuple(normalize_word(w) for w in words(kw)) for kw in keywords)


def canonical_json(value: object) -> str:
    """Deterministic JSON for hashing / equality (sorted keys, no whitespace)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


_UNSAFE_CHAR_RE = re.compile(r"[\x00-\x1f\x7f-\x9f\ud800-\udfff]")


def safe_text(text: str) -> str:
    """Escape control characters and lone surrogates for terminal output.

    Evidence, tool names, and server names come from attacker-controlled
    configs; printed raw, ANSI sequences in them could erase or rewrite lines of
    MCPGuard's own report, and lone surrogates crash ``print``.
    """
    return _UNSAFE_CHAR_RE.sub(lambda m: m.group(0).encode("unicode_escape", "backslashreplace").decode("ascii"), text)
