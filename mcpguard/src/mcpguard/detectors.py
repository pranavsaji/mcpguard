"""Pure text detectors shared by the metadata rules and the tool-output guard.

Each function takes a string and returns what it found, never a finding: rules
(TP01/TP02/TP03) decide severity and location for *metadata*, and
:mod:`mcpguard.guard` reuses the very same checks on *tool outputs*, so the two
can never drift apart.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field

from .patterns import (
    ANSI_ESCAPE_RE,
    BASE64_RUN_RE,
    CONTROL_CHAR_RE,
    COVERT_PARAM_TOKENS,
    EXFIL_PATTERNS,
    INJECTION_PATTERNS,
    INVISIBLE_CHAR_SET,
    PADDING_RE,
    PREFERENCE_PATTERNS,
    SENSITIVE_PARAM_TOKENS,
    SHADOWING_PATTERNS,
    TAG_CHAR_RANGE,
    VARIATION_SELECTOR_RANGE,
    VARIATION_SELECTOR_SUPPLEMENT_RANGE,
)
from .util import MAX_MATCHES, all_matches, contains_phrase, keyword_phrases, truncate, words

__all__ = [
    "HiddenContent",
    "decode_base64_payloads",
    "exfil_matches",
    "find_hidden_content",
    "html_comments",
    "injection_matches",
    "mixed_scripts",
    "preference_matches",
    "shadowing_matches",
    "suspicious_parameter_name",
]


def injection_matches(text: str) -> list[str]:
    """Instruction-override / concealment / pseudo-tag directives in ``text``."""
    return all_matches(INJECTION_PATTERNS, text)


def exfil_matches(text: str) -> list[str]:
    """Directives to read sensitive files or ship data to an external destination."""
    return all_matches(EXFIL_PATTERNS, text)


def shadowing_matches(text: str) -> list[str]:
    """Directives that steer how the model uses *other* tools (tool shadowing)."""
    return all_matches(SHADOWING_PATTERNS, text)


def preference_matches(text: str) -> list[str]:
    """Language biasing the model's tool choice toward this tool (MPMA)."""
    return all_matches(PREFERENCE_PATTERNS, text)


_SENSITIVE_PARAM_PHRASES = keyword_phrases(SENSITIVE_PARAM_TOKENS)
_COVERT_PARAM_PHRASES = keyword_phrases(COVERT_PARAM_TOKENS)


def suspicious_parameter_name(name: str) -> tuple[str, str] | None:
    """``("sensitive"|"covert", token)`` when a parameter *name* is itself a lure."""
    tokens = words(name)
    for kind, phrases in (("sensitive", _SENSITIVE_PARAM_PHRASES), ("covert", _COVERT_PARAM_PHRASES)):
        for phrase in phrases:
            if contains_phrase(tokens, phrase):
                return kind, "_".join(phrase)
    return None


def decode_base64_payloads(text: str) -> list[str]:
    """Decoded base64 runs in ``text`` that carry injection or exfil directives.

    Only runs that decode to mostly-printable text *and* then match a directive
    are returned, so ordinary hashes, IDs, and binary blobs stay silent.
    """
    found: list[str] = []
    for match in BASE64_RUN_RE.finditer(text):
        blob = match.group(0)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        decoded = raw.decode("utf-8", errors="replace")
        printable = sum(ch.isprintable() or ch.isspace() for ch in decoded)
        if not decoded or printable / len(decoded) < 0.9:
            continue
        if injection_matches(decoded) or exfil_matches(decoded):
            found.append(truncate(decoded, 120))
    return found


@dataclass
class HiddenContent:
    """Everything in a string that a model reads but a human reviewer can't see."""

    invisibles: list[str] = field(default_factory=list)  # "U+200B" labels
    tag_text: str = ""  # decoded Unicode Tag ("ASCII smuggling") payload
    variation_selectors: int = 0  # suspicious variation-selector count
    ansi: list[str] = field(default_factory=list)  # escaped ANSI / control sequences
    html_comments: list[str] = field(default_factory=list)
    padding: bool = False

    def __bool__(self) -> bool:
        return bool(
            self.invisibles or self.tag_text or self.variation_selectors or self.ansi
            or self.html_comments or self.padding
        )


# Subdivision flags (England, Scotland, Wales) are legitimately spelled with tag
# characters: U+1F3F4, tag letters, then CANCEL TAG U+E007F. Built from code
# points so this source file stays free of invisible characters.
_FLAG_TAG_SEQUENCE_RE = re.compile(
    chr(0x1F3F4) + "[" + chr(0xE0020) + "-" + chr(0xE007E) + "]{1,12}" + chr(0xE007F)
)


def find_hidden_content(text: str) -> HiddenContent:
    """Scan ``text`` for invisible, smuggled, or terminal-control content."""
    found = HiddenContent()
    scan = _FLAG_TAG_SEQUENCE_RE.sub(chr(0x1F3F4), text)
    invisibles: dict[str, None] = {}
    tag_chars: list[str] = []
    vs_run = 0
    for char in scan:
        cp = ord(char)
        if char in INVISIBLE_CHAR_SET:
            invisibles.setdefault(f"U+{cp:04X}", None)
        if TAG_CHAR_RANGE[0] <= cp <= TAG_CHAR_RANGE[1]:
            if 0x20 <= cp - TAG_CHAR_RANGE[0] <= 0x7E:
                tag_chars.append(chr(cp - TAG_CHAR_RANGE[0]))
            invisibles.setdefault("U+E00xx (tag characters)", None)
        if VARIATION_SELECTOR_SUPPLEMENT_RANGE[0] <= cp <= VARIATION_SELECTOR_SUPPLEMENT_RANGE[1]:
            found.variation_selectors += 1
        elif VARIATION_SELECTOR_RANGE[0] <= cp <= VARIATION_SELECTOR_RANGE[1]:
            vs_run += 1
            # One selector after an emoji is normal; a run of them encodes data.
            if vs_run == 2:
                found.variation_selectors += 2
            elif vs_run > 2:
                found.variation_selectors += 1
        else:
            vs_run = 0
    found.invisibles = list(invisibles)
    found.tag_text = "".join(tag_chars)

    ansi = [m.group(0) for m in ANSI_ESCAPE_RE.finditer(text)]
    if not ansi and CONTROL_CHAR_RE.search(text):
        ansi = [m.group(0) for m in CONTROL_CHAR_RE.finditer(text)]
    found.ansi = list(dict.fromkeys(s.encode("unicode_escape").decode("ascii") for s in ansi))

    found.html_comments = html_comments(text)
    found.padding = bool(PADDING_RE.search(text))
    return found


def html_comments(text: str, limit: int = MAX_MATCHES) -> list[str]:
    """``<!-- ... -->`` spans, like ``HTML_COMMENT_RE`` but linear-time.

    A regex scan is quadratic on text holding many unclosed ``<!--`` (every one
    rescans to the end); tool outputs can be megabytes of hostile HTML.
    """
    found: dict[str, None] = {}
    start = text.find("<!--")
    while start != -1 and len(found) < limit:
        end = text.find("-->", start + 4)
        if end == -1:
            break
        found.setdefault(" ".join(text[start : end + 3].split()), None)
        start = text.find("<!--", end + 3)
    return list(found)


def mixed_scripts(name: str) -> list[str]:
    """Scripts mixed within one identifier (e.g. ``["CYRILLIC", "LATIN"]``).

    An identifier mixing Latin with a look-alike script (Cyrillic "\\u0430" in
    "re\\u0430d_file") is a homoglyph spoof. Digits and punctuation are ignored.
    """
    scripts: set[str] = set()
    for char in name:
        if not char.isalpha():
            continue
        try:
            scripts.add(unicodedata.name(char).split(" ")[0])
        except ValueError:
            scripts.add("UNKNOWN")
    return sorted(scripts) if len(scripts) > 1 else []
