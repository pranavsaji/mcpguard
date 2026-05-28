"""Centralized detection signatures.

All regexes and keyword sets used by rules live here so they can be reviewed,
tuned, and unit-tested in one place — and reused across multiple rules without
divergence. Patterns are compiled once at import.

Each pattern is intentionally conservative (favoring precision) for the MVP;
comments record intent so tuning later is informed rather than guesswork.
"""

from __future__ import annotations

import re
from re import Pattern

# --------------------------------------------------------------------------- #
# Tool poisoning / prompt injection (TP01)                                    #
# Directives aimed at the *model* hidden inside tool metadata.                #
# --------------------------------------------------------------------------- #

INJECTION_PATTERNS: tuple[Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts?|context)",
        r"disregard\s+(?:all\s+)?(?:previous|prior|above|the)\s+\w+",
        r"forget\s+(?:everything|all|your)\b",
        r"you\s+must\s+(?:always|never)\b",
        r"do\s+not\s+(?:tell|inform|mention|reveal)\s+(?:the\s+)?user",
        r"without\s+(?:telling|informing|notifying)\s+the\s+user",
        r"\bnew\s+(?:instructions?|system\s+prompt)\b",
        r"<\s*(?:system|important|secret)\s*>",  # pseudo-tags smuggling instructions
        r"\bas\s+an?\s+ai\b.*\bmust\b",
    )
)

# Data-exfiltration hints embedded in metadata.
EXFIL_PATTERNS: tuple[Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\b(?:send|post|upload|exfiltrate|forward)\b.{0,40}\b(?:to|->)\b.{0,40}https?://",
        r"\bread\b.{0,30}(?:~/\.ssh|\.env|id_rsa|/etc/passwd|credentials)",
        r"\b(?:include|append|attach)\b.{0,30}\b(?:api[_-]?key|token|secret|password)\b",
    )
)

# --------------------------------------------------------------------------- #
# Hidden content (TP02)                                                       #
# --------------------------------------------------------------------------- #

# Zero-width / invisible / BiDi control characters used to smuggle text.
INVISIBLE_CHARS: tuple[str, ...] = (
    "​",  # zero-width space
    "‌",  # zero-width non-joiner
    "‍",  # zero-width joiner
    "⁠",  # word joiner
    "﻿",  # zero-width no-break space / BOM
    "­",  # soft hyphen
    "‪",  # LRE
    "‫",  # RLE
    "‬",  # PDF
    "‭",  # LRO
    "‮",  # RLO (classic spoofing)
    "⁦",  # LRI
    "⁧",  # RLI
    "⁨",  # FSI
    "⁩",  # PDI
)
INVISIBLE_CHAR_SET: frozenset[str] = frozenset(INVISIBLE_CHARS)

HTML_COMMENT_RE: Pattern[str] = re.compile(r"<!--.*?-->", re.DOTALL)

# --------------------------------------------------------------------------- #
# Excessive agency / dangerous capabilities (CAP01)                           #
# Maps a capability label -> keywords that imply the tool wields it.          #
# --------------------------------------------------------------------------- #

CAPABILITY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "code execution": ("exec", "eval", "execute_code", "run_code", "shell", "subprocess", "spawn"),
    "shell / command": ("run_command", "execute_command", "system", "os_command", "bash", "powershell"),
    "filesystem write": ("write_file", "delete_file", "remove_file", "rmdir", "unlink", "overwrite"),
    "arbitrary network": ("http_request", "fetch_url", "curl", "send_request", "open_url", "webhook"),
    "credential access": ("read_secret", "get_credentials", "dump_env", "list_tokens", "get_password"),
    "database": ("execute_sql", "run_query", "drop_table", "delete_from"),
}

# Tokens that, appearing in a tool *name*, strongly imply a dangerous verb.
DANGEROUS_NAME_TOKENS: frozenset[str] = frozenset(
    {"exec", "eval", "shell", "command", "delete", "remove", "drop", "sudo", "admin"}
)

# --------------------------------------------------------------------------- #
# Command injection / RCE in source (CMD01)                                   #
# --------------------------------------------------------------------------- #

RCE_SOURCE_PATTERNS: dict[str, Pattern[str]] = {
    "python: subprocess shell=True": re.compile(r"subprocess\.\w+\([^)]*shell\s*=\s*True"),
    "python: os.system": re.compile(r"\bos\.system\s*\("),
    "python: os.popen": re.compile(r"\bos\.popen\s*\("),
    "python: eval/exec": re.compile(r"\b(?:eval|exec)\s*\("),
    "node: child_process.exec": re.compile(r"child_process\.(?:exec|execSync)\s*\("),
    "node: new Function": re.compile(r"\bnew\s+Function\s*\("),
    "shell: curl pipe to shell": re.compile(r"curl[^\n|]*\|\s*(?:ba)?sh\b"),
}

# --------------------------------------------------------------------------- #
# Secrets in env (SEC01)                                                       #
# --------------------------------------------------------------------------- #

SECRET_NAME_RE: Pattern[str] = re.compile(
    r"(?:api[_-]?key|secret|token|password|passwd|access[_-]?key|private[_-]?key|client[_-]?secret)",
    re.IGNORECASE,
)

# High-confidence vendor key formats — value-based, name-independent.
SECRET_VALUE_PATTERNS: dict[str, Pattern[str]] = {
    "OpenAI key": re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    "Anthropic key": re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    "AWS access key id": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "Slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "Private key block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}

# Values that look like unresolved placeholders, not real secrets.
PLACEHOLDER_RE: Pattern[str] = re.compile(
    r"^\s*(?:\$\{?[\w.-]+\}?|<[^>]+>|\{\{[^}]+\}\}|(?:your|my|the)[_-].*|x{3,}|changeme|placeholder|todo|example|\*+)\s*$",
    re.IGNORECASE,
)


def looks_like_placeholder(value: str) -> bool:
    """True if ``value`` is an obvious placeholder rather than a live secret."""
    return bool(PLACEHOLDER_RE.match(value.strip()))


# --------------------------------------------------------------------------- #
# Supply chain / pinning (SUP01)                                              #
# --------------------------------------------------------------------------- #

# Launchers whose packages should be version-pinned.
PINNED_LAUNCHERS: frozenset[str] = frozenset({"npx", "uvx", "pipx", "bunx"})

# A pinned npm spec looks like name@1.2.3 (or @scope/name@1.2.3). Reject "latest".
NPM_PINNED_RE: Pattern[str] = re.compile(r"@\d[\w.\-]*$")
REMOTE_FETCH_RE: Pattern[str] = re.compile(r"https?://|git\+|github:", re.IGNORECASE)
