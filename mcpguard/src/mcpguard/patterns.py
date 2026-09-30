"""Centralized detection signatures.

All regexes and keyword sets used by rules live here so they can be reviewed,
tuned, and unit-tested in one place — and reused across multiple rules without
divergence. Patterns are compiled once at import.

Each pattern is intentionally conservative (favoring precision) for the MVP;
comments record intent so tuning later is informed rather than guesswork.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from re import Pattern

# --------------------------------------------------------------------------- #
# Tool poisoning / prompt injection (TP01)                                    #
# Directives aimed at the *model* hidden inside tool metadata.                #
# --------------------------------------------------------------------------- #

INJECTION_PATTERNS: tuple[Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        # Instruction override.
        r"ignore\s+(?:all\s+)?(?:(?:the|any|your)\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|prompts?|context|directions|rules)",
        r"disregard\s+(?:all\s+)?(?:previous|prior|above|the)\s+\w+",
        r"forget\s+(?:everything|all|your)\b",
        r"\b(?:override|bypass)\s+(?:all\s+|any\s+)?(?:the\s+|your\s+)?(?:safety|security|system|content)\s+(?:rules|instructions|guidelines|polic(?:y|ies)|filters?|restrictions)",
        r"you\s+must\s+(?:always|never)\b",
        r"\bnew\s+(?:instructions?|system\s+prompt)\b",
        r"\bas\s+an?\s+ai\b.{0,80}?\bmust\b",
        r"\byou\s+are\s+now\s+(?:in\s+)?(?:an?\s+)?(?:developer|dan|jailbreak|jailbroken|unrestricted|god|admin)\b",
        # Concealment from the user: the hallmark of tool poisoning (Invariant, 2025).
        r"\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|mention|reveal|notify|alert)\b.{0,30}?\buser\b",
        r"\b(?:do\s+not|don'?t|never)\s+(?:mention|reveal|disclose)\s+(?:that\s+you|this\s+(?:instruction|step|tool)|these\s+instructions|any\s+of\s+this)",
        r"without\s+(?:telling|informing|notifying|alerting|asking)\s+the\s+user",
        r"\b(?:hide|conceal)\s+(?:this|it|these)\s+from\s+the\s+user",
        r"\bthe\s+user\s+(?:must|should)\s+(?:not|never)\s+(?:know|see|be\s+told)",
        # Pseudo-tags and chat-template tokens that smuggle "system" instructions.
        r"<\s*/?\s*(?:system|important|secret|instructions?|system[_-]?prompt|critical)\s*>",
        r"<\|\s*(?:im_start|im_end|system|endoftext|start_header_id)\s*\|>",
        r"\[/?(?:INST|SYSTEM)\]",
        # Tool-ordering hijack / "line jumping": a tool demanding to run before others.
        r"\b(?:always\s+)?(?:call|run|use|invoke)\s+this\s+tool\s+(?:first|before\s+(?:any|every|all)\b)",
        r"\b(?:before|prior\s+to)\s+(?:using|calling|invoking)\s+any\s+(?:other\s+)?tools?\b",
    )
)

# Files an MCP tool has no business asking the model to read or ship elsewhere.
_SENSITIVE_PATH = (
    r"(?:~/\.ssh(?:/[\w.-]+)?|\.ssh/[\w.-]*|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|(?<![\w.])\.env\b|/etc/(?:passwd|shadow)"
    r"|\.aws/(?:credentials|config)|\.config/gcloud[\w./-]*|\.azure/[\w./-]*|\.kube/config|\.docker/config\.json"
    r"|\.npmrc|\.pypirc|\.netrc|\.git-credentials|\.pgpass|\bmcp\.json|claude_desktop_config\.json"
    r"|\.cursor/[\w./-]*|\.bash_history|\.zsh_history|\bcredentials\.json|\bsecrets?\.(?:json|ya?ml|toml))"
)
_READ_VERB = (
    r"(?:read|cat|open|load|access|dump|print|output|return|include|attach|copy|upload|send|leak|provide|paste|share|supply|submit|reply\s+with|respond\s+with)"
)
# Credential-like nouns, excluding the ubiquitous pagination/continuation "token".
_CREDENTIAL_NOUN = (
    r"(?:api[_-]?keys?|(?<!page\s)(?<!pagination\s)(?<!next\s)(?<!continuation\s)(?<!cursor\s)"
    r"(?<!page_)(?<!next_)tokens?|secrets?|passwords?|credentials|private\s+keys?)"
)

# Data-exfiltration hints embedded in metadata.
EXFIL_PATTERNS: tuple[Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\b(?:send|post|upload|exfiltrate|forward|transmit|leak|beacon)\b.{0,40}\b(?:to|->)\b.{0,40}https?://",
        # Tempered: the match starts at the verb *nearest* the path.
        rf"\b{_READ_VERB}\b(?:(?!\b{_READ_VERB}\b).){{0,40}}?" + _SENSITIVE_PATH,
        r"\b(?:include|append|attach|embed)\b.{0,30}\b" + _CREDENTIAL_NOUN + r"\b",
        (
            r"\b(?:send|post|upload|forward|include|append|attach|leak|copy|pass)\b.{0,40}"
            r"\b(?:(?:conversation|chat)\s+(?:history|transcript|log)|(?:entire|full|whole)\s+conversation"
            r"|system\s+prompt|previous\s+messages|message\s+history)\b"
        ),
        # Markdown image whose URL is templated with data: renders -> silent GET to attacker.
        r"!\[[^\]\n]{0,200}\]\(\s*https?://[^)\s?]{0,500}\?(?:[^)\s=]{0,100}=[^)\s&]{0,200}&)*[\w.-]{1,100}=\s*(?:\{|\$|%7B|<|\[)[^)\n]{0,500}\)",
    )
)

# A long base64 run: decoded and re-scanned, since encoding is a cheap filter bypass.
BASE64_RUN_RE: Pattern[str] = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")

# --------------------------------------------------------------------------- #
# Tool shadowing / cross-tool interference (TP03)                             #
# Metadata of one tool steering how the model uses *other* tools.             #
# --------------------------------------------------------------------------- #

SHADOWING_PATTERNS: tuple[Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\bwhen\s+(?:using|calling|invoking)\s+(?:the\s+)?(?!this\b)[`'\"]?[\w.-]+[`'\"]?\s+tool\b",
        r"\b(?:instead\s+of|rather\s+than)\s+(?:using|calling|invoking)\s+(?:the\s+)?(?!this\b)[`'\"]?[\w.-]+",
        r"\b(?:all|every|any)\s+(?:e-?mails?|messages?)\b.{0,40}\b(?:must|should)\s+(?:also\s+)?(?:be\s+)?(?:sent|cc'?d|bcc'?d|forwarded|copied|redirected)\s+to\b",
        r"\b(?:bcc|redirect|forward)\b[^@\n]{0,30}?(?<![\w.+-])[\w.+-]{1,64}@[\w-]{1,63}\.[\w.]{1,63}",
        r"\b(?:change|replace|override)\s+(?:the\s+)?(?:recipient|destination|to[\s-]address|email\s+address)\b",
        r"\bthis\s+tool\s+(?:overrides|replaces|supersedes)\b",
    )
)

# "Preference manipulation" (MPMA): biasing the model's tool choice toward this tool.
PREFERENCE_PATTERNS: tuple[Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\b(?:always|only)\s+(?:use|prefer|choose|select)\s+this\s+tool\b",
        r"\b(?:other|all\s+other)\s+tools?\s+(?:are|is)\s+(?:deprecated|broken|unsafe|disabled|outdated)\b",
        r"\bnever\s+(?:use|call|choose)\s+(?:any\s+)?other\s+tools?\b",
    )
)

# Parameter-name tokens that solicit secrets from the model (CyberArk FSP:
# "content_from_reading_ssh_id_rsa") or open a covert channel (Invariant: "sidenote").
SENSITIVE_PARAM_TOKENS: tuple[str, ...] = (
    "ssh", "id_rsa", "id_ed25519", "id_ecdsa", "private_key", "mcp_json", "aws_credentials",
    "passwd", "etc_shadow", "dotenv", "env_file",
)
COVERT_PARAM_TOKENS: tuple[str, ...] = ("sidenote", "side_note", "hidden_note", "note_to_model")

# MCP (2025-11-25) recommends tool names of [A-Za-z0-9_.-], 1-128 chars.
TOOL_NAME_RE: Pattern[str] = re.compile(r"^[A-Za-z0-9_.\-/]{1,128}$")

# --------------------------------------------------------------------------- #
# Hidden content (TP02)                                                       #
# --------------------------------------------------------------------------- #

# Zero-width / invisible / BiDi control characters used to smuggle text. Written
# as escapes: a security tool must not itself carry invisible source text.
INVISIBLE_CHARS: tuple[str, ...] = (
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\u200e",  # left-to-right mark
    "\u200f",  # right-to-left mark
    "\u2060",  # word joiner
    "\u2061", "\u2062", "\u2063", "\u2064",  # invisible math operators
    "\ufeff",  # zero-width no-break space / BOM
    "\xad",  # soft hyphen
    "\u034f",  # combining grapheme joiner
    "\u061c",  # Arabic letter mark
    "\u115f", "\u1160", "\u3164", "\uffa0",  # Hangul fillers
    "\u17b4", "\u17b5",  # Khmer inherent vowels
    "\u180e",  # Mongolian vowel separator
    "\u202a",  # LRE
    "\u202b",  # RLE
    "\u202c",  # PDF
    "\u202d",  # LRO
    "\u202e",  # RLO (classic spoofing)
    "\u2066",  # LRI
    "\u2067",  # RLI
    "\u2068",  # FSI
    "\u2069",  # PDI
    "\u206a", "\u206b", "\u206c", "\u206d", "\u206e", "\u206f",  # deprecated format chars
    "\ufff9", "\ufffa", "\ufffb",  # interlinear annotation
)
INVISIBLE_CHAR_SET: frozenset[str] = frozenset(INVISIBLE_CHARS)

# Unicode "Tags" block: invisible copies of ASCII, the "ASCII smuggling" channel.
TAG_CHAR_RANGE: tuple[int, int] = (0xE0000, 0xE007F)
# Variation selectors: VS1-16 legitimately follow emoji; long runs, and the
# supplement block, encode bytes invisibly ("emoji smuggling").
VARIATION_SELECTOR_RANGE: tuple[int, int] = (0xFE00, 0xFE0F)
VARIATION_SELECTOR_SUPPLEMENT_RANGE: tuple[int, int] = (0xE0100, 0xE01EF)
# ESC / CSI and other C0/C1 controls (tab, LF, CR excepted): ANSI sequences can
# hide or rewrite text in terminal-based clients (Trail of Bits, 2025).
CONTROL_CHAR_RE: Pattern[str] = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x80-\x9f]")
ANSI_ESCAPE_RE: Pattern[str] = re.compile(r"(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
# Blank padding that pushes trailing text out of view in approval dialogs.
PADDING_RE: Pattern[str] = re.compile(r"\S(?:[ \t]{80,}|(?:[ \t]*\n){20,}[ \t]*)\S")

HTML_COMMENT_RE: Pattern[str] = re.compile(r"<!--.*?-->", re.DOTALL)

# --------------------------------------------------------------------------- #
# Excessive agency / dangerous capabilities (CAP01)                           #
# Maps a capability label -> keywords that imply the tool wields it.          #
# --------------------------------------------------------------------------- #

CAPABILITY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "code execution": (
        "exec", "eval", "execute_code", "run_code", "arbitrary_code", "shell",
        "subprocess", "spawn",
    ),
    "shell / command": (
        "run_command", "execute_command", "shell_command", "os_command", "system_command",
        "os_system", "bash", "powershell",
    ),
    "filesystem write": (
        "write_file", "delete_file", "remove_file", "move_file", "rmdir", "unlink", "overwrite",
    ),
    "arbitrary network": (
        "http_request", "fetch_url", "curl", "wget", "send_request", "open_url", "webhook",
    ),
    "credential access": (
        "read_secret", "get_secret", "get_credentials", "dump_env", "list_tokens", "get_password",
    ),
    "database": ("execute_sql", "run_sql", "run_query", "drop_table", "delete_from"),
}
# Keywords match whole *words*, never substrings: "system" must not fire on
# "filesystem", nor "exec" on "executive". Multi-word keywords (write_file) match
# as consecutive words in any casing/separator style (write_file, writeFile,
# write-file, "write file"). A trailing plural "s" is tolerated (webhooks).

# Tokens that, appearing in a tool *name*, strongly imply a dangerous verb.
DANGEROUS_NAME_TOKENS: frozenset[str] = frozenset(
    {"exec", "eval", "shell", "command", "delete", "remove", "drop", "sudo", "admin"}
)

# --------------------------------------------------------------------------- #
# Command injection / RCE in source (CMD01)                                   #
# --------------------------------------------------------------------------- #

# Launch commands whose server has scannable source somewhere: script
# interpreters and package runners. Anything else (docker, a compiled binary, an
# inline ``bash -c`` one-liner) has no source to find, so a missing source_path
# there is not worth reporting.
SOURCE_INTERPRETERS: frozenset[str] = frozenset(
    {"python", "python3", "node", "deno", "bun", "uv", "tsx", "ts-node", "npx", "bunx", "uvx", "pipx"}
)

PY_EXTENSIONS: frozenset[str] = frozenset({".py"})
JS_EXTENSIONS: frozenset[str] = frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"})
SHELL_EXTENSIONS: frozenset[str] = frozenset({".sh"})

# A bare call: not a method (``regex.exec(``), attribute, or definition.
_BARE = r"(?<![\w.$])(?<!def )(?<!function )"


@dataclass(frozen=True)
class SourcePattern:
    """An RCE sink signature, scoped to the languages where it is meaningful.

    ``view`` selects what the pattern is matched against: ``"code"`` (comments
    *and* string-literal contents blanked, so prose like "never call eval()" in a
    docstring or error message cannot fire) or ``"text"`` (only comments
    blanked, for sinks whose danger lives inside a string, e.g. ``curl … | sh``).
    """

    label: str
    regex: Pattern[str]
    extensions: frozenset[str] | None  # None = every scanned language
    view: str = "code"


RCE_SOURCE_PATTERNS: tuple[SourcePattern, ...] = (
    SourcePattern(
        "python: subprocess shell=True",
        re.compile(r"subprocess\.\w+\([^)]*shell\s*=\s*True"),
        PY_EXTENSIONS,
    ),
    SourcePattern("python: os.system", re.compile(r"\bos\.system\s*\("), PY_EXTENSIONS),
    SourcePattern("python: os.popen", re.compile(r"\bos\.popen\s*\("), PY_EXTENSIONS),
    SourcePattern(
        "python: eval/exec", re.compile(_BARE + r"(?:eval|exec)\s*\("), PY_EXTENSIONS
    ),
    SourcePattern(
        "node: child_process.exec",
        re.compile(r"child_process\.(?:exec|execSync)\s*\("),
        JS_EXTENSIONS,
    ),
    SourcePattern(
        "node: exec/execSync (destructured child_process)",
        re.compile(_BARE + r"(?:exec|execSync)\s*\("),
        JS_EXTENSIONS,
    ),
    SourcePattern("node: eval", re.compile(_BARE + r"eval\s*\("), JS_EXTENSIONS),
    SourcePattern("node: new Function", re.compile(r"\bnew\s+Function\s*\("), JS_EXTENSIONS),
    SourcePattern(
        "shell: curl pipe to shell",
        re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:ba|z)?sh\b"),
        None,
        view="text",
    ),
)

# --------------------------------------------------------------------------- #
# Secrets in env (SEC01)                                                       #
# --------------------------------------------------------------------------- #

SECRET_NAME_RE: Pattern[str] = re.compile(
    r"(?:api[_-]?key|secret|token|password|passwd|access[_-]?key|private[_-]?key|client[_-]?secret)",
    re.IGNORECASE,
)

# High-confidence vendor key formats — value-based, name-independent.
SECRET_VALUE_PATTERNS: dict[str, Pattern[str]] = {
    # Anthropic first: its "sk-ant-" prefix would otherwise read as an OpenAI key.
    "Anthropic key": re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    # Legacy "sk-..." and project / service-account / admin keys ("sk-proj-...").
    "OpenAI key": re.compile(r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}"),
    "GitHub token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b"),
    "GitLab token": re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
    "AWS access key id": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "Slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "Slack webhook": re.compile(r"hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "Stripe secret key": re.compile(r"\b[rs]k_live_[A-Za-z0-9]{20,}\b"),
    "Hugging Face token": re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"),
    "npm token": re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
    "SendGrid key": re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    "Groq key": re.compile(r"\bgsk_[A-Za-z0-9]{40,}\b"),
    "xAI key": re.compile(r"\bxai-[A-Za-z0-9]{40,}\b"),
    "Supabase access token": re.compile(r"\bsbp_[a-f0-9]{40}\b"),
    "Linear API key": re.compile(r"\blin_api_[A-Za-z0-9]{32,}\b"),
    "Notion token": re.compile(r"\bntn_[A-Za-z0-9]{40,}\b"),
    "Database URL with password": re.compile(
        r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql)://[^:/\s@]+:[^@\s/]{3,}@"
    ),
    "Private key block": re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"
    ),
}

# Literal credentials in HTTP headers ("Authorization: Bearer <token>").
AUTH_HEADER_NAME_RE: Pattern[str] = re.compile(
    r"^(?:authorization|proxy-authorization|x-api-key|api-key|x-auth-token|x-access-token|cookie)$",
    re.IGNORECASE,
)
# A launch argument carrying a secret: "--api-key sk-..." or "--token=...".
SECRET_FLAG_RE: Pattern[str] = re.compile(
    r"^--?(?:[\w-]*(?:api[_-]?key|token|secret|password|passwd|access[_-]?key))(?:=(.*))?$",
    re.IGNORECASE,
)
# Credential-bearing URL query parameters ("?api_key=...").
URL_SECRET_PARAM_RE: Pattern[str] = re.compile(
    r"[?&](?:api[_-]?key|apikey|key|token|access[_-]?token|auth|secret|password|client[_-]?secret)=([^&#\s]{8,})",
    re.IGNORECASE,
)
URL_USERINFO_RE: Pattern[str] = re.compile(r"^[a-z][\w+.-]*://[^/@:\s]+:([^/@\s]+)@", re.IGNORECASE)

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

# Launchers whose packages should be version-pinned, by ecosystem.
NPM_LAUNCHERS: frozenset[str] = frozenset({"npx", "bunx"})
PY_LAUNCHERS: frozenset[str] = frozenset({"uvx", "pipx"})
PINNED_LAUNCHERS: frozenset[str] = NPM_LAUNCHERS | PY_LAUNCHERS

# Flags whose *value* is the package spec (``npx -p pkg@1 cmd``, ``uvx --from
# pkg==1 cmd``, ``pipx run --spec pkg==1 cmd``).
PACKAGE_FLAGS: dict[str, frozenset[str]] = {
    "npx": frozenset({"-p", "--package"}),
    "bunx": frozenset({"-p", "--package"}),
    "uvx": frozenset({"--from"}),
    "pipx": frozenset({"--spec"}),
}

# Other flags that consume the next argument, so it is not mistaken for the package.
VALUE_FLAGS: dict[str, frozenset[str]] = {
    "npx": frozenset({"-c", "--call", "--registry", "--cache", "--userconfig", "-w", "--workspace"}),
    "bunx": frozenset(),
    "uvx": frozenset({
        "--with", "-w", "--with-editable", "--with-requirements", "--python", "-p",
        "--index", "--index-url", "-i", "--extra-index-url", "--default-index",
        "--find-links", "-f", "--constraints", "-c", "--overrides", "--directory",
        "--project", "--cache-dir", "--config-file", "--python-preference",
    }),
    "pipx": frozenset({"--python", "--pip-args", "--index-url", "-i", "--backend"}),
}

# npm: name@1.2.3 (or @scope/name@1.2.3[-pre]). Rejects "latest", ranges ("^1", "~1"),
# and partial versions ("1.2", "1.x"), which npm resolves as ranges.
NPM_PINNED_RE: Pattern[str] = re.compile(r"@\d+\.\d+\.\d+(?:[-+][\w.\-]+)?$")
# Python: pkg==1.2.3 / pkg===1.2.3 / pkg@1.2.3 (uvx), extras allowed (pkg[cli]==1.0).
PY_PINNED_RE: Pattern[str] = re.compile(r"(?:===?|@)\s*\d[\w.\-+!]*$")
# A local path or built artifact: nothing is fetched from a registry.
LOCAL_PACKAGE_RE: Pattern[str] = re.compile(
    r"^(?:\.{1,2}[/\\]|[/\\~]|[A-Za-z]:[/\\])|\.(?:whl|tar\.gz|tgz|zip)$", re.IGNORECASE
)
REMOTE_FETCH_RE: Pattern[str] = re.compile(r"https?://|git\+|github:", re.IGNORECASE)
# Download tools: a URL in the same command line as one of these is fetch-and-run.
DOWNLOADER_RE: Pattern[str] = re.compile(
    r"\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer)\b", re.IGNORECASE
)
# Runtimes that execute a script straight from a URL (``deno run https://...``).
URL_SCRIPT_RUNNERS: frozenset[str] = frozenset({"deno", "bun"})

# Container launches: images should be pinned by digest, and some run flags
# hand the server the host.
CONTAINER_RUNTIMES: frozenset[str] = frozenset({"docker", "podman", "nerdctl"})
# ``docker run`` flags that consume the next argument (so it's not the image).
CONTAINER_VALUE_FLAGS: frozenset[str] = frozenset({
    "-e", "--env", "--env-file", "-v", "--volume", "--mount", "--name", "-p", "--publish",
    "--network", "--net", "-u", "--user", "-w", "--workdir", "--entrypoint", "-l", "--label",
    "--platform", "--pull", "--cap-add", "--cap-drop", "--security-opt", "-m", "--memory",
    "--cpus", "--add-host", "--device", "--tmpfs", "-h", "--hostname", "--dns", "--ulimit",
    "--pid", "--ipc", "--uts", "--userns", "--log-driver", "--log-opt", "--restart", "--runtime",
    "--gpus", "--cidfile", "--group-add", "--label-file", "--stop-signal", "--shm-size",
    "--health-cmd", "--volumes-from", "--link", "--expose", "--mac-address", "--ip", "--ip6",
})

# --------------------------------------------------------------------------- #
# Dangerous launch configuration (CFG01)                                      #
# --------------------------------------------------------------------------- #

# Env vars that inject code into the server process (or every child it spawns).
CODE_INJECTION_ENV: dict[str, str] = {
    "LD_PRELOAD": "preloads a shared library into the server process",
    "LD_AUDIT": "loads an audit library into the server process",
    "LD_LIBRARY_PATH": "redirects shared-library resolution",
    "DYLD_INSERT_LIBRARIES": "injects a dynamic library into the server process",
    "DYLD_LIBRARY_PATH": "redirects dynamic-library resolution",
    "DYLD_FRAMEWORK_PATH": "redirects framework resolution",
    "PYTHONSTARTUP": "runs a Python file at interpreter start",
    "PERL5OPT": "injects Perl command-line options",
    "RUBYOPT": "injects Ruby command-line options",
    "BASH_ENV": "sources a file in every non-interactive bash",
    "ENV": "sources a file in every POSIX sh",
    "PROMPT_COMMAND": "runs a command before every shell prompt",
}
# Env vars that are only dangerous with code-loading flags in their value.
CODE_LOADING_OPTION_ENV: dict[str, Pattern[str]] = {
    "NODE_OPTIONS": re.compile(r"(?:^|\s)(?:-r|--require|--import|--loader|--experimental-loader|--inspect(?:-brk)?)\b"),
    "JAVA_TOOL_OPTIONS": re.compile(r"-javaagent:|-agentpath:|-agentlib:"),
    "_JAVA_OPTIONS": re.compile(r"-javaagent:|-agentpath:|-agentlib:"),
}
# Env settings that switch off TLS certificate verification.
TLS_DISABLE_ENV: dict[str, Pattern[str]] = {
    "NODE_TLS_REJECT_UNAUTHORIZED": re.compile(r"^\s*0\s*$"),
    "PYTHONHTTPSVERIFY": re.compile(r"^\s*0\s*$"),
    "GIT_SSL_NO_VERIFY": re.compile(r"^\s*(?:1|true|yes)\s*$", re.IGNORECASE),
    "CURL_CA_BUNDLE": re.compile(r"^\s*$"),
    "REQUESTS_CA_BUNDLE": re.compile(r"^\s*$"),
}
# Env vars / flags that point the package manager at a non-default registry.
REGISTRY_OVERRIDE_ENV: frozenset[str] = frozenset({
    "NPM_CONFIG_REGISTRY", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "UV_INDEX_URL",
    "UV_EXTRA_INDEX_URL", "UV_DEFAULT_INDEX", "UV_INDEX", "BUN_CONFIG_REGISTRY",
})
REGISTRY_OVERRIDE_FLAGS: frozenset[str] = frozenset({
    "--registry", "--index-url", "-i", "--extra-index-url", "--index", "--default-index",
})
# LLM API base-URL overrides: a hostile value receives the server's API key.
API_BASE_URL_ENV: dict[str, tuple[str, ...]] = {
    "ANTHROPIC_BASE_URL": ("api.anthropic.com",),
    "OPENAI_BASE_URL": ("api.openai.com",),
    "OPENAI_API_BASE": ("api.openai.com",),
}
PRIVILEGE_ESCALATION_COMMANDS: frozenset[str] = frozenset({"sudo", "doas", "pkexec", "runas", "gsudo"})
# A path argument that exposes the whole disk or the whole home directory.
ROOT_PATH_RE: Pattern[str] = re.compile(r"^(?:/|[A-Za-z]:[\\/]?|\\\\)$")
HOME_PATH_RE: Pattern[str] = re.compile(
    r"^(?:~[\\/]?|\$HOME[\\/]?|\$\{HOME\}[\\/]?|%USERPROFILE%[\\/]?|/Users/[^/\\]+/?|/home/[^/\\]+/?|/root/?"
    r"|[A-Za-z]:[\\/]Users[\\/][^/\\]+[\\/]?)$"
)
ALL_INTERFACES_RE: Pattern[str] = re.compile(r"^(?:0\.0\.0\.0|::|\[::\])$")
HOST_FLAGS: frozenset[str] = frozenset({"--host", "--bind", "--listen", "-H", "--hostname", "--address"})
DOCKER_SOCKET_RE: Pattern[str] = re.compile(r"(?:^|[=:,\s])(?:/var)?/run/docker\.sock\b|docker_engine")
DANGEROUS_CAPS: frozenset[str] = frozenset({"ALL", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_ADMIN", "DAC_READ_SEARCH"})

# --------------------------------------------------------------------------- #
# Remote transport (NET01)                                                    #
# --------------------------------------------------------------------------- #

LOOPBACK_HOST_RE: Pattern[str] = re.compile(
    r"^(?:localhost|127(?:\.\d{1,3}){3}|\[?::1\]?|[\w.-]+\.localhost|host\.docker\.internal)$",
    re.IGNORECASE,
)
# Known compromise indicators (hosts / file names) from public MCP campaigns.
IOC_SUBSTRINGS: dict[str, str] = {
    "productivity-suite-mcp.onrender.com": "Deadbugz rug-pull campaign endpoint (Pillar Security, Aug 2026)",
    ".deadbug-mcp.py": "Deadbugz rug-pull campaign local payload (Pillar Security, Aug 2026)",
    "giftshop.club": "postmark-mcp BCC exfiltration domain (Koi Security, Sep 2025)",
    "45.115.38.27": "MCP reverse-shell C2 (Koi Security / JFrog, Oct 2025)",
}

# --------------------------------------------------------------------------- #
# Toxic flow / lethal trifecta (FLOW01)                                       #
# Tool roles inferred from names; matched as whole words like CAP01.          #
# --------------------------------------------------------------------------- #

# Reads content a third party can author: the entry point for indirect injection.
UNTRUSTED_INPUT_KEYWORDS: tuple[str, ...] = (
    "fetch", "fetch_url", "fetch_page", "browse", "browser_navigate", "navigate", "scrape",
    "crawl", "web_search", "search_web", "brave_web_search", "read_url", "get_url",
    "read_email", "get_email", "list_emails", "search_emails", "read_inbox", "get_inbox",
    "get_issue", "list_issues", "search_issues", "issue_read", "get_issue_comments",
    "get_pull_request", "list_pull_requests", "get_pull_request_comments", "get_comments",
    "list_comments", "read_messages", "get_messages", "list_messages", "search_messages",
    "channel_history", "get_channel_history", "conversations_history", "get_thread",
    "read_feed", "get_feed", "get_ticket", "list_tickets", "search_tickets", "get_tweets",
    "search_tweets", "read_webpage", "get_webpage",
)
# Reaches data the user would not want leaked.
PRIVATE_DATA_KEYWORDS: tuple[str, ...] = (
    "read_file", "read_text_file", "read_multiple_files", "get_file_contents", "read_files",
    "search_files", "list_directory", "directory_tree", "read_query", "execute_sql", "run_sql",
    "run_query", "query_database", "query", "sql", "get_secret", "read_secret", "get_credentials",
    "list_secrets", "get_env", "read_env", "get_document", "read_document", "search_documents",
    "list_private_repos", "get_calendar", "list_events", "get_contacts", "list_contacts",
    "get_customer", "list_customers", "list_tables", "describe_table", "git_show", "git_diff",
    "git_log", "search_code", "read_graph", "search_nodes",
)
# Can move data off the machine: the exfiltration sink.
EXTERNAL_SINK_KEYWORDS: tuple[str, ...] = (
    "fetch", "fetch_url", "http_request", "send_request", "post_request", "webhook", "curl",
    "wget", "send_email", "send_mail", "reply_email", "forward_email", "draft_email",
    "post_message", "send_message", "chat_post_message", "slack_post_message", "reply_to_thread",
    "create_issue", "add_issue_comment", "create_comment", "add_comment", "create_pull_request",
    "create_or_update_file", "push_files", "git_push", "create_gist", "upload_file", "upload",
    "publish", "tweet", "post_tweet", "create_post", "share_file", "browser_navigate", "navigate",
)
# Package -> roles for well-known servers, used when no manifest is available.
KNOWN_SERVER_ROLES: dict[str, frozenset[str]] = {
    "mcp-server-fetch": frozenset({"untrusted", "sink"}),
    "@modelcontextprotocol/server-fetch": frozenset({"untrusted", "sink"}),
    "@modelcontextprotocol/server-filesystem": frozenset({"private"}),
    "@modelcontextprotocol/server-github": frozenset({"untrusted", "private", "sink"}),
    "@modelcontextprotocol/server-gitlab": frozenset({"untrusted", "private", "sink"}),
    "@modelcontextprotocol/server-slack": frozenset({"untrusted", "private", "sink"}),
    "@modelcontextprotocol/server-brave-search": frozenset({"untrusted"}),
    "@modelcontextprotocol/server-puppeteer": frozenset({"untrusted", "sink"}),
    "@playwright/mcp": frozenset({"untrusted", "sink"}),
    "@modelcontextprotocol/server-postgres": frozenset({"private"}),
    "mcp-server-sqlite": frozenset({"private"}),
    "@modelcontextprotocol/server-gdrive": frozenset({"private"}),
    "mcp-server-git": frozenset({"private"}),
    "ghcr.io/github/github-mcp-server": frozenset({"untrusted", "private", "sink"}),
}
