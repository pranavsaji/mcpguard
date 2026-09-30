"""Offline advisory data for MCP server packages (used by SUP02).

A curated, dependency-free list of MCP packages with published vulnerabilities,
confirmed-malicious packages, and archived reference servers that will not
receive fixes. Kept offline on purpose: the scanner must work air-gapped and
deterministically in CI. Each entry cites its primary source; extend the list as
advisories are published (check GitHub Security Advisories / OSV for "mcp").

Version ranges use a small syntax: comma-joined constraints are AND-ed
(``">=0.0.5,<0.1.16"``), a tuple of ranges is OR-ed, and ``"*"`` means every version.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = ["ADVISORIES", "Advisory", "canonical_package", "find_advisories", "version_matches"]

VULNERABLE, MALICIOUS, UNFIXED, ARCHIVED = "vulnerable", "malicious", "unfixed", "archived"


@dataclass(frozen=True)
class Advisory:
    ecosystem: str  # "npm" | "pypi"
    package: str
    affected: tuple[str, ...]
    kind: str  # VULNERABLE | MALICIOUS | UNFIXED | ARCHIVED
    severity: str  # "critical" | "high" | "medium" | "low"
    summary: str
    ids: tuple[str, ...] = ()
    fixed: str | None = None
    url: str = ""


_ARCHIVED_SUMMARY = (
    "Archived reference server (moved to modelcontextprotocol/servers-archived, 2025); "
    "receives no security fixes"
)
_ARCHIVED_URL = "https://github.com/modelcontextprotocol/servers-archived"

ADVISORIES: tuple[Advisory, ...] = (
    # --- npm: published vulnerabilities -------------------------------------------------
    Advisory("npm", "mcp-remote", (">=0.0.5,<0.1.16",), VULNERABLE, "critical",
             "OS command injection via a malicious server's authorization_endpoint",
             ("CVE-2025-6514", "GHSA-6xpm-ggf7-wc3p"), "0.1.16",
             "https://github.com/advisories/GHSA-6xpm-ggf7-wc3p"),
    Advisory("npm", "@modelcontextprotocol/inspector", ("<0.14.1",), VULNERABLE, "critical",
             "Unauthenticated inspector proxy allows remote code execution (DNS rebinding / CSRF)",
             ("CVE-2025-49596", "GHSA-7f8r-222p-6f5g"), "0.14.1",
             "https://github.com/advisories/GHSA-7f8r-222p-6f5g"),
    Advisory("npm", "@modelcontextprotocol/server-filesystem",
             ("<=0.6.2", ">=2025.1.14,<2025.7.1"), VULNERABLE, "high",
             "Sandbox escape: symlink following and allowed-directory prefix bypass",
             ("CVE-2025-53109", "GHSA-q66q-fx2p-7w4m", "CVE-2025-53110", "GHSA-hc55-p739-j48w"),
             "2025.7.1", "https://github.com/advisories/GHSA-q66q-fx2p-7w4m"),
    Advisory("npm", "figma-developer-mcp", ("<0.6.3",), VULNERABLE, "high",
             "Command injection in the Framelink Figma MCP server",
             ("CVE-2025-53967", "GHSA-gxw4-4fc5-9gr5"), "0.6.3",
             "https://github.com/advisories/GHSA-gxw4-4fc5-9gr5"),
    Advisory("npm", "mcp-server-kubernetes", ("<2.5.0",), VULNERABLE, "high",
             "Command injection via unsanitized kubectl arguments",
             ("CVE-2025-53355", "GHSA-gjv4-ghm7-q58q"), "2.5.0",
             "https://github.com/advisories/GHSA-gjv4-ghm7-q58q"),
    Advisory("npm", "@cyanheads/git-mcp-server", ("<2.1.5",), VULNERABLE, "high",
             "Command injection via unsanitized git arguments",
             ("CVE-2025-53107", "GHSA-3q26-f695-pp76"), "2.1.5",
             "https://github.com/advisories/GHSA-3q26-f695-pp76"),
    Advisory("npm", "@mcpjam/inspector", ("<1.4.3",), VULNERABLE, "high",
             "Remote code execution in the MCPJam inspector",
             ("CVE-2026-23744", "GHSA-232v-j27c-5pp6"), "1.4.3",
             "https://github.com/advisories/GHSA-232v-j27c-5pp6"),
    Advisory("npm", "gemini-mcp-tool", (">=1.1.2,<1.1.6",), VULNERABLE, "high",
             "Command injection in gemini-mcp-tool",
             ("CVE-2026-0755", "GHSA-4h5r-5jm8-jxjm"), "1.1.6",
             "https://github.com/advisories/GHSA-4h5r-5jm8-jxjm"),
    Advisory("npm", "ios-simulator-mcp", ("<1.3.3",), VULNERABLE, "high",
             "Command injection via unsanitized tool arguments",
             ("CVE-2025-52573", "GHSA-6f6r-m9pv-67jw"), "1.3.3",
             "https://github.com/advisories/GHSA-6f6r-m9pv-67jw"),
    Advisory("npm", "node-code-sandbox-mcp", ("<1.3.0",), VULNERABLE, "high",
             "Sandbox escape / command injection",
             ("CVE-2025-53372", "GHSA-5w57-2ccq-8w95"), "1.3.0",
             "https://github.com/advisories/GHSA-5w57-2ccq-8w95"),
    Advisory("npm", "@akoskm/create-mcp-server-stdio", ("<0.0.13",), VULNERABLE, "high",
             "Command injection in the generated server's tool",
             ("CVE-2025-54994", "GHSA-3ch2-jxxc-v4xf"), "0.0.13",
             "https://github.com/akoskm/create-mcp-server-stdio/security/advisories/GHSA-3ch2-jxxc-v4xf"),
    Advisory("npm", "adb-mcp", ("<=0.1.0",), UNFIXED, "high",
             "Command injection; no fixed release published",
             ("CVE-2025-59834", "GHSA-54j7-grvr-9xwg"), None,
             "https://github.com/advisories/GHSA-54j7-grvr-9xwg"),
    Advisory("npm", "@modelcontextprotocol/server-postgres", ("*",), UNFIXED, "high",
             "SQL injection escapes the read-only transaction (fixed only in git, then archived)",
             (), None,
             "https://securitylabs.datadoghq.com/articles/mcp-vulnerability-case-study-SQL-injection-in-the-postgresql-mcp-server/"),
    # --- npm: malicious packages ----------------------------------------------------------
    Advisory("npm", "postmark-mcp", ("*",), MALICIOUS, "critical",
             "Impersonation package; v1.0.16+ BCC'd every sent email to an attacker (removed from npm)",
             (), None, "https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/"),
    Advisory("npm", "@lanyer640/mcp-runcommand-server", ("*",), MALICIOUS, "critical",
             "Opens a reverse shell to an attacker host",
             (), None, "https://www.koi.ai/blog/mcp-malware-wave-continues-a-remote-shell-in-backdoor"),
    # --- npm: archived reference servers -------------------------------------------------
    *(
        Advisory("npm", f"@modelcontextprotocol/server-{name}", ("*",), ARCHIVED, "low",
                 _ARCHIVED_SUMMARY, (), None, _ARCHIVED_URL)
        for name in ("github", "gitlab", "slack", "puppeteer", "brave-search", "gdrive",
                     "google-maps", "redis", "sentry", "aws-kb-retrieval", "everart")
    ),
    # --- PyPI ---------------------------------------------------------------------------
    Advisory("pypi", "mcp-server-git", ("<2025.12.18",), VULNERABLE, "high",
             "Path-restriction bypass, unrestricted git_init, and argument injection "
             "(git_diff / git_checkout)",
             ("CVE-2025-68143", "CVE-2025-68144", "GHSA-9xwc-hfwc-8w59", "CVE-2025-68145",
              "GHSA-j22h-9j4x-23w5"), "2025.12.18",
             "https://github.com/advisories/GHSA-9xwc-hfwc-8w59"),
    Advisory("pypi", "mcp-atlassian", ("<0.22.0",), VULNERABLE, "high",
             "Arbitrary local file read via confluence_upload_attachment file_path",
             ("CVE-2026-73498", "GHSA-mfv2-4wvm-9pgp"), "0.22.0",
             "https://nvd.nist.gov/vuln/detail/CVE-2026-73498"),
    Advisory("pypi", "mcp-server-sqlite", ("*",), UNFIXED, "high",
             "SQL injection in the archived reference server; will not be fixed",
             (), None,
             "https://www.trendmicro.com/en_us/research/25/f/why-a-classic-mcp-server-vulnerability-can-undermine-your-entire-ai-agent.html"),
    *(
        Advisory("pypi", name, ("*",), MALICIOUS, "critical",
                 "Malicious package: reverse shell to an attacker host (JFrog, Oct 2025)",
                 (), None, "https://research.jfrog.com/post/3-malicious-mcps-pypi-reverse-shell/")
        for name in ("mcp-runcmd-server", "mcp-runcommand-server", "mcp-runcommand-server2")
    ),
    Advisory("pypi", "tiktoken-mcp", ("*",), MALICIOUS, "critical",
             "Trojanized MCP fork planting persistence in .claude/.vscode/.cursor (UNC6780, GTIG)",
             (), None,
             "https://cloud.google.com/blog/topics/threat-intelligence/from-prompting-to-autonomy-the-evolution-of-adversarial-ai"),
)


def canonical_package(ecosystem: str, name: str) -> str:
    """npm names are case-sensitive-ish but lowercased in practice; PyPI per PEP 503."""
    name = name.strip().lower()
    return re.sub(r"[-_.]+", "-", name) if ecosystem == "pypi" else name


def _version_tuple(version: str) -> tuple[int, ...] | None:
    """Numeric release tuple, with a trailing ``-1`` for pre-releases.

    ``1.2.3-beta.1`` / ``1.2.3rc1`` / ``1.2.3.dev0`` sort *below* ``1.2.3`` (the
    appended -1 loses to the release's zero padding), as npm and PEP 440 order them.
    """
    match = re.match(r"^\s*v?(\d+(?:\.\d+)*)(.*)$", version)
    if not match:
        return None
    release = tuple(int(p) for p in match.group(1).split("."))
    suffix = match.group(2).strip().lower()
    if re.match(r"^[-.]?(?:a|alpha|b|beta|rc|c|pre|preview|dev|canary|next)", suffix):
        return (*release, *(0,) * max(0, 3 - len(release)), -1)
    return release


def _compare(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    width = max(len(a), len(b))
    pa, pb = a + (0,) * (width - len(a)), b + (0,) * (width - len(b))
    return (pa > pb) - (pa < pb)


_OPS = {
    "<": lambda c: c < 0, "<=": lambda c: c <= 0, ">": lambda c: c > 0,
    ">=": lambda c: c >= 0, "==": lambda c: c == 0, "=": lambda c: c == 0,
}


def version_matches(version: str, ranges: tuple[str, ...]) -> bool:
    """True if ``version`` falls in any of ``ranges`` (unparseable -> False)."""
    if "*" in ranges:
        return True
    parsed = _version_tuple(version)
    if parsed is None:
        return False
    for spec in ranges:
        ok = True
        for constraint in spec.split(","):
            m = re.match(r"^\s*(<=|>=|==|<|>|=)\s*(\S+)\s*$", constraint)
            bound = _version_tuple(m.group(2)) if m else None
            if m is None or bound is None or not _OPS[m.group(1)](_compare(parsed, bound)):
                ok = False
                break
        if ok:
            return True
    return False


def find_advisories(ecosystem: str, package: str) -> list[Advisory]:
    """All advisories for a package, matched on its canonical name."""
    key = canonical_package(ecosystem, package)
    return [
        a for a in ADVISORIES
        if a.ecosystem == ecosystem and canonical_package(a.ecosystem, a.package) == key
    ]
