/**
 * Offline advisory data for MCP server packages (used by SUP02) — a port of the
 * Python engine's `advisories.py`. Kept offline on purpose: the scanner must
 * work air-gapped and deterministically.
 *
 * Version ranges use a small syntax: comma-joined constraints are AND-ed
 * (">=0.0.5,<0.1.16"), a list of ranges is OR-ed, and "*" means every version.
 */

import { globalOf, pyDigitsToInt, pyRe, pyStrip } from "./pycompat";

export type AdvisoryKind = "vulnerable" | "malicious" | "unfixed" | "archived";
export type Ecosystem = "npm" | "pypi";

export interface Advisory {
  ecosystem: Ecosystem;
  package: string;
  affected: string[];
  kind: AdvisoryKind;
  severity: "critical" | "high" | "medium" | "low";
  summary: string;
  ids: string[];
  fixed: string | null;
  url: string;
}

function adv(
  ecosystem: Ecosystem,
  pkg: string,
  affected: string[],
  kind: AdvisoryKind,
  severity: Advisory["severity"],
  summary: string,
  ids: string[] = [],
  fixed: string | null = null,
  url = "",
): Advisory {
  return { ecosystem, package: pkg, affected, kind, severity, summary, ids, fixed, url };
}

const ARCHIVED_SUMMARY =
  "Archived reference server (moved to modelcontextprotocol/servers-archived, 2025); " +
  "receives no security fixes";
const ARCHIVED_URL = "https://github.com/modelcontextprotocol/servers-archived";

export const ADVISORIES: readonly Advisory[] = [
  // --- npm: published vulnerabilities ---------------------------------------------
  adv("npm", "mcp-remote", [">=0.0.5,<0.1.16"], "vulnerable", "critical",
    "OS command injection via a malicious server's authorization_endpoint",
    ["CVE-2025-6514", "GHSA-6xpm-ggf7-wc3p"], "0.1.16",
    "https://github.com/advisories/GHSA-6xpm-ggf7-wc3p"),
  adv("npm", "@modelcontextprotocol/inspector", ["<0.14.1"], "vulnerable", "critical",
    "Unauthenticated inspector proxy allows remote code execution (DNS rebinding / CSRF)",
    ["CVE-2025-49596", "GHSA-7f8r-222p-6f5g"], "0.14.1",
    "https://github.com/advisories/GHSA-7f8r-222p-6f5g"),
  adv("npm", "@modelcontextprotocol/server-filesystem",
    ["<=0.6.2", ">=2025.1.14,<2025.7.1"], "vulnerable", "high",
    "Sandbox escape: symlink following and allowed-directory prefix bypass",
    ["CVE-2025-53109", "GHSA-q66q-fx2p-7w4m", "CVE-2025-53110", "GHSA-hc55-p739-j48w"],
    "2025.7.1", "https://github.com/advisories/GHSA-q66q-fx2p-7w4m"),
  adv("npm", "figma-developer-mcp", ["<0.6.3"], "vulnerable", "high",
    "Command injection in the Framelink Figma MCP server",
    ["CVE-2025-53967", "GHSA-gxw4-4fc5-9gr5"], "0.6.3",
    "https://github.com/advisories/GHSA-gxw4-4fc5-9gr5"),
  adv("npm", "mcp-server-kubernetes", ["<2.5.0"], "vulnerable", "high",
    "Command injection via unsanitized kubectl arguments",
    ["CVE-2025-53355", "GHSA-gjv4-ghm7-q58q"], "2.5.0",
    "https://github.com/advisories/GHSA-gjv4-ghm7-q58q"),
  adv("npm", "@cyanheads/git-mcp-server", ["<2.1.5"], "vulnerable", "high",
    "Command injection via unsanitized git arguments",
    ["CVE-2025-53107", "GHSA-3q26-f695-pp76"], "2.1.5",
    "https://github.com/advisories/GHSA-3q26-f695-pp76"),
  adv("npm", "@mcpjam/inspector", ["<1.4.3"], "vulnerable", "high",
    "Remote code execution in the MCPJam inspector",
    ["CVE-2026-23744", "GHSA-232v-j27c-5pp6"], "1.4.3",
    "https://github.com/advisories/GHSA-232v-j27c-5pp6"),
  adv("npm", "gemini-mcp-tool", [">=1.1.2,<1.1.6"], "vulnerable", "high",
    "Command injection in gemini-mcp-tool",
    ["CVE-2026-0755", "GHSA-4h5r-5jm8-jxjm"], "1.1.6",
    "https://github.com/advisories/GHSA-4h5r-5jm8-jxjm"),
  adv("npm", "ios-simulator-mcp", ["<1.3.3"], "vulnerable", "high",
    "Command injection via unsanitized tool arguments",
    ["CVE-2025-52573", "GHSA-6f6r-m9pv-67jw"], "1.3.3",
    "https://github.com/advisories/GHSA-6f6r-m9pv-67jw"),
  adv("npm", "node-code-sandbox-mcp", ["<1.3.0"], "vulnerable", "high",
    "Sandbox escape / command injection",
    ["CVE-2025-53372", "GHSA-5w57-2ccq-8w95"], "1.3.0",
    "https://github.com/advisories/GHSA-5w57-2ccq-8w95"),
  adv("npm", "@akoskm/create-mcp-server-stdio", ["<0.0.13"], "vulnerable", "high",
    "Command injection in the generated server's tool",
    ["CVE-2025-54994", "GHSA-3ch2-jxxc-v4xf"], "0.0.13",
    "https://github.com/akoskm/create-mcp-server-stdio/security/advisories/GHSA-3ch2-jxxc-v4xf"),
  adv("npm", "adb-mcp", ["<=0.1.0"], "unfixed", "high",
    "Command injection; no fixed release published",
    ["CVE-2025-59834", "GHSA-54j7-grvr-9xwg"], null,
    "https://github.com/advisories/GHSA-54j7-grvr-9xwg"),
  adv("npm", "@modelcontextprotocol/server-postgres", ["*"], "unfixed", "high",
    "SQL injection escapes the read-only transaction (fixed only in git, then archived)",
    [], null,
    "https://securitylabs.datadoghq.com/articles/mcp-vulnerability-case-study-SQL-injection-in-the-postgresql-mcp-server/"),
  // --- npm: malicious packages ------------------------------------------------------
  adv("npm", "postmark-mcp", ["*"], "malicious", "critical",
    "Impersonation package; v1.0.16+ BCC'd every sent email to an attacker (removed from npm)",
    [], null, "https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/"),
  adv("npm", "@lanyer640/mcp-runcommand-server", ["*"], "malicious", "critical",
    "Opens a reverse shell to an attacker host",
    [], null, "https://www.koi.ai/blog/mcp-malware-wave-continues-a-remote-shell-in-backdoor"),
  // --- npm: archived reference servers ----------------------------------------------
  ...[
    "github", "gitlab", "slack", "puppeteer", "brave-search", "gdrive",
    "google-maps", "redis", "sentry", "aws-kb-retrieval", "everart",
  ].map((name) =>
    adv("npm", `@modelcontextprotocol/server-${name}`, ["*"], "archived", "low",
      ARCHIVED_SUMMARY, [], null, ARCHIVED_URL),
  ),
  // --- PyPI -------------------------------------------------------------------------
  adv("pypi", "mcp-server-git", ["<2025.12.18"], "vulnerable", "high",
    "Path-restriction bypass, unrestricted git_init, and argument injection " +
      "(git_diff / git_checkout)",
    ["CVE-2025-68143", "CVE-2025-68144", "GHSA-9xwc-hfwc-8w59", "CVE-2025-68145",
      "GHSA-j22h-9j4x-23w5"], "2025.12.18",
    "https://github.com/advisories/GHSA-9xwc-hfwc-8w59"),
  adv("pypi", "mcp-atlassian", ["<0.22.0"], "vulnerable", "high",
    "Arbitrary local file read via confluence_upload_attachment file_path",
    ["CVE-2026-73498", "GHSA-mfv2-4wvm-9pgp"], "0.22.0",
    "https://nvd.nist.gov/vuln/detail/CVE-2026-73498"),
  adv("pypi", "mcp-server-sqlite", ["*"], "unfixed", "high",
    "SQL injection in the archived reference server; will not be fixed",
    [], null,
    "https://www.trendmicro.com/en_us/research/25/f/why-a-classic-mcp-server-vulnerability-can-undermine-your-entire-ai-agent.html"),
  ...["mcp-runcmd-server", "mcp-runcommand-server", "mcp-runcommand-server2"].map((name) =>
    adv("pypi", name, ["*"], "malicious", "critical",
      "Malicious package: reverse shell to an attacker host (JFrog, Oct 2025)",
      [], null, "https://research.jfrog.com/post/3-malicious-mcps-pypi-reverse-shell/"),
  ),
  adv("pypi", "tiktoken-mcp", ["*"], "malicious", "critical",
    "Trojanized MCP fork planting persistence in .claude/.vscode/.cursor (UNC6780, GTIG)",
    [], null,
    "https://cloud.google.com/blog/topics/threat-intelligence/from-prompting-to-autonomy-the-evolution-of-adversarial-ai"),
];

const PYPI_SEPARATORS = pyRe(String.raw`[-_.]+`);

/** npm names are lowercased in practice; PyPI names are normalized per PEP 503. */
export function canonicalPackage(ecosystem: string, name: string): string {
  const lowered = pyStrip(name).toLowerCase();
  return ecosystem === "pypi" ? lowered.replace(globalOf(PYPI_SEPARATORS), "-") : lowered;
}

const VERSION_RE = pyRe(String.raw`^\s*v?(\d+(?:\.\d+)*)(.*)$`);
const PRERELEASE_RE = pyRe(String.raw`^[-.]?(?:a|alpha|b|beta|rc|c|pre|preview|dev|canary|next)`);
const CONSTRAINT_RE = pyRe(String.raw`^\s*(<=|>=|==|<|>|=)\s*(\S+)\s*$`);

/**
 * Numeric release tuple, with a trailing -1 for pre-releases: `1.2.3-beta.1` /
 * `1.2.3rc1` / `1.2.3.dev0` sort *below* `1.2.3` (the appended -1 loses to the
 * release's zero padding), as npm and PEP 440 order them.
 */
function versionTuple(version: string): number[] | null {
  const m = VERSION_RE.exec(version);
  if (!m) return null;
  const release = m[1].split(".").map(pyDigitsToInt);
  const suffix = pyStrip(m[2]).toLowerCase();
  if (PRERELEASE_RE.test(suffix)) {
    return [...release, ...Array<number>(Math.max(0, 3 - release.length)).fill(0), -1];
  }
  return release;
}

function compare(a: number[], b: number[]): number {
  const width = Math.max(a.length, b.length);
  for (let i = 0; i < width; i++) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    if (x !== y) return x > y ? 1 : -1;
  }
  return 0;
}

const OPS: Record<string, (c: number) => boolean> = {
  "<": (c) => c < 0,
  "<=": (c) => c <= 0,
  ">": (c) => c > 0,
  ">=": (c) => c >= 0,
  "==": (c) => c === 0,
  "=": (c) => c === 0,
};

/** True if `version` falls in any of `ranges` (unparseable -> false). */
export function versionMatches(version: string, ranges: string[]): boolean {
  if (ranges.includes("*")) return true;
  const parsed = versionTuple(version);
  if (parsed === null) return false;
  for (const spec of ranges) {
    let ok = true;
    for (const constraint of spec.split(",")) {
      const m = CONSTRAINT_RE.exec(constraint);
      const bound = m ? versionTuple(m[2]) : null;
      if (m === null || bound === null || !OPS[m[1]](compare(parsed, bound))) {
        ok = false;
        break;
      }
    }
    if (ok) return true;
  }
  return false;
}

/** All advisories for a package, matched on its canonical name. */
export function findAdvisories(ecosystem: string, pkg: string): Advisory[] {
  const key = canonicalPackage(ecosystem, pkg);
  return ADVISORIES.filter(
    (a) => a.ecosystem === ecosystem && canonicalPackage(a.ecosystem, a.package) === key,
  );
}
