/**
 * Detection rules (TypeScript port). Each rule is a pure function:
 * `(spec) => Finding[]`. Config/manifest-based rules mirror the Python engine;
 * source-scan (CMD01) and live-drift (MAN01) rules require the CLI/`--connect`
 * and are intentionally not part of the browser engine.
 */

import {
  CAPABILITY_KEYWORDS,
  DANGEROUS_NAME_TOKENS,
  EXFIL_PATTERNS,
  HTML_COMMENT_RE,
  INJECTION_PATTERNS,
  INVISIBLE_CHAR_SET,
  NPM_PINNED_RE,
  PINNED_LAUNCHERS,
  REMOTE_FETCH_RE,
  SECRET_NAME_RE,
  SECRET_VALUE_PATTERNS,
  looksLikePlaceholder,
} from "./patterns";
import {
  type Finding,
  type FindingLocation,
  type MCPServerSpec,
  type Severity,
  commandLine,
  parameterDescriptions,
} from "./types";

export type Rule = (spec: MCPServerSpec) => Finding[];

// --- helpers -----------------------------------------------------------------

function truncate(text: string, limit = 160): string {
  const collapsed = text.split(/\s+/).filter(Boolean).join(" ");
  return collapsed.length <= limit ? collapsed : collapsed.slice(0, limit - 1).trimEnd() + "…";
}

function firstMatch(patterns: RegExp[], text: string): string | null {
  for (const p of patterns) {
    const m = p.exec(text);
    if (m) return m[0];
  }
  return null;
}

function mk(
  base: Pick<Finding, "rule_id" | "category" | "mappings"> & { title: string; severity: Severity },
  over: Partial<Finding> & Pick<Finding, "location" | "evidence" | "remediation">,
): Finding {
  return {
    rule_id: base.rule_id,
    title: over.title ?? base.title,
    severity: over.severity ?? base.severity,
    category: base.category,
    location: over.location,
    evidence: over.evidence,
    remediation: over.remediation,
    mappings: base.mappings,
    confidence: over.confidence ?? 1.0,
  };
}

function basename(p: string): string {
  const parts = p.split(/[\\/]/);
  return parts[parts.length - 1] ?? p;
}

// --- TP01: tool poisoning ----------------------------------------------------

const TP01 = {
  rule_id: "TP01",
  title: "Prompt injection in tool metadata",
  category: "tool_poisoning" as const,
  mappings: ["OWASP-LLM01", "MCP-TOOL-POISONING"],
};

export const toolPoisoning: Rule = (spec) => {
  const m = spec.manifest;
  if (!m) return [];
  const out: Finding[] = [];

  const scan = (field: string, text: string, tool?: string) => {
    if (!text) return;
    const loc: FindingLocation = { server: spec.name, tool, field };
    const injection = firstMatch(INJECTION_PATTERNS, text);
    if (injection) {
      out.push(
        mk(
          { ...TP01, severity: "high" },
          {
            location: loc,
            evidence: truncate(injection),
            remediation:
              "Remove instruction-like content from this field. Tool/parameter descriptions should describe behavior, never direct the model.",
          },
        ),
      );
    }
    const exfil = firstMatch(EXFIL_PATTERNS, text);
    if (exfil) {
      out.push(
        mk(
          { ...TP01, severity: "critical" },
          {
            title: "Possible data-exfiltration directive in tool metadata",
            location: loc,
            evidence: truncate(exfil),
            remediation:
              "This field appears to instruct the model to send data to an external destination or read sensitive files. Treat the server as untrusted and review its source.",
          },
        ),
      );
    }
  };

  scan("instructions", m.instructions);
  for (const tool of m.tools) {
    scan("description", tool.description, tool.name);
    for (const [pname, pdesc] of Object.entries(parameterDescriptions(tool))) {
      scan(`param:${pname}`, pdesc, tool.name);
    }
  }
  for (const p of m.prompts) scan("description", p.description, p.name);
  for (const r of m.resources) scan("description", r.description, r.name || r.uri);
  return out;
};

// --- TP02: hidden content ----------------------------------------------------

const TP02 = {
  rule_id: "TP02",
  title: "Hidden or invisible content in tool metadata",
  category: "hidden_content" as const,
  mappings: ["OWASP-LLM01", "MCP-TOOL-POISONING"],
};

function namedInvisibles(text: string): string[] {
  const seen = new Set<string>();
  for (const ch of text) {
    if (INVISIBLE_CHAR_SET.has(ch)) {
      seen.add("U+" + ch.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0"));
    }
  }
  return [...seen];
}

export const hiddenContent: Rule = (spec) => {
  const m = spec.manifest;
  if (!m) return [];
  const out: Finding[] = [];

  const fields: Array<[string | undefined, string, string]> = [
    [undefined, "instructions", m.instructions],
  ];
  for (const tool of m.tools) {
    fields.push([tool.name, "description", tool.description]);
    for (const [pname, pdesc] of Object.entries(parameterDescriptions(tool))) {
      fields.push([tool.name, `param:${pname}`, pdesc]);
    }
  }

  for (const [tool, field, text] of fields) {
    if (!text) continue;
    const loc: FindingLocation = { server: spec.name, tool, field };
    const invis = namedInvisibles(text);
    if (invis.length) {
      out.push(
        mk(
          { ...TP02, severity: "high" },
          {
            location: loc,
            evidence: `invisible characters present: ${invis.join(", ")}`,
            remediation:
              "Strip zero-width / BiDi control characters from this field. Their only plausible purpose in metadata is to hide instructions from human reviewers.",
          },
        ),
      );
    }
    const comment = HTML_COMMENT_RE.exec(text);
    if (comment) {
      out.push(
        mk(
          { ...TP02, severity: "medium" },
          {
            title: "HTML comment hidden in tool metadata",
            location: loc,
            evidence: truncate(comment[0]),
            remediation:
              "Remove HTML comments; they are invisible in many UIs but read by the model.",
          },
        ),
      );
    }
  }
  return out;
};

// --- CAP01: excessive agency -------------------------------------------------

const CAP01 = {
  rule_id: "CAP01",
  title: "Tool exposes a dangerous capability",
  category: "excessive_agency" as const,
  mappings: ["OWASP-AGENTIC-EXCESSIVE-AGENCY"],
};

function tokenize(text: string): Set<string> {
  const spaced = text.replace(/([a-z0-9])(?=[A-Z])/g, "$1 ");
  return new Set(spaced.toLowerCase().match(/[a-z0-9]+/g) ?? []);
}

export const excessiveAgency: Rule = (spec) => {
  const m = spec.manifest;
  if (!m) return [];
  const out: Finding[] = [];
  for (const tool of m.tools) {
    const haystack = `${tool.name} ${tool.description}`.toLowerCase();
    const matched: string[] = [];
    for (const [cap, keywords] of Object.entries(CAPABILITY_KEYWORDS)) {
      if (keywords.some((kw) => haystack.includes(kw))) matched.push(cap);
    }
    if (matched.length) {
      const nameTokens = tokenize(tool.name);
      const dangerous = [...nameTokens].some((t) => DANGEROUS_NAME_TOKENS.has(t));
      out.push(
        mk(
          { ...CAP01, severity: dangerous ? "high" : "medium" },
          {
            location: { server: spec.name, tool: tool.name },
            evidence: `capabilities inferred: ${matched.sort().join(", ")}`,
            remediation:
              "Confirm this tool needs this power. Apply least privilege: scope filesystem/network access, sandbox execution, and require human approval for high-impact actions.",
            confidence: 0.7,
          },
        ),
      );
    }
  }
  return out;
};

// --- SEC01: secrets in env ---------------------------------------------------

const SEC01 = {
  rule_id: "SEC01",
  title: "Plaintext secret in server config env",
  category: "secrets" as const,
  mappings: ["CWE-798", "MCP-SECRETS"],
};

function redact(value: string): string {
  if (value.length <= 8) return value ? value[0] + "***" : "***";
  return `${value.slice(0, 4)}…${value.slice(-2)} (${value.length} chars)`;
}

export const secrets: Rule = (spec) => {
  const out: Finding[] = [];
  for (const [key, value] of Object.entries(spec.env)) {
    if (!value || looksLikePlaceholder(value)) continue;
    const loc: FindingLocation = { server: spec.name, field: `env:${key}` };

    let matchedVendor: string | null = null;
    for (const [vendor, pattern] of Object.entries(SECRET_VALUE_PATTERNS)) {
      if (pattern.test(value)) {
        matchedVendor = vendor;
        break;
      }
    }
    if (matchedVendor) {
      out.push(
        mk(
          { ...SEC01, severity: "critical" },
          {
            title: `Hardcoded ${matchedVendor} in config`,
            location: loc,
            evidence: `${key}=${redact(value)}`,
            remediation: `Move the secret out of the config. Reference it via an environment variable (e.g. "\${${key}}") and inject at runtime from a secret manager.`,
          },
        ),
      );
      continue;
    }
    if (SECRET_NAME_RE.test(key)) {
      out.push(
        mk(
          { ...SEC01, severity: "high" },
          {
            location: loc,
            evidence: `${key}=${redact(value)}`,
            remediation: `This env var name implies a credential. Do not store its value in the config; reference "\${${key}}" and inject from a secret manager.`,
            confidence: 0.6,
          },
        ),
      );
    }
  }
  return out;
};

// --- SUP01: unpinned / remote-fetched launch ---------------------------------

const SUP01 = {
  rule_id: "SUP01",
  title: "Unpinned or remote-fetched MCP server",
  category: "supply_chain" as const,
  mappings: ["MCP-SUPPLY-CHAIN", "SLSA-PROVENANCE"],
};

export const pinning: Rule = (spec) => {
  if (!spec.command) return [];
  const loc: FindingLocation = { server: spec.name, field: "command" };
  const cmdLine = commandLine(spec);

  if (REMOTE_FETCH_RE.test(cmdLine)) {
    return [
      mk(
        { ...SUP01, severity: "high" },
        {
          title: "MCP server fetches code from a remote URL at launch",
          location: loc,
          evidence: truncate(cmdLine),
          remediation:
            "Do not fetch-and-execute remote code at launch. Vendor the server, pin a version, and verify its integrity (hash / signature).",
        },
      ),
    ];
  }

  const launcher = basename(spec.command).toLowerCase();
  if (!PINNED_LAUNCHERS.has(launcher)) return [];

  const pkg = spec.args.find((a) => !a.startsWith("-"));
  if (!pkg || NPM_PINNED_RE.test(pkg)) return [];

  const tail = cmdLine.split(launcher).slice(1).join(launcher).trim();
  return [
    mk(
      { ...SUP01, severity: "medium" },
      {
        location: loc,
        evidence: `${launcher} ${tail}`.trim(),
        remediation: `Pin the package version (e.g. '${pkg}@1.2.3') so a compromised or malicious 'latest' release cannot execute on launch.`,
      },
    ),
  ];
};

/** All browser-runnable rules, in stable id order. */
export const RULES: Rule[] = [excessiveAgency, pinning, secrets, hiddenContent, toolPoisoning];
