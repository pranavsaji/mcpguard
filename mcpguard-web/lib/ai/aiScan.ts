/**
 * Server-side AI scan for the dashboard: the deterministic engine plus the AI
 * judge rules that work on a config (no source files, no lockfile here):
 *
 *  - AI01  semantic tool poisoning (mirrors Python `rules/ai_judge.py`)
 *  - AI03  tool capability vs. the server's stated purpose (`rules/ai_purpose.py`)
 *  - FLOW01 with AI-inferred tool roles (`rules/toxic_flow.py` `ai_tool_roles`)
 *  - AI00  judge degraded / unavailable — reported, never a silent pass
 *
 * Additive only: AI findings are appended to the deterministic report; nothing is
 * removed. AI02 (source review) and MAN01's semantic drift need the CLI.
 */

import { parseLaunch } from "../scanner/launchers";
import { aiRoleKey } from "../scanner/rules";
import { assembleReport, finalizeTarget, scanSpecs } from "../scanner/scan";
import { truncate } from "../scanner/detectors";
import {
  type Finding,
  type MCPManifest,
  type MCPServerSpec,
  type ScanReport,
  type Severity,
  SEVERITY_RANK,
  manifestTextFields,
} from "../scanner/types";
import type { AIConfig } from "./judge";

const INSTRUCTIONS_OWNER = "(server instructions)";

const AI01 = {
  rule_id: "AI01",
  title: "AI judge: tool metadata manipulates the assistant",
  category: "tool_poisoning" as const,
  mappings: ["OWASP-LLM01", "MCP-TOOL-POISONING"],
};
const AI01_SEVERITY: Record<string, Severity> = {
  exfiltration: "critical",
  injection: "high",
  concealment: "high",
  tool_steering: "high",
};
const AI01_LABELS: Record<string, string> = {
  injection: "directs the assistant",
  exfiltration: "solicits or sends sensitive data",
  concealment: "asks for secrecy from the user",
  tool_steering: "steers other tools",
};
const AI03 = {
  rule_id: "AI03",
  title: "AI judge: tool exceeds the server's stated purpose",
  category: "excessive_agency" as const,
  mappings: ["OWASP-AGENTIC-EXCESSIVE-AGENCY"],
};
const ROLE_QUESTIONS: Record<string, string> = {
  untrusted_input: "untrusted",
  private_data: "private",
  external_sink: "sink",
  code_exec: "exec",
};

/** Python `f"{p:.2f}"`. */
const p2 = (p: number): string => p.toFixed(2);
/** Python `round(p, 2)`. */
const r2 = (p: number): number => Math.round(p * 100) / 100;

/** Owner -> all of its model-visible text, labelled by field (Python `_groups`). */
function metadataGroups(manifest: MCPManifest): Map<string, string> {
  const groups = new Map<string, string[]>();
  const push = (owner: string, line: string) => groups.set(owner, [...(groups.get(owner) ?? []), line]);
  for (const tool of manifest.tools) push(tool.name, `[tool name] ${tool.name}`);
  for (const [owner, field, text] of manifestTextFields(manifest)) push(owner ?? INSTRUCTIONS_OWNER, `[${field}] ${text}`);
  return new Map([...groups].map(([owner, lines]) => [owner, lines.join("\n")]));
}

async function ai01(spec: MCPServerSpec, ai: AIConfig): Promise<Finding[]> {
  const out: Finding[] = [];
  if (!spec.manifest) return out;
  for (const [owner, document] of metadataGroups(spec.manifest)) {
    const verdict = await ai.ask("metadata", document);
    if (verdict === null) return out;
    const hits = Object.keys(verdict.scores)
      .filter((q) => verdict.scores[q] >= ai.threshold)
      .sort((a, b) => verdict.scores[b] - verdict.scores[a]);
    if (!hits.length) continue;
    const severity = hits
      .map((q) => AI01_SEVERITY[q] ?? "high")
      .reduce((a, b) => (SEVERITY_RANK[b] > SEVERITY_RANK[a] ? b : a));
    const isInstructions = owner === INSTRUCTIONS_OWNER;
    out.push({
      ...AI01,
      severity,
      location: isInstructions ? { server: spec.name, field: "instructions" } : { server: spec.name, tool: owner },
      evidence: truncate(
        `${verdict.judge}: ` + hits.map((q) => `${AI01_LABELS[q] ?? q} p=${p2(verdict.scores[q])}`).join(", "),
        300,
      ),
      remediation:
        "An AI judge reads this text as an attempt to manipulate the assistant. Review it by hand; treat the server as untrusted until you do.",
      confidence: r2(Math.max(...hits.map((q) => verdict.scores[q]))),
    });
  }
  return out;
}

/** Python `redact_url`: credentials and query strings never reach a judge. */
export function redactUrl(url: string): string {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.hostname}${u.port ? `:${u.port}` : ""}${u.pathname}`;
  } catch {
    return "(unparseable url)";
  }
}

/** Python `stated_purpose`. */
export function statedPurpose(spec: MCPServerSpec, manifest: MCPManifest): string {
  const parts = [`server name: ${spec.name}`];
  const launch = parseLaunch(spec.command, spec.args);
  if (launch) parts.push(`package: ${launch.name}`);
  else if (spec.url) parts.push(`remote endpoint: ${redactUrl(spec.url)}`);
  if (manifest.instructions) parts.push(`server instructions: ${manifest.instructions}`);
  return parts.join("\n");
}

async function ai03(spec: MCPServerSpec, ai: AIConfig): Promise<Finding[]> {
  const out: Finding[] = [];
  const manifest = spec.manifest;
  if (!manifest || !manifest.tools.length) return out;
  const purpose = statedPurpose(spec, manifest);
  for (const tool of manifest.tools) {
    const verdict = await ai.ask("purpose", {
      server_purpose: purpose,
      tool: `name: ${tool.name}\ndescription: ${tool.description}`,
    });
    if (verdict === null) return out;
    const mismatch = verdict.scores.mismatch ?? 0;
    const excessive = verdict.scores.excessive ?? 0;
    const location = { server: spec.name, tool: tool.name };
    if (mismatch >= ai.threshold) {
      out.push({
        ...AI03,
        title: "AI judge: tool description reveals hidden or mismatched behavior",
        severity: "high",
        location,
        evidence: truncate(`${verdict.judge}: mismatch p=${p2(mismatch)}; ${tool.description}`, 240),
        remediation:
          "The tool does something its name and the server's purpose don't suggest. Treat it as deceptive until reviewed.",
        confidence: r2(mismatch),
      });
    } else if (excessive >= ai.threshold) {
      out.push({
        ...AI03,
        severity: "medium",
        location,
        evidence: truncate(
          `${verdict.judge}: excessive p=${p2(excessive)}; purpose: ${purpose.split("\n")[0]}; tool: ${tool.name}`,
          240,
        ),
        remediation:
          "This server doesn't need this power for what it says it does. Remove or disable the tool, or require approval for every call.",
        confidence: r2(excessive),
      });
    }
  }
  return out;
}

/** Toxic-flow roles the judge reads from each tool's name + description. */
async function inferRoles(specs: MCPServerSpec[], ai: AIConfig): Promise<Map<string, Set<string>>> {
  const roles = new Map<string, Set<string>>();
  for (const spec of specs) {
    for (const tool of spec.manifest?.tools ?? []) {
      const verdict = await ai.ask("roles", `name: ${tool.name}\ndescription: ${tool.description}`);
      if (verdict === null) continue;
      const set = new Set<string>();
      for (const [q, role] of Object.entries(ROLE_QUESTIONS)) {
        if ((verdict.scores[q] ?? 0) >= ai.roleThreshold) set.add(role);
      }
      roles.set(aiRoleKey(spec.name, tool.name), set);
    }
  }
  return roles;
}

function aiUnavailable(spec: MCPServerSpec, ai: AIConfig, errors: string[]): Finding {
  const unique = [...new Set(errors)];
  return {
    rule_id: "AI00",
    title: "AI judge degraded or unavailable (semantic checks may be incomplete)",
    severity: ai.failClosed ? "high" : "info",
    category: "tool_poisoning",
    location: { server: spec.name },
    evidence: `${errors.length} failed judgement(s): ${unique.slice(0, 2).join("; ")}`.slice(0, 300),
    remediation:
      "Check the judge's API key, quota, and network. Deterministic rules still ran; use failClosed to fail the gate when the AI layer can't answer.",
    mappings: [],
    confidence: 0,
  };
}

/** Deterministic scan + AI rules, as one report (same schema as `scanSpecs`). */
export async function aiScanSpecs(specs: MCPServerSpec[], gate: Severity, ai: AIConfig): Promise<ScanReport> {
  const roleErrorsFrom = ai.errors.length;
  const aiRoles = await inferRoles(specs, ai);
  const roleErrors = ai.errors.slice(roleErrorsFrom);
  const base = scanSpecs(specs, gate, { aiRoles });

  // Each judge problem is reported once, on the first target it affected (as the
  // Python CLI does) — not repeated on every server card.
  const reported = new Set<string>();
  const results = [];
  for (const [i, spec] of specs.entries()) {
    const before = ai.errors.length;
    const extra = [...(await ai01(spec, ai)), ...(await ai03(spec, ai))];
    const errors = [...(i === 0 ? roleErrors : []), ...ai.errors.slice(before)].filter((e) => !reported.has(e));
    errors.forEach((e) => reported.add(e));
    if (errors.length) extra.push(aiUnavailable(spec, ai, errors));
    results.push(finalizeTarget(spec.name, [...extra, ...base.results[i].findings]));
  }
  return assembleReport(results, gate);
}
