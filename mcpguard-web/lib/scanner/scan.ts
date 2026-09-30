/**
 * Scan orchestration — runs the rule set over parsed specs and assembles a
 * report with the exact JSON schema the Python engine emits.
 */

import { parseConfigText } from "./configParser";
import { pyCompare } from "./pycompat";
import { RULES, type RuleContext } from "./rules";
import {
  type Finding,
  type MCPServerSpec,
  type ScanReport,
  type Severity,
  type TargetReport,
  SEVERITIES,
  SEVERITY_RANK,
  severityAtLeast,
} from "./types";

/** Matches the Python engine's version; findings are identical for shared rules. */
export const ENGINE_VERSION = "0.2.0";

function bySeverity(findings: Finding[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const f of findings) out[f.severity] = (out[f.severity] ?? 0) + 1;
  return out;
}

function maxSeverity(findings: Finding[]): Severity | null {
  let best: Severity | null = null;
  for (const f of findings) {
    if (best === null || SEVERITY_RANK[f.severity] > SEVERITY_RANK[best]) best = f.severity;
  }
  return best;
}

/** Sort by descending severity, then rule id (stable, like Python's `sorted`). */
function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const d = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    return d !== 0 ? d : pyCompare(a.rule_id, b.rule_id);
  });
}

/** Python `_run_rule`: a rule that throws becomes an INFO finding, not an aborted scan. */
function runRule(id: string, run: (spec: MCPServerSpec, ctx: RuleContext) => Finding[], spec: MCPServerSpec, ctx: RuleContext): Finding[] {
  try {
    return run(spec, ctx);
  } catch (e) {
    const err = e instanceof Error ? e : new Error(String(e));
    return [
      {
        rule_id: id,
        title: "Rule raised an exception (skipped)",
        severity: "info",
        category: "supply_chain",
        location: { server: spec.name },
        evidence: `${err.name}: ${err.message}`,
        remediation: "This is an MCPGuard bug; please report it.",
        mappings: [],
        confidence: 0.0,
      },
    ];
  }
}

function report(spec: MCPServerSpec, ctx: RuleContext): TargetReport {
  const findings: Finding[] = [];
  for (const { id, run } of RULES) findings.push(...runRule(id, run, spec, ctx));
  const sorted = sortFindings(findings);
  return {
    target: spec.name,
    summary: {
      total: sorted.length,
      by_severity: bySeverity(sorted),
      max_severity: maxSeverity(sorted),
    },
    findings: sorted,
  };
}

/** Scan one server on its own (cross-server rules see only this server). */
export function scanSpec(spec: MCPServerSpec): TargetReport {
  return report(spec, { peers: [[spec, spec.manifest]] });
}

/**
 * Scan every server in one config. Cross-server rules (tool shadowing, toxic
 * flow) see the whole config's manifests, in config order.
 */
export function scanSpecs(
  specs: MCPServerSpec[],
  gate: Severity,
  extras: Pick<RuleContext, "aiRoles"> = {},
): ScanReport {
  const ctx: RuleContext = { peers: specs.map((s) => [s, s.manifest]), ...extras };
  return assembleReport(specs.map((spec) => report(spec, ctx)), gate);
}

/**
 * Re-sort one target's findings (after extra findings were appended, e.g. by the
 * server-side AI layer) and recompute its summary.
 */
export function finalizeTarget(target: string, findings: Finding[]): TargetReport {
  const sorted = sortFindings(findings);
  return {
    target,
    summary: { total: sorted.length, by_severity: bySeverity(sorted), max_severity: maxSeverity(sorted) },
    findings: sorted,
  };
}

/** Build the top-level report (gate verdict, totals) from per-target reports. */
export function assembleReport(results: TargetReport[], gate: Severity): ScanReport {
  const all = results.flatMap((r) => r.findings);
  const failed = all.some((f) => severityAtLeast(f.severity, gate));
  return {
    tool: "mcpguard",
    version: ENGINE_VERSION,
    gate,
    ok: !failed,
    summary: {
      targets: results.length,
      total_findings: all.length,
      by_severity: bySeverity(all),
    },
    results,
  };
}

/** Parse config text and scan it in one call. */
export function scanConfigText(text: string, gate: Severity = "high"): ScanReport {
  const specs = parseConfigText(text);
  return scanSpecs(specs, gate);
}

export { SEVERITIES };
