/**
 * Scan orchestration — runs the rule set over parsed specs and assembles a
 * report with the exact JSON schema the Python engine emits.
 */

import { parseConfigText } from "./configParser";
import { RULES } from "./rules";
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

export const ENGINE_VERSION = "0.1.0";

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

/** Sort by descending severity, then rule id (stable, matches Python). */
function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const d = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    return d !== 0 ? d : a.rule_id.localeCompare(b.rule_id);
  });
}

export function scanSpec(spec: MCPServerSpec): TargetReport {
  const findings: Finding[] = [];
  for (const rule of RULES) {
    try {
      findings.push(...rule(spec));
    } catch {
      // Rule isolation: a broken rule must not abort the scan.
    }
  }
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

export function scanSpecs(specs: MCPServerSpec[], gate: Severity): ScanReport {
  const results = specs.map(scanSpec);
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
