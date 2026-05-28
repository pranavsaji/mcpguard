/**
 * Core domain types for the MCPGuard scan engine (TypeScript port).
 *
 * The JSON shapes here mirror the Python engine's `to_dict()` output exactly,
 * so reports are interchangeable between the CLI and this web app. Parity is
 * enforced by a test against the shared fixtures.
 */

export const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];

/** Numeric rank for ordering / threshold comparisons. */
export const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function severityAtLeast(a: Severity, b: Severity): boolean {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b];
}

export type Category =
  | "tool_poisoning"
  | "hidden_content"
  | "excessive_agency"
  | "rce_surface"
  | "secrets"
  | "supply_chain"
  | "rug_pull"
  | "manifest_drift";

export interface FindingLocation {
  server?: string;
  tool?: string;
  field?: string;
  path?: string;
  line?: number;
}

export interface Finding {
  rule_id: string;
  title: string;
  severity: Severity;
  category: Category;
  location: FindingLocation;
  evidence: string;
  remediation: string;
  mappings: string[];
  confidence: number;
}

export interface TargetReport {
  target: string;
  summary: {
    total: number;
    by_severity: Record<string, number>;
    max_severity: Severity | null;
  };
  findings: Finding[];
}

export interface ScanReport {
  tool: "mcpguard";
  version: string;
  gate: Severity;
  ok: boolean;
  summary: {
    targets: number;
    total_findings: number;
    by_severity: Record<string, number>;
  };
  results: TargetReport[];
}

// --- MCP domain --------------------------------------------------------------

export type Transport = "stdio" | "http" | "sse" | "unknown";

export interface MCPTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

export interface MCPResource {
  uri: string;
  name: string;
  description: string;
}

export interface MCPPrompt {
  name: string;
  description: string;
}

export interface MCPManifest {
  instructions: string;
  tools: MCPTool[];
  resources: MCPResource[];
  prompts: MCPPrompt[];
}

export interface MCPServerSpec {
  name: string;
  transport: Transport;
  command: string | null;
  args: string[];
  env: Record<string, string>;
  url: string | null;
  manifest: MCPManifest | null;
}

/** Parameter descriptions pulled from a tool's JSON input schema. */
export function parameterDescriptions(tool: MCPTool): Record<string, string> {
  const props = (tool.inputSchema as { properties?: unknown }).properties;
  if (!props || typeof props !== "object") return {};
  const out: Record<string, string> = {};
  for (const [name, schema] of Object.entries(props as Record<string, unknown>)) {
    if (schema && typeof schema === "object") {
      const desc = (schema as { description?: unknown }).description;
      if (typeof desc === "string") out[name] = desc;
    }
  }
  return out;
}

export function commandLine(spec: MCPServerSpec): string {
  const parts = spec.command ? [spec.command, ...spec.args] : [...spec.args];
  return parts.filter(Boolean).join(" ");
}
