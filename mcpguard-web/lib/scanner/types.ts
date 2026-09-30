/**
 * Core domain types for the MCPGuard scan engine (TypeScript port).
 *
 * The JSON shapes here mirror the Python engine's `to_dict()` output exactly,
 * so reports are interchangeable between the CLI and this web app. Parity is
 * enforced by a test against the shared fixtures.
 */

import { orderedEntries, orderedMap, pyStr, removeSuffix } from "./pycompat";

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
  | "manifest_drift"
  | "tool_shadowing"
  | "toxic_flow"
  | "vulnerable_component"
  | "insecure_config"
  | "insecure_transport";

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
  title: string;
  /** MCP behavior hints (readOnlyHint, destructiveHint, openWorldHint, title). */
  annotations: Record<string, unknown>;
  outputSchema: Record<string, unknown>;
}

export interface MCPResource {
  uri: string;
  name: string;
  description: string;
}

export interface MCPPrompt {
  name: string;
  description: string;
  /** Argument name -> description. */
  arguments: Record<string, string>;
}

export interface MCPManifest {
  instructions: string;
  tools: MCPTool[];
  resources: MCPResource[];
  prompts: MCPPrompt[];
  /** MCP 2026-07-28 list-result cache hint `ttlMs`, when served (an integer). */
  ttlMs?: number | null;
  /** MCP 2026-07-28 list-result cache hint `cacheScope` ("" when absent). */
  cacheScope?: string;
}

export interface MCPServerSpec {
  name: string;
  transport: Transport;
  command: string | null;
  args: string[];
  env: Record<string, string>;
  url: string | null;
  /** HTTP headers for a remote server (e.g. Authorization). */
  headers: Record<string, string>;
  manifest: MCPManifest | null;
}

// --- model-visible text (port of models.py text_fields / schema_text_fields) ---

// Keywords holding a map of *named* subschemas; their keys are names, not keywords.
const NAMED_SUBSCHEMA_KEYS: ReadonlySet<string> = new Set([
  "properties", "patternProperties", "$defs", "definitions", "dependentSchemas", "dependencies",
]);
// Standard JSON Schema keywords. Any *other* key is itself model-visible text.
const SCHEMA_KEYWORDS: ReadonlySet<string> = new Set([
  "$schema", "$id", "$ref", "$anchor", "$dynamicRef", "$dynamicAnchor", "$comment", "$vocabulary",
  "type", "title", "description", "default", "examples", "enum", "const", "format", "pattern",
  "required", "items", "prefixItems", "additionalItems", "additionalProperties", "contains",
  "minContains", "maxContains", "propertyNames", "unevaluatedItems", "unevaluatedProperties",
  "anyOf", "oneOf", "allOf", "not", "if", "then", "else", "minimum", "maximum",
  "exclusiveMinimum", "exclusiveMaximum", "multipleOf", "minLength", "maxLength", "minItems",
  "maxItems", "uniqueItems", "minProperties", "maxProperties", "dependentRequired",
  "contentEncoding", "contentMediaType", "contentSchema", "readOnly", "writeOnly", "deprecated",
  "nullable", ...NAMED_SUBSCHEMA_KEYS,
]);
const MAX_SCHEMA_DEPTH = 32;

type JsonObject = Record<string, unknown>;

function isObject(value: unknown): value is JsonObject {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function own(obj: JsonObject, key: string): unknown {
  return Object.prototype.hasOwnProperty.call(obj, key) ? obj[key] : undefined;
}

/**
 * Every model-visible string in a JSON schema as `[path, text]` pairs.
 *
 * Walks *every* string value (descriptions, titles, defaults, enums, examples,
 * `required` entries, even `type`), every non-keyword key, and every property /
 * definition name, at any depth and through any composition keyword — the
 * "Full-Schema Poisoning" surface. Paths read like `q.title` /
 * `opts.mode.enum` / `q.<name>` (a property name) / `q.x-note#key`.
 */
export function schemaTextFields(schema: unknown, prefix = ""): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  walkSchema(schema, prefix, out, 0);
  return out;
}

function walkSchema(node: unknown, path: string, out: Array<[string, string]>, depth: number): void {
  if (depth > MAX_SCHEMA_DEPTH) return;
  if (typeof node === "string") {
    if (node) out.push([path, node]);
  } else if (Array.isArray(node)) {
    // str/int/float scalars, never bools (Python: isinstance(v, (str, int, float)) and not bool)
    const scalars = node
      .filter((v) => typeof v === "string" || typeof v === "number")
      .map((v) => pyStr(v));
    if (scalars.some((v) => v)) out.push([path, scalars.join(" | ")]);
    node.forEach((item, index) => {
      if (item && typeof item === "object") walkSchema(item, `${path}[${index}]`, out, depth + 1);
    });
  } else if (isObject(node)) {
    for (const [key, value] of orderedEntries(node)) {
      const child = path ? `${path}.${key}` : key;
      if (NAMED_SUBSCHEMA_KEYS.has(key) && isObject(value)) {
        for (const [name, sub] of orderedEntries(value)) {
          const named = path ? `${path}.${name}` : name;
          out.push([`${named}.<name>`, name]);
          walkSchema(sub, named, out, depth + 1);
        }
        continue;
      }
      if (!SCHEMA_KEYWORDS.has(key)) out.push([`${child}#key`, key]);
      walkSchema(value, child, out, depth + 1);
    }
  }
}

/**
 * Every model-visible text field of a tool as `[field label, text]`: the
 * description, title, annotation title, and every string anywhere in the input
 * and output schemas (labels `param:q`, `param:q.title`, `param:q#name`,
 * `inputSchema.T.description`, `outputSchema.r.description`, ...).
 */
export function toolTextFields(tool: MCPTool): Array<[string, string]> {
  const fields: Array<[string, string]> = [["description", tool.description]];
  if (tool.title) fields.push(["title", tool.title]);
  const annTitle = own(tool.annotations, "title");
  if (typeof annTitle === "string" && annTitle) fields.push(["annotations.title", annTitle]);
  // Walk `properties` as a map so paths start at the parameter name.
  for (const [path, text] of schemaTextFields({ properties: own(tool.inputSchema, "properties") })) {
    if (path.endsWith(".<name>")) fields.push([`param:${removeSuffix(path, ".<name>")}#name`, text]);
    else fields.push([`param:${removeSuffix(path, ".description")}`, text]);
  }
  const rest = orderedMap(orderedEntries(tool.inputSchema).filter(([k]) => k !== "properties"));
  for (const [p, t] of schemaTextFields(rest)) fields.push([`inputSchema.${p}`, t]);
  for (const [p, t] of schemaTextFields(tool.outputSchema)) fields.push([`outputSchema.${p}`, t]);
  return fields.filter(([, text]) => text);
}

export function promptTextFields(prompt: MCPPrompt): Array<[string, string]> {
  const fields: Array<[string, string]> = [["description", prompt.description]];
  for (const [name, desc] of orderedEntries(prompt.arguments)) fields.push([`arg:${name}`, desc]);
  return fields.filter(([, text]) => text);
}

/**
 * Every model-visible string of a manifest as `[owner, field, text]` — `owner`
 * is the tool / prompt / resource the text belongs to (`null` for server
 * instructions). The attack surface TP01/TP02/TP03 scan.
 */
export function manifestTextFields(m: MCPManifest): Array<[string | null, string, string]> {
  const out: Array<[string | null, string, string]> = [];
  if (m.instructions) out.push([null, "instructions", m.instructions]);
  for (const tool of m.tools) {
    for (const [label, text] of toolTextFields(tool)) out.push([tool.name, label, text]);
  }
  for (const prompt of m.prompts) {
    for (const [label, text] of promptTextFields(prompt)) out.push([prompt.name, label, text]);
  }
  for (const r of m.resources) {
    if (r.description) out.push([r.name || r.uri, "description", r.description]);
  }
  return out;
}

/** Parameter descriptions pulled from a tool's JSON input schema. */
export function parameterDescriptions(tool: MCPTool): Record<string, string> {
  const props = own(tool.inputSchema, "properties");
  if (!isObject(props)) return {};
  const out: Record<string, string> = {};
  for (const [name, schema] of orderedEntries(props)) {
    if (isObject(schema)) {
      const desc = own(schema, "description");
      if (typeof desc === "string") out[name] = desc;
    }
  }
  return out;
}

/** The full command line as a single string (for pattern matching). */
export function commandLine(spec: Pick<MCPServerSpec, "command" | "args">): string {
  const parts = spec.command ? [spec.command, ...spec.args] : [...spec.args];
  return parts.filter(Boolean).join(" ");
}
