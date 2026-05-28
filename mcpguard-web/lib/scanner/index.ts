export * from "./types";
export { ConfigError, parseConfigText, parseConfig, parseManifest } from "./configParser";
export { RULES } from "./rules";
export { scanConfigText, scanSpec, scanSpecs, ENGINE_VERSION } from "./scan";

/** Catalog of rules surfaced in the web engine, for UI documentation. */
export const RULE_CATALOG = [
  { id: "TP01", name: "Tool poisoning", category: "tool_poisoning", maps: "OWASP LLM01" },
  { id: "TP02", name: "Hidden content", category: "hidden_content", maps: "OWASP LLM01" },
  { id: "CAP01", name: "Excessive agency", category: "excessive_agency", maps: "OWASP Agentic" },
  { id: "SEC01", name: "Secrets in env", category: "secrets", maps: "CWE-798" },
  { id: "SUP01", name: "Unpinned / remote launch", category: "supply_chain", maps: "MCP supply-chain" },
] as const;
