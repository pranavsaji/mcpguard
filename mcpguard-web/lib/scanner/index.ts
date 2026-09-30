export * from "./types";
export { ConfigError, parseConfigText, parseConfig, parseManifest } from "./configParser";
export { RULES, type Rule, type RuleContext } from "./rules";
export { scanConfigText, scanSpec, scanSpecs, ENGINE_VERSION } from "./scan";

/** Catalog of rules surfaced in the web engine, for UI documentation. */
export const RULE_CATALOG = [
  { id: "TP01", name: "Tool poisoning", category: "tool_poisoning", maps: "OWASP LLM01" },
  { id: "TP02", name: "Hidden content", category: "hidden_content", maps: "OWASP LLM01" },
  { id: "TP03", name: "Tool shadowing / spoofing", category: "tool_shadowing", maps: "OWASP LLM01" },
  { id: "FLOW01", name: "Toxic flow (lethal trifecta)", category: "toxic_flow", maps: "OWASP LLM01 / Agentic" },
  { id: "CAP01", name: "Excessive agency", category: "excessive_agency", maps: "OWASP Agentic" },
  { id: "SEC01", name: "Plaintext secrets", category: "secrets", maps: "CWE-798" },
  { id: "SUP01", name: "Unpinned / remote launch", category: "supply_chain", maps: "MCP supply-chain" },
  { id: "SUP02", name: "Vulnerable / malicious package", category: "vulnerable_component", maps: "CWE-1395" },
  { id: "CFG01", name: "Dangerous launch config", category: "insecure_config", maps: "CWE-250" },
  { id: "NET01", name: "Insecure transport", category: "insecure_transport", maps: "CWE-319" },
] as const;
