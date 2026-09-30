/**
 * Detection rules (TypeScript port). Each rule is a pure function
 * `(spec, ctx) => Finding[]` mirroring one Python rule module; `ctx.peers`
 * carries every server in the config for the cross-server rules (TP03, FLOW01).
 *
 * Browser-runnable: CACHE01, CAP01, CFG01, FLOW01, HDR01, NET01, SEC01, SUP01,
 * SUP02, SUP03, TP01, TP02, TP03. Source-scan (CMD01), live/baseline drift (MAN01, MAN02), and
 * SUP02's installed-package.json lookup need a filesystem or a live connection
 * and stay in the CLI.
 */

import { canonicalPackage, findAdvisories, versionMatches, type Advisory } from "./advisories";
import {
  containsPhrase,
  decodeBase64Payloads,
  exfilMatches,
  findHiddenContent,
  injectionMatches,
  keywordPhrases,
  matchesEvidence,
  mixedScripts,
  normalizeWord,
  preferenceMatches,
  shadowingMatches,
  suspiciousParameterName,
  truncate,
  words,
} from "./detectors";
import { commandBasename, parseLaunch, type PackageLaunch } from "./launchers";
import {
  ALL_INTERFACES_RE,
  API_BASE_URL_ENV,
  AUTH_HEADER_NAME_RE,
  BRAND_PUBLISHERS,
  CAPABILITY_KEYWORDS,
  CODE_INJECTION_ENV,
  CODE_LOADING_OPTION_ENV,
  CONTAINER_RUNTIMES,
  CONTAINER_VALUE_FLAGS,
  DANGEROUS_CAPS,
  DANGEROUS_NAME_TOKENS,
  DOCKER_SOCKET_RE,
  DOWNLOADER_RE,
  EXTERNAL_SINK_KEYWORDS,
  HEADER_PARAM_TYPES,
  HOME_PATH_RE,
  HOST_FLAGS,
  HTTP_TOKEN_RE,
  IOC_SUBSTRINGS,
  KNOWN_SERVER_ROLES,
  LONG_CACHE_TTL_MS,
  LOOPBACK_HOST_RE,
  PRIVATE_DATA_KEYWORDS,
  PRIVILEGE_ESCALATION_COMMANDS,
  REGISTRY_OVERRIDE_ENV,
  REGISTRY_OVERRIDE_FLAGS,
  REMOTE_FETCH_RE,
  ROOT_PATH_RE,
  SECRET_FLAG_RE,
  SECRET_NAME_RE,
  SECRET_VALUE_PATTERNS,
  TLS_DISABLE_ENV,
  TOOL_NAME_RE,
  TRUSTED_SCOPES,
  UNTRUSTED_INPUT_KEYWORDS,
  URL_SCRIPT_RUNNERS,
  URL_SECRET_PARAM_RE,
  URL_USERINFO_RE,
  WELL_KNOWN_PACKAGES,
  looksLikePlaceholder,
} from "./patterns";
import {
  codePoints,
  orderedEntries,
  pyRe,
  pyRepr,
  pyReprValue,
  pySorted,
  pyStr,
  pyStrip,
  pyUnicodeEscape,
  reEscape,
  removeSuffix,
  urlparse,
  PyValueError,
  type ParsedUrl,
} from "./pycompat";
import {
  type Category,
  type Finding,
  type FindingLocation,
  type MCPManifest,
  type MCPServerSpec,
  type MCPTool,
  type Severity,
  commandLine,
  manifestTextFields,
} from "./types";

/** Every server in the scanned config with its effective manifest, in config order. */
export interface RuleContext {
  peers: Array<[MCPServerSpec, MCPManifest | null]>;
  /**
   * Toxic-flow roles an AI judge inferred per tool (server-side `--ai` only),
   * keyed by `aiRoleKey(server, tool)`. Unioned with the name-based roles.
   */
  aiRoles?: Map<string, Set<string>>;
}

/** Map key for `RuleContext.aiRoles`. */
export function aiRoleKey(server: string, tool: string): string {
  return JSON.stringify([server, tool]);
}

/** A detector. Without `ctx` a rule sees no peers (Python's `AnalysisContext()`). */
export type Rule = (spec: MCPServerSpec, ctx?: RuleContext) => Finding[];

// --- helpers -----------------------------------------------------------------

interface RuleMeta {
  rule_id: string;
  title: string;
  category: Category;
  severity: Severity;
  mappings: string[];
}

interface FindingInput {
  location: FindingLocation;
  evidence: string;
  remediation: string;
  severity?: Severity;
  title?: string;
  confidence?: number;
}

/** Python `Rule.finding(...)`: a finding carrying the rule's identity. */
function finding(meta: RuleMeta, f: FindingInput): Finding {
  return {
    rule_id: meta.rule_id,
    title: f.title ?? meta.title,
    severity: f.severity ?? meta.severity,
    category: meta.category,
    location: f.location,
    evidence: f.evidence,
    remediation: f.remediation,
    mappings: [...meta.mappings],
    confidence: f.confidence ?? 1.0,
  };
}

/** Python `Location(...).to_dict()`: only the fields that are set. */
function loc(server: string, tool?: string | null, field?: string | null): FindingLocation {
  const out: FindingLocation = { server };
  if (tool !== undefined && tool !== null) out.tool = tool;
  if (field !== undefined && field !== null) out.field = field;
  return out;
}

/** Own-property lookup in a constant table (never the Object prototype). */
function lookup<T>(table: Record<string, T>, key: string): T | undefined {
  return Object.prototype.hasOwnProperty.call(table, key) ? table[key] : undefined;
}

/** Python `str.partition(sep)`. */
function partition(text: string, sep: string): [string, string, string] {
  const at = text.indexOf(sep);
  return at < 0 ? [text, "", ""] : [text.slice(0, at), sep, text.slice(at + sep.length)];
}

/** `(flag, value)` for every `--flag value` / `--flag=value` in `args`. */
function flagValues(args: string[], flags: ReadonlySet<string>): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  args.forEach((arg, i) => {
    const [flag, eq, inline] = partition(arg, "=");
    if (!flags.has(flag)) return;
    if (eq) out.push([flag, inline]);
    else if (i + 1 < args.length) out.push([flag, args[i + 1]]);
  });
  return out;
}

const startsWithHttp = (text: string) => text.startsWith("http://") || text.startsWith("https://");

// --- TP01: tool poisoning ----------------------------------------------------

const TP01: RuleMeta = {
  rule_id: "TP01",
  title: "Prompt injection in tool metadata",
  category: "tool_poisoning",
  severity: "high",
  mappings: ["OWASP-LLM01", "MCP-TOOL-POISONING", "OWASP-ASI01"],
};

export const toolPoisoning: Rule = (spec) => {
  const manifest = spec.manifest;
  if (!manifest) return [];
  const out: Finding[] = [];
  for (const [owner, field, text] of manifestTextFields(manifest)) {
    if (!text) continue;
    const location = loc(spec.name, owner, field);
    const injections = injectionMatches(text);
    if (injections.length) {
      out.push(
        finding(TP01, {
          location,
          evidence: matchesEvidence(injections),
          remediation:
            "Remove instruction-like content from this field. Tool/parameter descriptions should describe behavior, never direct the model.",
          severity: "high",
        }),
      );
    }
    const exfils = exfilMatches(text);
    if (exfils.length) {
      out.push(
        finding(TP01, {
          title: "Possible data-exfiltration directive in tool metadata",
          location,
          evidence: matchesEvidence(exfils),
          remediation:
            "This field appears to instruct the model to send data to an external destination or read sensitive files. Treat the server as untrusted and review its source.",
          severity: "critical",
        }),
      );
    }
    const lure = field.endsWith("#name") ? suspiciousParameterName(text) : null;
    if (lure !== null) {
      const [kind, token] = lure;
      out.push(
        finding(TP01, {
          title:
            kind === "sensitive"
              ? "Parameter name solicits sensitive data"
              : "Parameter name opens a covert side channel",
          location,
          evidence: `parameter ${pyRepr(text)} (token: ${token})`,
          remediation:
            "A parameter's name is read by the model as an instruction of what to fill in. Names asking for keys or files, or 'sidenote'-style catch-alls, are a known tool-poisoning channel. Treat the server as untrusted.",
          severity: kind === "sensitive" ? "high" : "medium",
          confidence: 0.7,
        }),
      );
    }
    const encoded = decodeBase64Payloads(text);
    if (encoded.length) {
      out.push(
        finding(TP01, {
          title: "Encoded (base64) instructions hidden in tool metadata",
          location,
          evidence: matchesEvidence(encoded.map((d) => `decodes to: ${d}`)),
          remediation:
            "This field carries base64 that decodes to model-directed instructions \u2014 an encoding used to slip past reviewers and filters. Treat the server as malicious.",
          severity: "critical",
        }),
      );
    }
  }
  return out;
};

// --- TP02: hidden content ----------------------------------------------------

const TP02: RuleMeta = {
  rule_id: "TP02",
  title: "Hidden or invisible content in tool metadata",
  category: "hidden_content",
  severity: "high",
  mappings: ["OWASP-LLM01", "MCP-TOOL-POISONING", "OWASP-ASI01"],
};

export const hiddenContent: Rule = (spec) => {
  const manifest = spec.manifest;
  if (!manifest) return [];
  const out: Finding[] = [];
  // Tool names are model-visible too (and shown to users): scanned after the text fields.
  const fields: Array<[string | null, string, string]> = [
    ...manifestTextFields(manifest),
    ...manifest.tools.map((t) => [t.name, "name", t.name] as [string, string, string]),
  ];
  for (const [owner, field, text] of fields) {
    if (!text) continue;
    const location = loc(spec.name, owner, field);
    const hidden = findHiddenContent(text);

    if (hidden.invisibles.length) {
      let evidence = `invisible characters present: ${hidden.invisibles.join(", ")}`;
      let severity: Severity = "high";
      if (hidden.tagText) {
        evidence += `; hidden text decodes to: ${pyRepr(truncate(hidden.tagText, 120))}`;
        if (injectionMatches(hidden.tagText).length || exfilMatches(hidden.tagText).length) {
          severity = "critical";
        }
      }
      out.push(
        finding(TP02, {
          location,
          evidence,
          remediation:
            "Strip zero-width / BiDi / tag characters from this field. Their only plausible purpose in metadata is to hide instructions from human reviewers.",
          severity,
        }),
      );
    }
    if (hidden.variationSelectors) {
      out.push(
        finding(TP02, {
          title: "Variation-selector smuggling in tool metadata",
          location,
          evidence: `${hidden.variationSelectors} suspicious variation selectors (invisible byte encoding)`,
          remediation:
            "Runs of Unicode variation selectors can encode arbitrary hidden data. Strip them and treat the server as untrusted.",
        }),
      );
    }
    if (hidden.ansi.length) {
      out.push(
        finding(TP02, {
          title: "Terminal escape sequences in tool metadata",
          location,
          evidence: matchesEvidence(hidden.ansi),
          remediation:
            "ANSI / control sequences can hide or rewrite text shown to the user in terminal clients while the model still reads it. Remove them.",
        }),
      );
    }
    if (hidden.htmlComments.length) {
      out.push(
        finding(TP02, {
          title: "HTML comment hidden in tool metadata",
          location,
          evidence: matchesEvidence(hidden.htmlComments),
          remediation: "Remove HTML comments; they are invisible in many UIs but read by the model.",
          severity: "medium",
        }),
      );
    }
    if (hidden.padding) {
      out.push(
        finding(TP02, {
          title: "Whitespace padding hides trailing content in tool metadata",
          location,
          evidence: truncate(codePoints(text).slice(-120).join("")),
          remediation:
            "Long blank runs push text below the fold of approval dialogs. Remove the padding and review the text after it.",
          severity: "medium",
        }),
      );
    }
  }
  return out;
};

// --- TP03: tool shadowing / collisions / spoofing ----------------------------

const TP03: RuleMeta = {
  rule_id: "TP03",
  title: "Tool shadowing: metadata steers another server's tools",
  category: "tool_shadowing",
  severity: "high",
  mappings: ["OWASP-LLM01", "MCP-TOOL-SHADOWING", "OWASP-ASI01"],
};

// A tool name is only "distinctive" enough to count as a reference when it can't
// plausibly be an ordinary word: it has a separator or an inner capital, and length.
const DISTINCTIVE_RE = pyRe(String.raw`^(?=.{5,})(?:.*[_\-.].*|.*[a-z][A-Z].*)$`);

// The tool a "when using X" / "instead of calling X" directive names.
const TARGET_RE = pyRe(String.raw`(?:using|calling|invoking)\s+(?:the\s+)?[${"`"}'\"]?([\w.-]+)`, "i");

function mentionPattern(name: string): RegExp {
  return pyRe(String.raw`(?<![\w-])` + reEscape(name) + String.raw`(?![\w-])`);
}

export const toolShadowing: Rule = (spec, ctx = { peers: [] }) => {
  const manifest = spec.manifest;
  if (!manifest) return [];
  const out: Finding[] = [];
  const own = new Set(manifest.tools.map((t) => t.name));

  // Distinctive tool names served by *other* servers: tool -> server.
  const foreign = new Map<string, string>();
  for (const [peer, peerManifest] of ctx.peers) {
    if (peer.name === spec.name || peerManifest === null) continue;
    for (const tool of peerManifest.tools) {
      if (!own.has(tool.name) && DISTINCTIVE_RE.test(tool.name) && !foreign.has(tool.name)) {
        foreign.set(tool.name, peer.name);
      }
    }
  }
  const mentions = [...foreign].map(([name, server]) => ({ name, server, re: mentionPattern(name) }));

  for (const [owner, field, text] of manifestTextFields(manifest)) {
    const location = loc(spec.name, owner, field);
    const referenced = pySorted(
      mentions.filter((m) => m.re.test(text)).map((m) => `${m.name} (${m.server})`),
    );
    if (referenced.length) {
      out.push(
        finding(TP03, {
          title: "Tool metadata references another server's tool",
          location,
          evidence: `mentions: ${referenced.join(", ")}`,
          remediation:
            "A server's metadata should never mention another server's tools. This is the tool-shadowing pattern; disable the server and review it.",
          confidence: 0.8,
        }),
      );
    }
    const directives = shadowingMatches(text).filter((d) => {
      const target = TARGET_RE.exec(d);
      return !(target && own.has(target[1])); // directives about this server's own tools are fine
    });
    if (directives.length) {
      out.push(
        finding(TP03, {
          location,
          evidence: matchesEvidence(directives),
          remediation:
            "This text instructs the model how to use other tools or where to redirect data. Treat the server as malicious.",
        }),
      );
    }
    const preference = preferenceMatches(text);
    if (preference.length) {
      out.push(
        finding(TP03, {
          title: "Tool metadata manipulates tool selection",
          location,
          evidence: matchesEvidence(preference),
          remediation:
            "Descriptions should state what a tool does, not rank it against others. Remove the preference language.",
          severity: "medium",
          confidence: 0.7,
        }),
      );
    }
  }

  // Collisions: the same tool name served by another server.
  for (const tool of manifest.tools) {
    const others = pySorted(
      ctx.peers
        .filter(
          ([peer, peerManifest]) =>
            peer.name !== spec.name &&
            peerManifest !== null &&
            peerManifest.tools.some((t) => t.name === tool.name),
        )
        .map(([peer]) => peer.name),
    );
    if (others.length) {
      out.push(
        finding(TP03, {
          title: "Tool name collides with another server's tool",
          location: loc(spec.name, tool.name),
          evidence: `${pyRepr(tool.name)} is also served by: ${others.join(", ")}`,
          remediation:
            "Two servers exposing the same tool name lets one hijack calls meant for the other. Remove one, or use a client that namespaces tools.",
          severity: "medium",
        }),
      );
    }
  }

  // Spoofed names: mixed scripts (homoglyphs) or characters outside the MCP set.
  for (const tool of manifest.tools) {
    const scripts = mixedScripts(tool.name);
    if (scripts.length) {
      out.push(
        finding(TP03, {
          title: "Tool name mixes Unicode scripts (homoglyph spoofing)",
          location: loc(spec.name, tool.name),
          evidence: `${pyRepr(tool.name)} mixes ${scripts.join(", ")} characters`,
          remediation:
            "Look-alike characters let a tool impersonate a trusted one. Treat the server as malicious.",
        }),
      );
    } else if (!TOOL_NAME_RE.test(tool.name)) {
      out.push(
        finding(TP03, {
          title: "Tool name outside the MCP-recommended character set",
          location: loc(spec.name, tool.name),
          evidence: `${pyRepr(tool.name)} (${pyUnicodeEscape(tool.name)})`,
          remediation:
            "MCP recommends tool names of 1-128 characters from [A-Za-z0-9_.-]. Other characters are a spoofing and confusion risk.",
          severity: "medium",
        }),
      );
    }
  }
  return out;
};

// --- CAP01: excessive agency -------------------------------------------------

const CAP01: RuleMeta = {
  rule_id: "CAP01",
  title: "Tool exposes a dangerous capability",
  category: "excessive_agency",
  severity: "medium",
  mappings: ["OWASP-AGENTIC-EXCESSIVE-AGENCY", "OWASP-ASI02", "OWASP-ASI03"],
};

const MUTATING_CAPABILITIES = new Set(["code execution", "shell / command", "filesystem write", "database"]);
const DESTRUCTIVE_NAME_TOKENS = new Set([
  "delete", "remove", "drop", "write", "exec", "execute", "run", "update", "create", "kill", "send",
]);

const KEYWORD_PHRASES: Array<[string, string[][]]> = Object.entries(CAPABILITY_KEYWORDS).map(
  ([capability, keywords]) => [capability, keywordPhrases(keywords)],
);

export const excessiveAgency: Rule = (spec) => {
  const manifest = spec.manifest;
  if (!manifest) return [];
  const out: Finding[] = [];
  for (const tool of manifest.tools) {
    // Name and description are matched separately so a phrase can't straddle them.
    const fields = [words(tool.name).map(normalizeWord), words(tool.description).map(normalizeWord)];
    const location = loc(spec.name, tool.name);
    const matched = KEYWORD_PHRASES.filter(([, phrases]) =>
      fields.some((f) => phrases.some((p) => containsPhrase(f, p))),
    ).map(([capability]) => capability);
    const nameTokens = new Set(words(tool.name));

    if (matched.length) {
      // A dangerous verb in the *name* itself is a stronger signal.
      const dangerous = [...nameTokens].some((t) => DANGEROUS_NAME_TOKENS.has(t));
      out.push(
        finding(CAP01, {
          location,
          evidence: `capabilities inferred: ${pySorted(matched).join(", ")}`,
          remediation:
            "Confirm this tool needs this power. Apply least privilege: scope filesystem/network access, sandbox execution, and require human approval for high-impact actions.",
          severity: dangerous ? "high" : "medium",
          confidence: 0.7,
        }),
      );
    }

    // Clients may auto-approve tools that claim to be read-only; a tool that
    // says so while wielding write/exec power is lying to the approval gate.
    const mutating = pySorted(matched.filter((c) => MUTATING_CAPABILITIES.has(c)));
    const destructiveName = pySorted([...nameTokens].filter((t) => DESTRUCTIVE_NAME_TOKENS.has(t)));
    const annotations = tool.annotations;
    if (
      Object.keys(annotations).length > 0 &&
      Object.prototype.hasOwnProperty.call(annotations, "readOnlyHint") &&
      annotations.readOnlyHint === true &&
      (mutating.length || destructiveName.length)
    ) {
      out.push(
        finding(CAP01, {
          title: "Tool annotations understate its capability (readOnlyHint)",
          location: loc(spec.name, tool.name, "annotations"),
          evidence:
            "readOnlyHint=true but " +
            (mutating.length
              ? `capabilities inferred: ${mutating.join(", ")}`
              : `name implies mutation: ${destructiveName.join(", ")}`),
          remediation:
            "Annotations are self-reported and untrusted. Never auto-approve based on them; require confirmation for this tool and report the mismatch upstream.",
          severity: "high",
          confidence: 0.7,
        }),
      );
    }
  }
  return out;
};

// --- FLOW01: toxic flow / lethal trifecta ------------------------------------

const FLOW01: RuleMeta = {
  rule_id: "FLOW01",
  title: "Lethal trifecta: untrusted input + private data + exfiltration path",
  category: "toxic_flow",
  severity: "high",
  mappings: ["OWASP-LLM01", "MCP-TOXIC-FLOW", "OWASP-AGENTIC-EXCESSIVE-AGENCY", "OWASP-ASI01", "OWASP-ASI02"],
};

const UNTRUSTED = "untrusted";
const PRIVATE = "private";
const SINK = "sink";
const EXEC = "exec";

const ROLE_PHRASES: Array<[string, string[][]]> = [
  [UNTRUSTED, keywordPhrases(UNTRUSTED_INPUT_KEYWORDS)],
  [PRIVATE, keywordPhrases(PRIVATE_DATA_KEYWORDS)],
  [SINK, keywordPhrases(EXTERNAL_SINK_KEYWORDS)],
  [
    EXEC,
    keywordPhrases([...CAPABILITY_KEYWORDS["code execution"], ...CAPABILITY_KEYWORDS["shell / command"]]),
  ],
];

/** Roles inferred from a tool's *name* (descriptions are too noisy for this). */
export function toolRoles(tool: MCPTool): Set<string> {
  const nameWords = words(tool.name).map(normalizeWord);
  const roles = new Set(
    ROLE_PHRASES.filter(([, phrases]) => phrases.some((p) => containsPhrase(nameWords, p))).map(
      ([role]) => role,
    ),
  );
  // openWorldHint=true means the tool touches the outside world by its own account.
  if (tool.annotations.openWorldHint === true && (roles.has(PRIVATE) || roles.has(SINK))) {
    roles.add(SINK);
  }
  return roles;
}

function knownPackage(spec: MCPServerSpec): string | null {
  const launch = parseLaunch(spec.command, spec.args);
  if (launch !== null) return launch.name;
  if (spec.command && CONTAINER_RUNTIMES.has(commandBasename(spec.command))) {
    const image = containerImage(spec.args);
    if (image) return image.includes("/") ? rsplitFirst(partition(image, "@")[0], ":") : image;
  }
  return null;
}

/** Python `text.rsplit(sep, 1)[0]`. */
function rsplitFirst(text: string, sep: string): string {
  const at = text.lastIndexOf(sep);
  return at < 0 ? text : text.slice(0, at);
}

class Flow {
  // role -> [server name, label, inferred from package name?]
  readonly tools = new Map<string, Array<[string, string, boolean]>>();

  add(role: string, server: string, label: string, inferred: boolean): void {
    const list = this.tools.get(role) ?? [];
    list.push([server, label, inferred]);
    this.tools.set(role, list);
  }

  labels(role: string, server: string | null = null): string[] {
    return (this.tools.get(role) ?? [])
      .filter(([srv]) => server === null || server === srv)
      .map(([, label]) => label);
  }

  has(role: string, manifestOnly = false): boolean {
    return (this.tools.get(role) ?? []).some(([, , inferred]) => !inferred || !manifestOnly);
  }
}

function serverRoles(
  spec: MCPServerSpec,
  manifest: MCPManifest | null,
  flow: Flow,
  aiRoles?: Map<string, Set<string>>,
): Set<string> {
  const roles = new Set<string>();
  if (manifest !== null && manifest.tools.length) {
    for (const tool of manifest.tools) {
      const inferred = new Set([...toolRoles(tool), ...(aiRoles?.get(aiRoleKey(spec.name, tool.name)) ?? [])]);
      for (const role of inferred) {
        roles.add(role);
        flow.add(role, spec.name, `${spec.name}/${tool.name}`, false);
      }
    }
    return roles;
  }
  const pkg = knownPackage(spec);
  const known = pkg ? lookup(KNOWN_SERVER_ROLES, pkg) : undefined;
  if (pkg && known) {
    for (const role of known) {
      roles.add(role);
      flow.add(role, spec.name, `${spec.name} (${pkg})`, true);
    }
  }
  return roles;
}

function summarize(labels: string[]): string {
  return labels.slice(0, 4).join(", ") + (labels.length > 4 ? ` (+${labels.length - 4} more)` : "");
}

export const toxicFlow: Rule = (spec, ctx = { peers: [] }) => {
  const peers = ctx.peers.length ? ctx.peers : [[spec, spec.manifest] as [MCPServerSpec, MCPManifest | null]];
  const flow = new Flow();
  const perServer = new Map<string, Set<string>>();
  for (const [peer, manifest] of peers) {
    perServer.set(peer.name, serverRoles(peer, manifest, flow, ctx.aiRoles));
  }
  if (!perServer.get(spec.name)?.has(UNTRUSTED)) return []; // report only where attacker text enters

  const out: Finding[] = [];
  const entry = summarize(flow.labels(UNTRUSTED, spec.name));
  const location = loc(spec.name);

  if (flow.has(PRIVATE) && flow.has(SINK)) {
    // Full confidence only when every leg is backed by a real manifest.
    const observed = [UNTRUSTED, PRIVATE, SINK].every((r) => flow.has(r, true));
    out.push(
      finding(FLOW01, {
        location,
        evidence: truncate(
          `untrusted input: ${entry}; private data: ${summarize(flow.labels(PRIVATE))}; ` +
            `exfiltration: ${summarize(flow.labels(SINK))}`,
          400,
        ),
        remediation:
          "Injected text read by one tool can drive the others to leak private data. Split these servers across separate agent sessions, remove one leg of the trifecta, or require human approval for every sink call.",
        severity: observed ? "high" : "medium",
        confidence: observed ? 0.6 : 0.4,
      }),
    );
  }
  if (flow.has(EXEC)) {
    const observed = flow.has(UNTRUSTED, true) && flow.has(EXEC, true);
    out.push(
      finding(FLOW01, {
        title: "Untrusted input can reach code execution",
        location,
        evidence: truncate(`untrusted input: ${entry}; code execution: ${summarize(flow.labels(EXEC))}`, 400),
        remediation:
          "Text an attacker controls can become a command. Sandbox the execution tool and require human approval for it, or remove the untrusted-input tool.",
        severity: observed ? "high" : "medium",
        confidence: observed ? 0.6 : 0.4,
      }),
    );
  }
  return out;
};

// --- SEC01: plaintext secrets ------------------------------------------------

const SEC01: RuleMeta = {
  rule_id: "SEC01",
  title: "Plaintext secret in server config env",
  category: "secrets",
  severity: "high",
  mappings: ["CWE-798", "MCP-SECRETS", "OWASP-ASI03"],
};

/** Show only enough of a secret to identify it, never the whole thing. */
function redact(value: string): string {
  const chars = codePoints(value);
  if (chars.length <= 8) return chars.length ? chars[0] + "***" : "***";
  return `${chars.slice(0, 4).join("")}\u2026${chars.slice(-2).join("")} (${chars.length} chars)`;
}

/** The vendor whose key format `value` contains, if any. */
function vendorOf(value: string): string | null {
  for (const [vendor, pattern] of SECRET_VALUE_PATTERNS) if (pattern.test(value)) return vendor;
  return null;
}

/** A placeholder, `${VAR}` reference, or a header template like `Bearer ${TOKEN}`. */
function isReference(value: string): boolean {
  const stripped = pyStrip(value);
  if (looksLikePlaceholder(stripped)) return true;
  const [scheme, , rest] = partition(stripped, " ");
  return !!rest && ["bearer", "basic", "token"].includes(scheme.toLowerCase()) && looksLikePlaceholder(rest);
}

function vendorFinding(location: FindingLocation, vendor: string, evidence: string, name: string): Finding {
  return finding(SEC01, {
    title: `Hardcoded ${vendor} in config`,
    location,
    evidence,
    remediation: `Move the secret out of the config. Reference it via an environment variable (e.g. "\${${name}}") and inject at runtime from a secret manager.`,
    severity: "critical",
  });
}

function urlSecrets(spec: MCPServerSpec, field: string, url: string): Finding[] {
  const out: Finding[] = [];
  const checks: Array<[RegExp, string]> = [
    [URL_USERINFO_RE, "password in URL"],
    [URL_SECRET_PARAM_RE, "secret in URL query"],
  ];
  for (const [pattern, what] of checks) {
    const match = pattern.exec(url);
    if (match && !isReference(match[1])) {
      out.push(
        finding(SEC01, {
          title: `Credential embedded in server URL (${what})`,
          location: loc(spec.name, null, field),
          evidence: redact(match[1]),
          remediation:
            "URLs are logged by proxies, shells, and clients. Send the credential in an Authorization header sourced from the environment instead.",
          severity: vendorOf(match[1]) ? "critical" : "high",
        }),
      );
    }
  }
  return out;
}

export const secrets: Rule = (spec) => {
  const out: Finding[] = [];

  for (const [key, value] of orderedEntries(spec.env)) {
    if (!value || looksLikePlaceholder(value)) continue;
    const location = loc(spec.name, null, `env:${key}`);
    // 1) Value matches a known vendor format -> high confidence regardless of name.
    const vendor = vendorOf(value);
    if (vendor) {
      out.push(vendorFinding(location, vendor, `${key}=${redact(value)}`, key));
      continue;
    }
    // 2) Name implies a secret and value looks real -> medium/high confidence.
    if (SECRET_NAME_RE.test(key)) {
      out.push(
        finding(SEC01, {
          location,
          evidence: `${key}=${redact(value)}`,
          remediation: `This env var name implies a credential. Do not store its value in the config; reference "\${${key}}" and inject from a secret manager.`,
          confidence: 0.6,
        }),
      );
    }
  }

  for (const [name, value] of orderedEntries(spec.headers)) {
    if (!value || isReference(value)) continue;
    const location = loc(spec.name, null, `header:${name}`);
    const vendor = vendorOf(value);
    if (vendor) {
      out.push(vendorFinding(location, vendor, `${name}: ${redact(value)}`, name));
    } else if (AUTH_HEADER_NAME_RE.test(name) || SECRET_NAME_RE.test(name)) {
      out.push(
        finding(SEC01, {
          title: "Plaintext credential in server config header",
          location,
          evidence: `${name}: ${redact(value)}`,
          remediation:
            'Don\'t hardcode auth headers. Use "Bearer ${TOKEN}" with the token injected from the environment or a secret manager, or use OAuth.',
          confidence: 0.8,
        }),
      );
    }
  }

  const args = spec.args;
  args.forEach((arg, i) => {
    const location = loc(spec.name, null, "args");
    const flag = SECRET_FLAG_RE.exec(arg);
    let value: string | null = null;
    if (flag) value = flag[1] !== undefined ? flag[1] : i + 1 < args.length ? args[i + 1] : null;
    const vendor = vendorOf(arg);
    if (vendor) {
      out.push(vendorFinding(location, vendor, redact(arg), "SECRET"));
    } else if (value && !value.startsWith("-") && !isReference(value)) {
      out.push(
        finding(SEC01, {
          title: "Plaintext secret passed as a launch argument",
          location,
          evidence: `${partition(arg, "=")[0]} ${redact(value)}`,
          remediation:
            "Arguments are visible to every local user via the process list and land in logs. Pass the secret through an env var reference instead.",
          confidence: 0.7,
        }),
      );
    }
    if (startsWithHttp(arg)) out.push(...urlSecrets(spec, "args", arg));
  });

  if (spec.url) out.push(...urlSecrets(spec, "url", spec.url));
  return out;
};

// --- SUP01: unpinned / remote-fetched launch ---------------------------------

const SUP01: RuleMeta = {
  rule_id: "SUP01",
  title: "Unpinned or remote-fetched MCP server",
  category: "supply_chain",
  severity: "medium",
  mappings: ["MCP-SUPPLY-CHAIN", "SLSA-PROVENANCE", "OWASP-ASI04"],
};

const GIT_SPEC_RE = pyRe(String.raw`(?:^|\s)(?:git\+|github:)`, "i");
const URL_RE = pyRe(String.raw`https?://`, "i");
const URL_PREFIX_RE = pyRe(String.raw`^https?://`, "i"); // Python _URL_RE.match(...)

/** True when the server's *code* is downloaded from a URL at launch. */
function isRemoteFetch(spec: MCPServerSpec, launch: PackageLaunch | null): boolean {
  if (launch !== null && REMOTE_FETCH_RE.test(launch.spec)) return true;
  if (spec.args.some((arg) => GIT_SPEC_RE.test(arg))) return true;
  const line = commandLine(spec);
  if (DOWNLOADER_RE.test(line) && URL_RE.test(line)) return true;
  const runner = removeSuffix(commandBasename(spec.command ?? ""), ".exe");
  return URL_SCRIPT_RUNNERS.has(runner) && spec.args.some((a) => URL_PREFIX_RE.test(a));
}

/** The image a `docker|podman run` line starts, or null. */
export function containerImage(args: string[]): string | null {
  const run = args.indexOf("run");
  if (run < 0) return null;
  const rest = args.slice(run + 1);
  let i = 0;
  while (i < rest.length) {
    const arg = rest[i];
    if (arg.startsWith("-")) {
      const takesValue = CONTAINER_VALUE_FLAGS.has(arg) && !arg.includes("=");
      i += takesValue ? 2 : 1;
      continue;
    }
    return arg;
  }
  return null;
}

export const pinning: Rule = (spec) => {
  if (!spec.command) return [];
  const location = loc(spec.name, null, "command");
  const launch = parseLaunch(spec.command, spec.args);
  const cmdLine = commandLine(spec);

  // Remote fetch-and-run is the worst case.
  if (isRemoteFetch(spec, launch)) {
    return [
      finding(SUP01, {
        title: "MCP server fetches code from a remote URL at launch",
        location,
        evidence: truncate(cmdLine),
        remediation:
          "Do not fetch-and-execute remote code at launch. Vendor the server, pin a version, and verify its integrity (hash / signature).",
        severity: "high",
      }),
    ];
  }

  if (CONTAINER_RUNTIMES.has(removeSuffix(commandBasename(spec.command), ".exe"))) {
    const image = containerImage(spec.args);
    if (image === null || image.includes("@sha256:")) return [];
    const lastSegment = image.slice(image.lastIndexOf("/") + 1);
    const tag = partition(lastSegment, ":")[2];
    return [
      finding(SUP01, {
        title: "MCP container image not pinned by digest",
        location,
        evidence: truncate(cmdLine),
        remediation: `Pin the image by digest (e.g. '${tag ? image.split(":")[0] : image}@sha256:<digest>'); tags \u2014 including version tags \u2014 can be re-pushed.`,
        severity: tag === "" || tag === "latest" ? "medium" : "low",
      }),
    ];
  }

  if (!launch || launch.isLocal || launch.isPinned) return [];
  const example = launch.ecosystem === "npm" ? `${launch.name}@1.2.3` : `${launch.name}==1.2.3`;
  return [
    finding(SUP01, {
      location,
      evidence: truncate(cmdLine),
      remediation: `Pin the package version (e.g. '${example}') so a compromised or malicious 'latest' release cannot execute on launch.`,
    }),
  ];
};

// --- SUP02: known-vulnerable / malicious / archived packages -------------------

const SUP02: RuleMeta = {
  rule_id: "SUP02",
  title: "MCP server package has a known vulnerability",
  category: "vulnerable_component",
  severity: "high",
  mappings: ["CWE-1395", "MCP-SUPPLY-CHAIN", "OWASP-ASI04"],
};

function assessAdvisory(
  spec: MCPServerSpec,
  launch: PackageLaunch,
  version: string | null,
  adv: Advisory,
): Finding | null {
  const location = loc(spec.name, null, "command");
  const ids = adv.ids.length ? ` [${adv.ids.join(", ")}]` : "";
  const where = version ? `${launch.name}@${version}` : `${launch.name} (unpinned)`;
  const evidence = `${where}: ${adv.summary}${ids}`;

  if (adv.kind === "malicious") {
    return finding(SUP02, {
      title: "MCP server package is known malware",
      location,
      evidence,
      remediation: `Remove this server immediately and rotate every credential it could reach. Source: ${adv.url}`,
      severity: "critical",
    });
  }
  if (adv.kind === "archived") {
    return finding(SUP02, {
      title: "MCP server package is archived / unmaintained",
      location,
      evidence,
      remediation: `Migrate to a maintained server. Source: ${adv.url}`,
      severity: adv.severity,
    });
  }
  if (adv.kind === "unfixed" || (version !== null && versionMatches(version, adv.affected))) {
    const fix = adv.fixed ? `Upgrade to ${adv.fixed} or later` : "No fixed release exists; replace it";
    return finding(SUP02, {
      location,
      evidence,
      remediation: `${fix}. Source: ${adv.url}`,
      severity: adv.severity,
    });
  }
  if (version === null && adv.fixed) {
    return finding(SUP02, {
      title: "Unpinned launch of a package with a known vulnerability",
      location,
      evidence,
      remediation:
        `Versions ${adv.affected.join(" or ")} are affected. Pin to ${launch.name}@${adv.fixed} or later ` +
        `so a stale cache can't run a vulnerable build. Source: ${adv.url}`,
      severity: "low",
      confidence: 0.5,
    });
  }
  return null;
}

export const vulnerablePackages: Rule = (spec) => {
  const out: Finding[] = [];
  const haystack = [commandLine(spec), spec.url ?? "", ...orderedEntries(spec.env).map(([, v]) => v)].join(" ").toLowerCase();
  for (const [needle, description] of Object.entries(IOC_SUBSTRINGS)) {
    if (haystack.includes(needle.toLowerCase())) {
      out.push(
        finding(SUP02, {
          title: "Known MCP attack-campaign indicator in server config",
          location: loc(spec.name),
          evidence: `${needle}: ${description}`,
          remediation:
            "This config references infrastructure from a documented MCP attack campaign. Remove the server, check how it was added, and rotate secrets.",
          severity: "critical",
        }),
      );
    }
  }
  const launch = parseLaunch(spec.command, spec.args);
  if (launch === null || launch.isLocal) return out;
  // The CLI also reads the locally installed package.json when unpinned; the
  // browser has no filesystem, so only the pinned version is assessed here.
  const version = launch.version;
  for (const adv of findAdvisories(launch.ecosystem, launch.name)) {
    const f = assessAdvisory(spec, launch, version, adv);
    if (f !== null) out.push(f);
  }
  return out;
};

// --- CFG01: dangerous launch configuration -----------------------------------

const CFG01: RuleMeta = {
  rule_id: "CFG01",
  title: "Dangerous MCP server launch configuration",
  category: "insecure_config",
  severity: "high",
  mappings: ["CWE-250", "MCP-LOCAL-SERVER-COMPROMISE", "OWASP-ASI05"],
};

const MOUNT_FLAGS = new Set(["-v", "--volume", "--mount"]);
const CAP_ADD_FLAGS = new Set(["--cap-add"]);
const SECURITY_OPT_FLAGS = new Set(["--security-opt"]);
const NAMESPACE_FLAGS = new Set(["--network", "--net", "--pid", "--ipc", "--uts"]);
const PUBLISH_FLAGS = new Set(["-p", "--publish"]);
const MOUNT_SOURCE_PREFIX_RE = pyRe(String.raw`^(?:type=\w+,)?(?:source|src)=`);

function registryFinding(location: FindingLocation, evidence: string): Finding {
  return finding(CFG01, {
    title: "Package registry overridden for the MCP server",
    location,
    evidence: truncate(evidence),
    remediation:
      "A non-default (or extra) index can serve a look-alike package \u2014 the dependency-confusion vector. Use only a registry you control, never an extra index alongside the public one.",
    severity: "medium",
    confidence: 0.6,
  });
}

function bindAllFinding(spec: MCPServerSpec, evidence: string): Finding {
  return finding(CFG01, {
    title: "MCP server listens on all network interfaces",
    location: loc(spec.name, null, "args"),
    evidence: truncate(evidence),
    remediation:
      "Bind local servers to 127.0.0.1. Listening on every interface exposes the server to the network and to DNS-rebinding from any web page.",
    severity: "medium",
  });
}

/** Lowercased host of `url`; empty when it is malformed (never throws). */
function hostnameOf(url: string): string {
  try {
    return (urlparse(url).hostname ?? "").toLowerCase();
  } catch (e) {
    if (e instanceof PyValueError) return "";
    throw e;
  }
}

function envFindings(spec: MCPServerSpec): Finding[] {
  const out: Finding[] = [];
  for (const [key, value] of orderedEntries(spec.env)) {
    const upper = key.toUpperCase();
    const location = loc(spec.name, null, `env:${key}`);
    const reason = lookup(CODE_INJECTION_ENV, upper);
    const loader = lookup(CODE_LOADING_OPTION_ENV, upper);
    if ((reason && pyStrip(value)) || (loader && loader.test(value))) {
      out.push(
        finding(CFG01, {
          title: "Env var injects code into the MCP server process",
          location,
          evidence: truncate(`${key}=${value}`),
          remediation: `${key} ${reason || "loads extra code at startup"}. Remove it; nothing in an MCP config needs to load code into the server out-of-band.`,
        }),
      );
    }
    const tls = lookup(TLS_DISABLE_ENV, upper);
    if (tls && tls.test(value)) {
      out.push(
        finding(CFG01, {
          title: "TLS certificate verification disabled",
          location,
          evidence: `${key}=${pyRepr(value)}`,
          remediation:
            "Disabling verification lets anyone on the network intercept the server's traffic and tokens. Trust a specific CA instead.",
        }),
      );
    }
    const hosts = lookup(API_BASE_URL_ENV, upper);
    if (hosts && pyStrip(value) && !value.startsWith("${")) {
      const host = hostnameOf(value);
      if (host && !hosts.includes(host) && host !== "localhost" && host !== "127.0.0.1") {
        out.push(
          finding(CFG01, {
            title: "LLM API base URL redirected to a non-vendor host",
            location,
            evidence: `${key}=${truncate(value, 100)}`,
            remediation:
              "The server's API key is sent to whatever this points at. Confirm the host is a proxy you operate; otherwise remove the override.",
            severity: "medium",
            confidence: 0.5,
          }),
        );
      }
    }
    if (REGISTRY_OVERRIDE_ENV.has(upper) && pyStrip(value)) {
      out.push(registryFinding(location, `${key}=${value}`));
    }
  }
  return out;
}

function pathFindings(spec: MCPServerSpec, args: string[]): Finding[] {
  const out: Finding[] = [];
  for (const arg of args) {
    const value = arg.startsWith("-") && arg.includes("=") ? partition(arg, "=")[2] : arg;
    if (ROOT_PATH_RE.test(value)) {
      out.push(
        finding(CFG01, {
          title: "MCP server given access to the entire filesystem",
          location: loc(spec.name, null, "args"),
          evidence: truncate(commandLine(spec)),
          remediation:
            "Scope the server to the specific project directories it needs; a root path exposes SSH keys, cloud credentials, and every other secret.",
        }),
      );
    } else if (HOME_PATH_RE.test(value)) {
      out.push(
        finding(CFG01, {
          title: "MCP server given access to the whole home directory",
          location: loc(spec.name, null, "args"),
          evidence: truncate(commandLine(spec)),
          remediation:
            "The home directory holds ~/.ssh, ~/.aws, browser profiles, and MCP configs. Scope the server to the project directories it needs.",
          severity: "medium",
        }),
      );
    }
  }
  return out;
}

function containerFindings(spec: MCPServerSpec, args: string[]): Finding[] {
  const out: Finding[] = [];
  const location = loc(spec.name, null, "args");
  const hit = (title: string, evidence: string, remediation: string, severity: Severity = "high") =>
    out.push(finding(CFG01, { title, location, evidence: truncate(evidence), remediation, severity }));

  if (args.includes("--privileged")) {
    hit(
      "MCP container runs --privileged",
      "--privileged",
      "A privileged container is root on the host. Drop --privileged.",
    );
  }
  for (const [, mount] of flagValues(args, MOUNT_FLAGS)) {
    const source = partition(partition(mount.replace(MOUNT_SOURCE_PREFIX_RE, ""), ":")[0], ",")[0];
    if (DOCKER_SOCKET_RE.test(mount)) {
      hit(
        "Docker socket mounted into the MCP container",
        mount,
        "The Docker socket grants root on the host. Never mount it into a server.",
      );
    } else if (ROOT_PATH_RE.test(source)) {
      hit(
        "Host root filesystem mounted into the MCP container",
        mount,
        "Mount only the specific directories the server needs, read-only if possible.",
      );
    } else if (HOME_PATH_RE.test(source)) {
      hit(
        "Whole home directory mounted into the MCP container",
        mount,
        "Mount only the project directories the server needs.",
        "medium",
      );
    }
  }
  for (const [flag, value] of flagValues(args, CAP_ADD_FLAGS)) {
    const cap = value.toUpperCase();
    if (DANGEROUS_CAPS.has(cap.startsWith("CAP_") ? cap.slice(4) : cap)) {
      hit(
        "MCP container granted a dangerous capability",
        `${flag} ${value}`,
        "Drop the added capability; it enables container escape.",
      );
    }
  }
  for (const [flag, value] of flagValues(args, SECURITY_OPT_FLAGS)) {
    if (value.includes("unconfined") || pyStrip(value) === "no-new-privileges=false") {
      hit(
        "MCP container security profile disabled",
        `${flag} ${value}`,
        "Keep the default seccomp / AppArmor profiles.",
      );
    }
  }
  for (const [flag, value] of flagValues(args, NAMESPACE_FLAGS)) {
    if (value === "host") {
      hit(
        "MCP container shares a host namespace",
        `${flag}=${value}`,
        "Host namespaces remove container isolation. Use the default namespaces and publish only the ports the server needs.",
        "medium",
      );
    }
  }
  for (const [, value] of flagValues(args, PUBLISH_FLAGS)) {
    if (value.split(":").length - 1 === 1 || value.startsWith("0.0.0.0:")) {
      out.push(bindAllFinding(spec, `-p ${value} (publishes on all interfaces)`));
    }
  }
  return out;
}

export const launchConfig: Rule = (spec) => {
  const out: Finding[] = envFindings(spec);
  if (!spec.command) return out;
  let command = removeSuffix(commandBasename(spec.command), ".exe");
  let args = spec.args;
  if (PRIVILEGE_ESCALATION_COMMANDS.has(command)) {
    out.push(
      finding(CFG01, {
        title: "MCP server launched with elevated privileges",
        location: loc(spec.name, null, "command"),
        evidence: truncate(commandLine(spec)),
        remediation:
          "Never run an MCP server as root. Anything that steers it \u2014 including prompt injection \u2014 then acts with full control of the machine.",
      }),
    );
    args = args.slice(1);
    command = spec.args.length ? commandBasename(spec.args[0]) : command;
  }
  if (CONTAINER_RUNTIMES.has(command)) out.push(...containerFindings(spec, args));
  else out.push(...pathFindings(spec, args));
  for (const [flag, value] of flagValues(args, REGISTRY_OVERRIDE_FLAGS)) {
    if (startsWithHttp(value) || value.startsWith("file:")) {
      out.push(registryFinding(loc(spec.name, null, "args"), `${flag} ${value}`));
    }
  }
  for (const [flag, value] of flagValues(args, HOST_FLAGS)) {
    if (ALL_INTERFACES_RE.test(value)) out.push(bindAllFinding(spec, `${flag} ${value}`));
  }
  return out;
};

// --- NET01: insecure transport -----------------------------------------------

const NET01: RuleMeta = {
  rule_id: "NET01",
  title: "Plaintext HTTP connection to a remote MCP server",
  category: "insecure_transport",
  severity: "high",
  mappings: ["CWE-319", "MCP-TRANSPORT-SECURITY", "OWASP-ASI03"],
};

// Local bridges whose URL argument is the remote MCP endpoint.
const BRIDGE_PACKAGES = new Set(["mcp-remote", "supergateway", "mcp-proxy"]);

/** `[field, url]` for every remote MCP endpoint this entry talks to. */
function endpoints(spec: MCPServerSpec): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  if (spec.url) out.push(["url", spec.url]);
  const launch = parseLaunch(spec.command, spec.args);
  if (launch !== null && BRIDGE_PACKAGES.has(launch.name)) {
    for (const arg of spec.args) if (startsWithHttp(arg)) out.push(["args", arg]);
  }
  return out;
}

export const transport: Rule = (spec) => {
  const out: Finding[] = [];
  for (const [field, url] of endpoints(spec)) {
    let parsed: ParsedUrl;
    try {
      parsed = urlparse(url);
    } catch (e) {
      if (e instanceof PyValueError) continue; // malformed (e.g. "http://[") - nothing to judge
      throw e;
    }
    const host = parsed.hostname ?? "";
    if (parsed.scheme === "http" && host && !LOOPBACK_HOST_RE.test(host)) {
      const hostPart = parsed.netloc.slice(parsed.netloc.lastIndexOf("@") + 1);
      out.push(
        finding(NET01, {
          location: loc(spec.name, null, field),
          evidence: `${parsed.scheme}://${hostPart}${parsed.path}`,
          remediation:
            "Use https://. Over plaintext, tokens can be stolen and tool descriptions rewritten in transit.",
        }),
      );
    }
  }
  if (spec.transport === "sse") {
    out.push(
      finding(NET01, {
        title: "Deprecated HTTP+SSE transport",
        location: loc(spec.name, null, "url"),
        evidence: spec.url || "type: sse",
        remediation:
          "The MCP spec replaced HTTP+SSE with Streamable HTTP. Move to it when the server supports it.",
        severity: "low",
      }),
    );
  }
  return out;
};

// --- HDR01 / CACHE01: MCP 2026-07-28 protocol surface ------------------------

const HDR01: RuleMeta = {
  rule_id: "HDR01",
  title: "Invalid x-mcp-header designation (clients must reject this tool)",
  category: "insecure_transport",
  severity: "medium",
  mappings: ["MCP-2026-07-28-SEP-2243", "OWASP-ASI03", "CWE-113"],
};

const HEADER_KEY = "x-mcp-header";
const MAX_HEADER_DEPTH = 32;

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function ownValue(obj: Record<string, unknown>, key: string): unknown {
  return Object.prototype.hasOwnProperty.call(obj, key) ? obj[key] : undefined;
}

/** `[path, raw schema path, property schema]` for every property reachable via `properties` alone. */
function reachable(
  schema: unknown,
  path = "",
  raw = "",
  depth = 0,
): Array<[string, string, Record<string, unknown>]> {
  const out: Array<[string, string, Record<string, unknown>]> = [];
  if (depth > MAX_HEADER_DEPTH || !isJsonObject(schema)) return out;
  const props = ownValue(schema, "properties");
  if (!isJsonObject(props)) return out;
  for (const [name, sub] of orderedEntries(props)) {
    if (!isJsonObject(sub)) continue;
    const child = path ? `${path}.${name}` : name;
    const childRaw = raw ? `${raw}.properties.${name}` : `properties.${name}`;
    out.push([child, childRaw, sub]);
    out.push(...reachable(sub, child, childRaw, depth + 1));
  }
  return out;
}

/** Paths of every `x-mcp-header` key anywhere in a schema. */
function allDesignations(node: unknown, path = "", depth = 0): string[] {
  const out: string[] = [];
  if (depth > MAX_HEADER_DEPTH) return out;
  if (isJsonObject(node)) {
    for (const [key, value] of orderedEntries(node)) {
      const child = path ? `${path}.${key}` : key;
      if (key === HEADER_KEY) out.push(path || "<root>");
      out.push(...allDesignations(value, child, depth + 1));
    }
  } else if (Array.isArray(node)) {
    node.forEach((item, index) => out.push(...allDesignations(item, `${path}[${index}]`, depth + 1)));
  }
  return out;
}

function headerTypeProblem(prop: Record<string, unknown>): string | null {
  const declared = ownValue(prop, "type");
  const types = typeof declared === "string" ? [declared] : Array.isArray(declared) ? declared : [];
  const concrete = types.filter((t) => t !== "null");
  if (!concrete.length) return "the parameter declares no primitive type";
  const bad = concrete
    .filter((t) => !(typeof t === "string" && HEADER_PARAM_TYPES.has(t)))
    .map((t) => pyStr(t));
  if (bad.length) return `type ${bad.join("/")} cannot be mirrored (string, integer, boolean only)`;
  return null;
}

function isSecretParam(path: string, prop: Record<string, unknown>): boolean {
  const name = path.slice(path.lastIndexOf(".") + 1);
  const description = ownValue(prop, "description");
  return SECRET_NAME_RE.test(name) || (typeof description === "string" && SECRET_NAME_RE.test(description));
}

function headerValueProblem(value: unknown, seen: Map<string, string>, path: string): string | null {
  if (typeof value !== "string" || !value) return "the header name must be a non-empty string";
  if (!HTTP_TOKEN_RE.test(value)) return "the header name is not an HTTP field-name token";
  const key = value.toLowerCase();
  if (!seen.has(key)) seen.set(key, path);
  const first = seen.get(key)!;
  if (first !== path) return `duplicates the header name used by ${first} (case-insensitive)`;
  return null;
}

export const headerMirroring: Rule = (spec) => {
  const manifest = spec.manifest;
  if (!manifest) return [];
  const out: Finding[] = [];
  for (const tool of manifest.tools) {
    const schema = tool.inputSchema;
    const validPaths = new Set<string>();
    const seen = new Map<string, string>();
    for (const [path, raw, prop] of reachable(schema)) {
      if (!Object.prototype.hasOwnProperty.call(prop, HEADER_KEY)) continue;
      validPaths.add(raw);
      const value = prop[HEADER_KEY];
      const location = loc(spec.name, tool.name, `param:${path}`);
      if (typeof value === "string" && ["\r", "\n", "\x00"].some((c) => value.includes(c))) {
        out.push(
          finding(HDR01, {
            title: "x-mcp-header value contains control characters (header injection)",
            location,
            evidence: `${HEADER_KEY}=${pyReprValue(value)}`,
            remediation:
              "A header name carrying CR/LF can split the HTTP request a client sends. Treat the server as hostile; conforming clients must drop this tool.",
            severity: "high",
          }),
        );
        continue;
      }
      const problem = headerValueProblem(value, seen, path) ?? headerTypeProblem(prop);
      if (problem) {
        out.push(
          finding(HDR01, {
            location,
            evidence: truncate(`${HEADER_KEY}=${pyReprValue(value)}: ${problem}`, 300),
            remediation:
              "Fix the tool definition: the header name must be a unique HTTP token on a string / integer / boolean parameter. Until then clients drop the tool.",
          }),
        );
      } else if (isSecretParam(path, prop)) {
        out.push(
          finding(HDR01, {
            title: "Credential-bearing parameter mirrored into an HTTP header",
            location,
            evidence: `${path} -> Mcp-Param-${pyStr(value)}`,
            remediation:
              "Headers are copied into proxy, WAF, CDN, and access logs. Do not mirror secrets; pass them in the body or through the authorization flow.",
          }),
        );
      }
    }
    for (const path of allDesignations(schema)) {
      if (!validPaths.has(path)) {
        out.push(
          finding(HDR01, {
            location: loc(spec.name, tool.name, `inputSchema.${path}`),
            evidence: `${HEADER_KEY} at ${path}: not reachable from the schema root through 'properties' alone (items / anyOf / $ref / if-then are not allowed)`,
            remediation:
              "Move the designation onto a top-level or nested 'properties' parameter, or remove it. Clients must reject tools with misplaced designations.",
          }),
        );
      }
    }
  }
  return out;
};

const CACHE01: RuleMeta = {
  rule_id: "CACHE01",
  title: "Tool list cache hint weakens change detection",
  category: "rug_pull",
  severity: "low",
  mappings: ["MCP-2026-07-28-SEP-2549", "MCP-RUG-PULL", "OWASP-ASI04"],
};

/** Evidence that requests to this server carry credentials, if any. */
function authenticated(spec: MCPServerSpec): string | null {
  for (const [name] of orderedEntries(spec.headers)) {
    if (AUTH_HEADER_NAME_RE.test(name)) return `${name} header`;
  }
  if (spec.url && (URL_USERINFO_RE.test(spec.url) || URL_SECRET_PARAM_RE.test(spec.url))) {
    return "credentials in the URL";
  }
  for (let i = 0; i < spec.args.length; i++) {
    if (spec.args[i] === "--header" && i + 1 < spec.args.length) {
      const header = pyStrip(partition(spec.args[i + 1], ":")[0]);
      if (AUTH_HEADER_NAME_RE.test(header)) return `${header} header (bridge argument)`;
    }
  }
  return null;
}

/** Python `f"{x:.0f}"`: round half to even. */
function formatRound0(x: number): string {
  const floor = Math.floor(x);
  const diff = x - floor;
  const rounded = diff > 0.5 ? floor + 1 : diff < 0.5 ? floor : floor % 2 === 0 ? floor : floor + 1;
  return rounded.toFixed(0);
}

export const cacheHints: Rule = (spec) => {
  const manifest = spec.manifest;
  if (!manifest) return [];
  const out: Finding[] = [];
  const auth = authenticated(spec);
  if (manifest.cacheScope === "public" && auth) {
    out.push(
      finding(CACHE01, {
        title: "Authenticated tool list marked cacheScope: public",
        location: loc(spec.name, null, "cacheScope"),
        evidence: `cacheScope=public; requests carry ${auth}`,
        remediation:
          "Shared caches may store this per-user catalog and serve it to other users, and a poisoned copy outlives the fix. Serve authenticated lists with cacheScope: private.",
        severity: "medium",
      }),
    );
  }
  const ttl = manifest.ttlMs;
  if (ttl !== undefined && ttl !== null && ttl > LONG_CACHE_TTL_MS) {
    out.push(
      finding(CACHE01, {
        location: loc(spec.name, null, "ttlMs"),
        evidence: `ttlMs=${ttl} (~${formatRound0(ttl / 3_600_000)}h)`,
        remediation:
          "Clients may keep serving a cached tool list this long, so a changed definition is invisible to them until it expires. A cached list is not a reviewed one: pin it with `mcpguard lock` and re-check on every connect.",
      }),
    );
  }
  return out;
};

// --- SUP03: publisher provenance (impersonation, typosquats) ------------------

const SUP03: RuleMeta = {
  rule_id: "SUP03",
  title: "MCP server package imitates a trusted publisher",
  category: "supply_chain",
  severity: "high",
  mappings: ["MCP-SUPPLY-CHAIN", "OWASP-ASI04", "CWE-1357"],
};

const MIN_TYPO_LENGTH = 8; // shorter names collide with legitimate ones too often
const SKELETON_FOLD: Record<string, string> = { "0": "o", "1": "l", i: "l", "3": "e", "5": "s" };

/** A name with separators dropped and common lookalike characters folded. */
export function skeleton(name: string): string {
  const folded = name.toLowerCase().split("rn").join("m").split("vv").join("w");
  return codePoints(folded)
    .map((c) => lookup(SKELETON_FOLD, c) ?? c)
    .filter((c) => !"-_.".includes(c))
    .join("");
}

/** Optimal-string-alignment distance, returning `limit + 1` once it's exceeded. */
export function editDistance(aText: string, bText: string, limit = 2): number {
  const a = codePoints(aText);
  const b = codePoints(bText);
  if (Math.abs(a.length - b.length) > limit) return limit + 1;
  let prev2: number[] = [];
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i, ...new Array<number>(b.length).fill(0)];
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        cur[j] = Math.min(cur[j], prev2[j - 2] + 1);
      }
    }
    if (Math.min(...cur) > limit) return limit + 1;
    prev2 = prev;
    prev = cur;
  }
  return prev[prev.length - 1];
}

export const provenance: Rule = (spec) => {
  const launch = parseLaunch(spec.command, spec.args);
  // Local paths have no publisher; URL / git specs are SUP01's (fetch-and-run).
  if (launch === null || launch.isLocal || REMOTE_FETCH_RE.test(launch.spec)) return [];
  const eco = launch.ecosystem;
  const name = canonicalPackage(eco, launch.name);
  const known = new Set([...(lookup(WELL_KNOWN_PACKAGES, eco) ?? [])].map((k) => canonicalPackage(eco, k)));
  if (known.has(name)) return [];
  const location = loc(spec.name, null, "command");
  const scope = name.startsWith("@") && name.includes("/") ? name.split("/", 1)[0] : null;
  const verify =
    "Confirm the publisher before running it: check the package's repository, maintainers, and release history against the vendor's own documentation.";

  if (scope !== null && !TRUSTED_SCOPES.has(scope)) {
    for (const trusted of pySorted(TRUSTED_SCOPES)) {
      if (skeleton(scope) === skeleton(trusted) || (codePoints(trusted).length >= 12 && editDistance(scope, trusted) <= 2)) {
        return [
          finding(SUP03, {
            title: "npm scope imitates a trusted MCP publisher",
            location,
            evidence: `${launch.name}: scope ${scope} looks like ${trusted}`,
            remediation: `This is not ${trusted}. Remove the server. ${verify}`,
          }),
        ];
      }
    }
  }

  if (scope === null || !TRUSTED_SCOPES.has(scope)) {
    for (const knownName of pySorted(known)) {
      if (codePoints(knownName).length < MIN_TYPO_LENGTH) continue;
      if (skeleton(name) === skeleton(knownName)) {
        return [
          finding(SUP03, {
            title: "Package name is a lookalike of a well-known MCP server",
            location,
            evidence: `${launch.name} looks like ${knownName}`,
            remediation: `Did you mean ${knownName}? ${verify}`,
          }),
        ];
      }
      if (editDistance(name, knownName, 1) === 1) {
        return [
          finding(SUP03, {
            title: "Package name is one edit from a well-known MCP server",
            location,
            evidence: `${launch.name} vs ${knownName}`,
            remediation: `Did you mean ${knownName}? ${verify}`,
            severity: "medium",
            confidence: 0.6,
          }),
        ];
      }
    }
  }

  const nameWords = new Set(words(name));
  if (!nameWords.has("mcp")) return [];
  const raw = launch.name.toLowerCase();
  for (const brand of pySorted(Object.keys(BRAND_PUBLISHERS))) {
    if (!nameWords.has(brand)) continue;
    const publishers = BRAND_PUBLISHERS[brand];
    if (publishers.some((p) => raw.startsWith(p) || name.startsWith(canonicalPackage(eco, p)))) return [];
    const title = brand.charAt(0).toUpperCase() + brand.slice(1);
    const official = publishers.length ? publishers.join(" or ") : "no verified package scope";
    return [
      finding(SUP03, {
        title: `MCP package named after ${title} is not from its publisher`,
        location,
        evidence: `${launch.name}: ${title} publishes under ${official}`,
        remediation: `Brand names are free to register: postmark-mcp impersonated Postmark and stole mail. ${verify}`,
        severity: "low",
        confidence: 0.4,
      }),
    ];
  }
  return [];
};

/** Every browser-runnable rule, in id order (the Python engine runs rules sorted by id). */
export const RULES: ReadonlyArray<{ id: string; run: Rule }> = [
  { id: "CACHE01", run: cacheHints },
  { id: "CAP01", run: excessiveAgency },
  { id: "CFG01", run: launchConfig },
  { id: "FLOW01", run: toxicFlow },
  { id: "HDR01", run: headerMirroring },
  { id: "NET01", run: transport },
  { id: "SEC01", run: secrets },
  { id: "SUP01", run: pinning },
  { id: "SUP02", run: vulnerablePackages },
  { id: "SUP03", run: provenance },
  { id: "TP01", run: toolPoisoning },
  { id: "TP02", run: hiddenContent },
  { id: "TP03", run: toolShadowing },
];
