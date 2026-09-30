/**
 * Detection signatures — a faithful TypeScript port of the Python engine's
 * `patterns.py`. Pattern sources are copied verbatim from Python (as
 * `String.raw` templates) and compiled with {@link pyRe}, which reproduces
 * Python `re` semantics (Unicode `\w`/`\b`/`\s`, `.`, `$`, case folding), so
 * both engines match exactly the same text.
 */

import { pyRe, pyStrip } from "./pycompat";

const I = "i"; // re.IGNORECASE
const BT = "`";

// --------------------------------------------------------------------------- //
// Tool poisoning / prompt injection (TP01)                                    //
// --------------------------------------------------------------------------- //

export const INJECTION_PATTERNS: RegExp[] = [
  // Instruction override.
  String.raw`ignore\s+(?:all\s+)?(?:(?:the|any|your)\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|prompts?|context|directions|rules)`,
  String.raw`disregard\s+(?:all\s+)?(?:previous|prior|above|the)\s+\w+`,
  String.raw`forget\s+(?:everything|all|your)\b`,
  String.raw`\b(?:override|bypass)\s+(?:all\s+|any\s+)?(?:the\s+|your\s+)?(?:safety|security|system|content)\s+(?:rules|instructions|guidelines|polic(?:y|ies)|filters?|restrictions)`,
  String.raw`you\s+must\s+(?:always|never)\b`,
  String.raw`\bnew\s+(?:instructions?|system\s+prompt)\b`,
  String.raw`\bas\s+an?\s+ai\b.{0,80}?\bmust\b`,
  String.raw`\byou\s+are\s+now\s+(?:in\s+)?(?:an?\s+)?(?:developer|dan|jailbreak|jailbroken|unrestricted|god|admin)\b`,
  // Concealment from the user: the hallmark of tool poisoning (Invariant, 2025).
  String.raw`\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|mention|reveal|notify|alert)\b.{0,30}?\buser\b`,
  String.raw`\b(?:do\s+not|don'?t|never)\s+(?:mention|reveal|disclose)\s+(?:that\s+you|this\s+(?:instruction|step|tool)|these\s+instructions|any\s+of\s+this)`,
  String.raw`without\s+(?:telling|informing|notifying|alerting|asking)\s+the\s+user`,
  String.raw`\b(?:hide|conceal)\s+(?:this|it|these)\s+from\s+the\s+user`,
  String.raw`\bthe\s+user\s+(?:must|should)\s+(?:not|never)\s+(?:know|see|be\s+told)`,
  // Pseudo-tags and chat-template tokens that smuggle "system" instructions.
  String.raw`<\s*/?\s*(?:system|important|secret|instructions?|system[_-]?prompt|critical)\s*>`,
  String.raw`<\|\s*(?:im_start|im_end|system|endoftext|start_header_id)\s*\|>`,
  String.raw`\[/?(?:INST|SYSTEM)\]`,
  // Tool-ordering hijack / "line jumping": a tool demanding to run before others.
  String.raw`\b(?:always\s+)?(?:call|run|use|invoke)\s+this\s+tool\s+(?:first|before\s+(?:any|every|all)\b)`,
  String.raw`\b(?:before|prior\s+to)\s+(?:using|calling|invoking)\s+any\s+(?:other\s+)?tools?\b`,
].map((p) => pyRe(p, I));

// Files an MCP tool has no business asking the model to read or ship elsewhere.
const SENSITIVE_PATH =
  String.raw`(?:~/\.ssh(?:/[\w.-]+)?|\.ssh/[\w.-]*|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|(?<![\w.])\.env\b|/etc/(?:passwd|shadow)` +
  String.raw`|\.aws/(?:credentials|config)|\.config/gcloud[\w./-]*|\.azure/[\w./-]*|\.kube/config|\.docker/config\.json` +
  String.raw`|\.npmrc|\.pypirc|\.netrc|\.git-credentials|\.pgpass|\bmcp\.json|claude_desktop_config\.json` +
  String.raw`|\.cursor/[\w./-]*|\.bash_history|\.zsh_history|\bcredentials\.json|\bsecrets?\.(?:json|ya?ml|toml))`;
const READ_VERB = String.raw`(?:read|cat|open|load|access|dump|print|output|return|include|attach|copy|upload|send|leak|provide|paste|share|supply|submit|reply\s+with|respond\s+with)`;
// Credential-like nouns, excluding the ubiquitous pagination/continuation "token".
const CREDENTIAL_NOUN =
  String.raw`(?:api[_-]?keys?|(?<!page\s)(?<!pagination\s)(?<!next\s)(?<!continuation\s)(?<!cursor\s)` +
  String.raw`(?<!page_)(?<!next_)tokens?|secrets?|passwords?|credentials|private\s+keys?)`;

// Data-exfiltration hints embedded in metadata.
export const EXFIL_PATTERNS: RegExp[] = [
  String.raw`\b(?:send|post|upload|exfiltrate|forward|transmit|leak|beacon)\b.{0,40}\b(?:to|->)\b.{0,40}https?://`,
  // Tempered: the match starts at the verb *nearest* the path.
  String.raw`\b${READ_VERB}\b(?:(?!\b${READ_VERB}\b).){0,40}?` + SENSITIVE_PATH,
  String.raw`\b(?:include|append|attach|embed)\b.{0,30}\b` + CREDENTIAL_NOUN + String.raw`\b`,
  String.raw`\b(?:send|post|upload|forward|include|append|attach|leak|copy|pass)\b.{0,40}` +
    String.raw`\b(?:(?:conversation|chat)\s+(?:history|transcript|log)|(?:entire|full|whole)\s+conversation` +
    String.raw`|system\s+prompt|previous\s+messages|message\s+history)\b`,
  // Markdown image whose URL is templated with data: renders -> silent GET to attacker.
  String.raw`!\[[^\]\n]{0,200}\]\(\s*https?://[^)\s?]{0,500}\?(?:[^)\s=]{0,100}=[^)\s&]{0,200}&)*[\w.-]{1,100}=\s*(?:\{|\$|%7B|<|\[)[^)\n]{0,500}\)`,
].map((p) => pyRe(p, I));

// A long base64 run: decoded and re-scanned, since encoding is a cheap filter bypass.
export const BASE64_RUN_RE = pyRe(
  String.raw`(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])`,
);

// --------------------------------------------------------------------------- //
// Tool shadowing / cross-tool interference (TP03)                             //
// --------------------------------------------------------------------------- //

export const SHADOWING_PATTERNS: RegExp[] = [
  // (A backtick cannot appear raw in a template literal, hence the BT splice.)
  String.raw`\bwhen\s+(?:using|calling|invoking)\s+(?:the\s+)?(?!this\b)[${BT}'\"]?[\w.-]+[${BT}'\"]?\s+tool\b`,
  String.raw`\b(?:instead\s+of|rather\s+than)\s+(?:using|calling|invoking)\s+(?:the\s+)?(?!this\b)[${BT}'\"]?[\w.-]+`,
  String.raw`\b(?:all|every|any)\s+(?:e-?mails?|messages?)\b.{0,40}\b(?:must|should)\s+(?:also\s+)?(?:be\s+)?(?:sent|cc'?d|bcc'?d|forwarded|copied|redirected)\s+to\b`,
  String.raw`\b(?:bcc|redirect|forward)\b[^@\n]{0,30}?(?<![\w.+-])[\w.+-]{1,64}@[\w-]{1,63}\.[\w.]{1,63}`,
  String.raw`\b(?:change|replace|override)\s+(?:the\s+)?(?:recipient|destination|to[\s-]address|email\s+address)\b`,
  String.raw`\bthis\s+tool\s+(?:overrides|replaces|supersedes)\b`,
].map((p) => pyRe(p, I));

// "Preference manipulation" (MPMA): biasing the model's tool choice toward this tool.
export const PREFERENCE_PATTERNS: RegExp[] = [
  String.raw`\b(?:always|only)\s+(?:use|prefer|choose|select)\s+this\s+tool\b`,
  String.raw`\b(?:other|all\s+other)\s+tools?\s+(?:are|is)\s+(?:deprecated|broken|unsafe|disabled|outdated)\b`,
  String.raw`\bnever\s+(?:use|call|choose)\s+(?:any\s+)?other\s+tools?\b`,
].map((p) => pyRe(p, I));

// Parameter-name tokens that solicit secrets from the model (CyberArk FSP:
// "content_from_reading_ssh_id_rsa") or open a covert channel (Invariant: "sidenote").
export const SENSITIVE_PARAM_TOKENS: string[] = [
  "ssh", "id_rsa", "id_ed25519", "id_ecdsa", "private_key", "mcp_json", "aws_credentials",
  "passwd", "etc_shadow", "dotenv", "env_file",
];
export const COVERT_PARAM_TOKENS: string[] = ["sidenote", "side_note", "hidden_note", "note_to_model"];

// MCP (2025-11-25) recommends tool names of [A-Za-z0-9_.-], 1-128 chars.
export const TOOL_NAME_RE = pyRe(String.raw`^[A-Za-z0-9_.\-/]{1,128}$`);

// --------------------------------------------------------------------------- //
// Hidden content (TP02)                                                       //
// --------------------------------------------------------------------------- //

// Zero-width / invisible / BiDi control characters used to smuggle text. Kept as
// code points: a security tool must not itself carry invisible source text.
export const INVISIBLE_CODE_POINTS: number[] = [
  0x200b, // zero-width space
  0x200c, // zero-width non-joiner
  0x200d, // zero-width joiner
  0x200e, // left-to-right mark
  0x200f, // right-to-left mark
  0x2060, // word joiner
  0x2061, 0x2062, 0x2063, 0x2064, // invisible math operators
  0xfeff, // zero-width no-break space / BOM
  0x00ad, // soft hyphen
  0x034f, // combining grapheme joiner
  0x061c, // Arabic letter mark
  0x115f, 0x1160, 0x3164, 0xffa0, // Hangul fillers
  0x17b4, 0x17b5, // Khmer inherent vowels
  0x180e, // Mongolian vowel separator
  0x202a, // LRE
  0x202b, // RLE
  0x202c, // PDF
  0x202d, // LRO
  0x202e, // RLO (classic spoofing)
  0x2066, // LRI
  0x2067, // RLI
  0x2068, // FSI
  0x2069, // PDI
  0x206a, 0x206b, 0x206c, 0x206d, 0x206e, 0x206f, // deprecated format chars
  0xfff9, 0xfffa, 0xfffb, // interlinear annotation
];
export const INVISIBLE_CHARS: string[] = INVISIBLE_CODE_POINTS.map((cp) => String.fromCodePoint(cp));
export const INVISIBLE_CHAR_SET: ReadonlySet<string> = new Set(INVISIBLE_CHARS);

// Unicode "Tags" block: invisible copies of ASCII, the "ASCII smuggling" channel.
export const TAG_CHAR_RANGE: readonly [number, number] = [0xe0000, 0xe007f];
// Variation selectors: VS1-16 legitimately follow emoji; long runs, and the
// supplement block, encode bytes invisibly ("emoji smuggling").
export const VARIATION_SELECTOR_RANGE: readonly [number, number] = [0xfe00, 0xfe0f];
export const VARIATION_SELECTOR_SUPPLEMENT_RANGE: readonly [number, number] = [0xe0100, 0xe01ef];
// ESC / CSI and other C0/C1 controls (tab, LF, CR excepted): ANSI sequences can
// hide or rewrite text in terminal-based clients (Trail of Bits, 2025).
export const CONTROL_CHAR_RE = pyRe(String.raw`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x80-\x9f]`);
export const ANSI_ESCAPE_RE = pyRe(
  String.raw`(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)`,
);
// Blank padding that pushes trailing text out of view in approval dialogs.
export const PADDING_RE = pyRe(String.raw`\S(?:[ \t]{80,}|(?:[ \t]*\n){20,}[ \t]*)\S`);

// Kept for compatibility; TP02 uses the linear-time htmlComments() scanner.
export const HTML_COMMENT_RE = pyRe(String.raw`<!--.*?-->`, "s");

// --------------------------------------------------------------------------- //
// Excessive agency / dangerous capabilities (CAP01)                           //
// --------------------------------------------------------------------------- //

// Keywords match whole *words*, never substrings: "system" must not fire on
// "filesystem", nor "exec" on "executive". Multi-word keywords (write_file) match
// as consecutive words in any casing/separator style (write_file, writeFile,
// write-file, "write file"). A trailing plural "s" is tolerated (webhooks).
export const CAPABILITY_KEYWORDS: Record<string, string[]> = {
  "code execution": [
    "exec", "eval", "execute_code", "run_code", "arbitrary_code", "shell", "subprocess", "spawn",
  ],
  "shell / command": [
    "run_command", "execute_command", "shell_command", "os_command", "system_command",
    "os_system", "bash", "powershell",
  ],
  "filesystem write": [
    "write_file", "delete_file", "remove_file", "move_file", "rmdir", "unlink", "overwrite",
  ],
  "arbitrary network": [
    "http_request", "fetch_url", "curl", "wget", "send_request", "open_url", "webhook",
  ],
  "credential access": [
    "read_secret", "get_secret", "get_credentials", "dump_env", "list_tokens", "get_password",
  ],
  database: ["execute_sql", "run_sql", "run_query", "drop_table", "delete_from"],
};

// Tokens that, appearing in a tool *name*, strongly imply a dangerous verb.
export const DANGEROUS_NAME_TOKENS: ReadonlySet<string> = new Set([
  "exec", "eval", "shell", "command", "delete", "remove", "drop", "sudo", "admin",
]);

// --------------------------------------------------------------------------- //
// Secrets (SEC01)                                                             //
// --------------------------------------------------------------------------- //

export const SECRET_NAME_RE = pyRe(
  String.raw`(?:api[_-]?key|secret|token|password|passwd|access[_-]?key|private[_-]?key|client[_-]?secret)`,
  I,
);

// High-confidence vendor key formats — value-based, name-independent. Order
// matters: the first match names the vendor.
export const SECRET_VALUE_PATTERNS: Array<[string, RegExp]> = (
  [
    // Anthropic first: its "sk-ant-" prefix would otherwise read as an OpenAI key.
    ["Anthropic key", String.raw`\bsk-ant-[A-Za-z0-9_\-]{20,}`],
    // Legacy "sk-..." and project / service-account / admin keys ("sk-proj-...").
    ["OpenAI key", String.raw`\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}`],
    ["GitHub token", String.raw`\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b`],
    ["GitLab token", String.raw`\bglpat-[A-Za-z0-9_\-]{20,}\b`],
    ["AWS access key id", String.raw`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`],
    ["Slack token", String.raw`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`],
    ["Slack webhook", String.raw`hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+`],
    ["Google API key", String.raw`\bAIza[0-9A-Za-z_\-]{35}\b`],
    ["Stripe secret key", String.raw`\b[rs]k_live_[A-Za-z0-9]{20,}\b`],
    ["Hugging Face token", String.raw`\bhf_[A-Za-z0-9]{30,}\b`],
    ["npm token", String.raw`\bnpm_[A-Za-z0-9]{36}\b`],
    ["SendGrid key", String.raw`\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b`],
    ["Groq key", String.raw`\bgsk_[A-Za-z0-9]{40,}\b`],
    ["xAI key", String.raw`\bxai-[A-Za-z0-9]{40,}\b`],
    ["Supabase access token", String.raw`\bsbp_[a-f0-9]{40}\b`],
    ["Linear API key", String.raw`\blin_api_[A-Za-z0-9]{32,}\b`],
    ["Notion token", String.raw`\bntn_[A-Za-z0-9]{40,}\b`],
    [
      "Database URL with password",
      String.raw`\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql)://[^:/\s@]+:[^@\s/]{3,}@`,
    ],
    [
      "Private key block",
      String.raw`-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----`,
    ],
  ] as Array<[string, string]>
).map(([vendor, p]) => [vendor, pyRe(p)]);

// Literal credentials in HTTP headers ("Authorization: Bearer <token>").
export const AUTH_HEADER_NAME_RE = pyRe(
  String.raw`^(?:authorization|proxy-authorization|x-api-key|api-key|x-auth-token|x-access-token|cookie)$`,
  I,
);
// A launch argument carrying a secret: "--api-key sk-..." or "--token=...".
export const SECRET_FLAG_RE = pyRe(
  String.raw`^--?(?:[\w-]*(?:api[_-]?key|token|secret|password|passwd|access[_-]?key))(?:=(.*))?$`,
  I,
);
// Credential-bearing URL query parameters ("?api_key=...").
export const URL_SECRET_PARAM_RE = pyRe(
  String.raw`[?&](?:api[_-]?key|apikey|key|token|access[_-]?token|auth|secret|password|client[_-]?secret)=([^&#\s]{8,})`,
  I,
);
export const URL_USERINFO_RE = pyRe(String.raw`^[a-z][\w+.-]*://[^/@:\s]+:([^/@\s]+)@`, I);

// Values that look like unresolved placeholders, not real secrets.
export const PLACEHOLDER_RE = pyRe(
  String.raw`^\s*(?:\$\{?[\w.-]+\}?|<[^>]+>|\{\{[^}]+\}\}|(?:your|my|the)[_-].*|x{3,}|changeme|placeholder|todo|example|\*+)\s*$`,
  I,
);

/** True if `value` is an obvious placeholder rather than a live secret. */
export function looksLikePlaceholder(value: string): boolean {
  return PLACEHOLDER_RE.test(pyStrip(value));
}

// --------------------------------------------------------------------------- //
// Supply chain / pinning (SUP01)                                              //
// --------------------------------------------------------------------------- //

// Launchers whose packages should be version-pinned, by ecosystem.
export const NPM_LAUNCHERS: ReadonlySet<string> = new Set(["npx", "bunx"]);
export const PY_LAUNCHERS: ReadonlySet<string> = new Set(["uvx", "pipx"]);
export const PINNED_LAUNCHERS: ReadonlySet<string> = new Set([...NPM_LAUNCHERS, ...PY_LAUNCHERS]);

// Flags whose *value* is the package spec (npx -p pkg@1 cmd, uvx --from pkg==1 cmd,
// pipx run --spec pkg==1 cmd).
export const PACKAGE_FLAGS: Record<string, ReadonlySet<string>> = {
  npx: new Set(["-p", "--package"]),
  bunx: new Set(["-p", "--package"]),
  uvx: new Set(["--from"]),
  pipx: new Set(["--spec"]),
};

// Other flags that consume the next argument, so it is not mistaken for the package.
export const VALUE_FLAGS: Record<string, ReadonlySet<string>> = {
  npx: new Set(["-c", "--call", "--registry", "--cache", "--userconfig", "-w", "--workspace"]),
  bunx: new Set(),
  uvx: new Set([
    "--with", "-w", "--with-editable", "--with-requirements", "--python", "-p",
    "--index", "--index-url", "-i", "--extra-index-url", "--default-index",
    "--find-links", "-f", "--constraints", "-c", "--overrides", "--directory",
    "--project", "--cache-dir", "--config-file", "--python-preference",
  ]),
  pipx: new Set(["--python", "--pip-args", "--index-url", "-i", "--backend"]),
};

// npm: name@1.2.3 (or @scope/name@1.2.3[-pre]). Rejects "latest", ranges ("^1", "~1"),
// and partial versions ("1.2", "1.x"), which npm resolves as ranges.
export const NPM_PINNED_RE = pyRe(String.raw`@\d+\.\d+\.\d+(?:[-+][\w.\-]+)?$`);
// Python: pkg==1.2.3 / pkg===1.2.3 / pkg@1.2.3 (uvx), extras allowed (pkg[cli]==1.0).
export const PY_PINNED_RE = pyRe(String.raw`(?:===?|@)\s*\d[\w.\-+!]*$`);
// A local path or built artifact: nothing is fetched from a registry.
export const LOCAL_PACKAGE_RE = pyRe(
  String.raw`^(?:\.{1,2}[/\\]|[/\\~]|[A-Za-z]:[/\\])|\.(?:whl|tar\.gz|tgz|zip)$`,
  I,
);
export const REMOTE_FETCH_RE = pyRe(String.raw`https?://|git\+|github:`, I);
// Download tools: a URL in the same command line as one of these is fetch-and-run.
export const DOWNLOADER_RE = pyRe(
  String.raw`\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer)\b`,
  I,
);
// Runtimes that execute a script straight from a URL (`deno run https://...`).
export const URL_SCRIPT_RUNNERS: ReadonlySet<string> = new Set(["deno", "bun"]);

// Container launches: images should be pinned by digest, and some run flags
// hand the server the host.
export const CONTAINER_RUNTIMES: ReadonlySet<string> = new Set(["docker", "podman", "nerdctl"]);
// `docker run` flags that consume the next argument (so it's not the image).
export const CONTAINER_VALUE_FLAGS: ReadonlySet<string> = new Set([
  "-e", "--env", "--env-file", "-v", "--volume", "--mount", "--name", "-p", "--publish",
  "--network", "--net", "-u", "--user", "-w", "--workdir", "--entrypoint", "-l", "--label",
  "--platform", "--pull", "--cap-add", "--cap-drop", "--security-opt", "-m", "--memory",
  "--cpus", "--add-host", "--device", "--tmpfs", "-h", "--hostname", "--dns", "--ulimit",
  "--pid", "--ipc", "--uts", "--userns", "--log-driver", "--log-opt", "--restart", "--runtime",
  "--gpus", "--cidfile", "--group-add", "--label-file", "--stop-signal", "--shm-size",
  "--health-cmd", "--volumes-from", "--link", "--expose", "--mac-address", "--ip", "--ip6",
]);

// --------------------------------------------------------------------------- //
// Dangerous launch configuration (CFG01)                                      //
// --------------------------------------------------------------------------- //

// Env vars that inject code into the server process (or every child it spawns).
export const CODE_INJECTION_ENV: Record<string, string> = {
  LD_PRELOAD: "preloads a shared library into the server process",
  LD_AUDIT: "loads an audit library into the server process",
  LD_LIBRARY_PATH: "redirects shared-library resolution",
  DYLD_INSERT_LIBRARIES: "injects a dynamic library into the server process",
  DYLD_LIBRARY_PATH: "redirects dynamic-library resolution",
  DYLD_FRAMEWORK_PATH: "redirects framework resolution",
  PYTHONSTARTUP: "runs a Python file at interpreter start",
  PERL5OPT: "injects Perl command-line options",
  RUBYOPT: "injects Ruby command-line options",
  BASH_ENV: "sources a file in every non-interactive bash",
  ENV: "sources a file in every POSIX sh",
  PROMPT_COMMAND: "runs a command before every shell prompt",
};
// Env vars that are only dangerous with code-loading flags in their value.
export const CODE_LOADING_OPTION_ENV: Record<string, RegExp> = {
  NODE_OPTIONS: pyRe(
    String.raw`(?:^|\s)(?:-r|--require|--import|--loader|--experimental-loader|--inspect(?:-brk)?)\b`,
  ),
  JAVA_TOOL_OPTIONS: pyRe(String.raw`-javaagent:|-agentpath:|-agentlib:`),
  _JAVA_OPTIONS: pyRe(String.raw`-javaagent:|-agentpath:|-agentlib:`),
};
// Env settings that switch off TLS certificate verification.
export const TLS_DISABLE_ENV: Record<string, RegExp> = {
  NODE_TLS_REJECT_UNAUTHORIZED: pyRe(String.raw`^\s*0\s*$`),
  PYTHONHTTPSVERIFY: pyRe(String.raw`^\s*0\s*$`),
  GIT_SSL_NO_VERIFY: pyRe(String.raw`^\s*(?:1|true|yes)\s*$`, I),
  CURL_CA_BUNDLE: pyRe(String.raw`^\s*$`),
  REQUESTS_CA_BUNDLE: pyRe(String.raw`^\s*$`),
};
// Env vars / flags that point the package manager at a non-default registry.
export const REGISTRY_OVERRIDE_ENV: ReadonlySet<string> = new Set([
  "NPM_CONFIG_REGISTRY", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "UV_INDEX_URL",
  "UV_EXTRA_INDEX_URL", "UV_DEFAULT_INDEX", "UV_INDEX", "BUN_CONFIG_REGISTRY",
]);
export const REGISTRY_OVERRIDE_FLAGS: ReadonlySet<string> = new Set([
  "--registry", "--index-url", "-i", "--extra-index-url", "--index", "--default-index",
]);
// LLM API base-URL overrides: a hostile value receives the server's API key.
export const API_BASE_URL_ENV: Record<string, string[]> = {
  ANTHROPIC_BASE_URL: ["api.anthropic.com"],
  OPENAI_BASE_URL: ["api.openai.com"],
  OPENAI_API_BASE: ["api.openai.com"],
};
export const PRIVILEGE_ESCALATION_COMMANDS: ReadonlySet<string> = new Set([
  "sudo", "doas", "pkexec", "runas", "gsudo",
]);
// A path argument that exposes the whole disk or the whole home directory.
export const ROOT_PATH_RE = pyRe(String.raw`^(?:/|[A-Za-z]:[\\/]?|\\\\)$`);
export const HOME_PATH_RE = pyRe(
  String.raw`^(?:~[\\/]?|\$HOME[\\/]?|\$\{HOME\}[\\/]?|%USERPROFILE%[\\/]?|/Users/[^/\\]+/?|/home/[^/\\]+/?|/root/?` +
    String.raw`|[A-Za-z]:[\\/]Users[\\/][^/\\]+[\\/]?)$`,
);
export const ALL_INTERFACES_RE = pyRe(String.raw`^(?:0\.0\.0\.0|::|\[::\])$`);
export const HOST_FLAGS: ReadonlySet<string> = new Set([
  "--host", "--bind", "--listen", "-H", "--hostname", "--address",
]);
export const DOCKER_SOCKET_RE = pyRe(String.raw`(?:^|[=:,\s])(?:/var)?/run/docker\.sock\b|docker_engine`);
export const DANGEROUS_CAPS: ReadonlySet<string> = new Set([
  "ALL", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_ADMIN", "DAC_READ_SEARCH",
]);

// --------------------------------------------------------------------------- //
// Remote transport (NET01)                                                    //
// --------------------------------------------------------------------------- //

export const LOOPBACK_HOST_RE = pyRe(
  String.raw`^(?:localhost|127(?:\.\d{1,3}){3}|\[?::1\]?|[\w.-]+\.localhost|host\.docker\.internal)$`,
  I,
);
// Known compromise indicators (hosts / file names) from public MCP campaigns.
export const IOC_SUBSTRINGS: Record<string, string> = {
  "productivity-suite-mcp.onrender.com": "Deadbugz rug-pull campaign endpoint (Pillar Security, Aug 2026)",
  ".deadbug-mcp.py": "Deadbugz rug-pull campaign local payload (Pillar Security, Aug 2026)",
  "giftshop.club": "postmark-mcp BCC exfiltration domain (Koi Security, Sep 2025)",
  "45.115.38.27": "MCP reverse-shell C2 (Koi Security / JFrog, Oct 2025)",
};

// --------------------------------------------------------------------------- //
// Toxic flow / lethal trifecta (FLOW01)                                       //
// Tool roles inferred from names; matched as whole words like CAP01.          //
// --------------------------------------------------------------------------- //

// Reads content a third party can author: the entry point for indirect injection.
export const UNTRUSTED_INPUT_KEYWORDS: string[] = [
  "fetch", "fetch_url", "fetch_page", "browse", "browser_navigate", "navigate", "scrape",
  "crawl", "web_search", "search_web", "brave_web_search", "read_url", "get_url",
  "read_email", "get_email", "list_emails", "search_emails", "read_inbox", "get_inbox",
  "get_issue", "list_issues", "search_issues", "issue_read", "get_issue_comments",
  "get_pull_request", "list_pull_requests", "get_pull_request_comments", "get_comments",
  "list_comments", "read_messages", "get_messages", "list_messages", "search_messages",
  "channel_history", "get_channel_history", "conversations_history", "get_thread",
  "read_feed", "get_feed", "get_ticket", "list_tickets", "search_tickets", "get_tweets",
  "search_tweets", "read_webpage", "get_webpage",
];
// Reaches data the user would not want leaked.
export const PRIVATE_DATA_KEYWORDS: string[] = [
  "read_file", "read_text_file", "read_multiple_files", "get_file_contents", "read_files",
  "search_files", "list_directory", "directory_tree", "read_query", "execute_sql", "run_sql",
  "run_query", "query_database", "query", "sql", "get_secret", "read_secret", "get_credentials",
  "list_secrets", "get_env", "read_env", "get_document", "read_document", "search_documents",
  "list_private_repos", "get_calendar", "list_events", "get_contacts", "list_contacts",
  "get_customer", "list_customers", "list_tables", "describe_table", "git_show", "git_diff",
  "git_log", "search_code", "read_graph", "search_nodes",
];
// Can move data off the machine: the exfiltration sink.
export const EXTERNAL_SINK_KEYWORDS: string[] = [
  "fetch", "fetch_url", "http_request", "send_request", "post_request", "webhook", "curl",
  "wget", "send_email", "send_mail", "reply_email", "forward_email", "draft_email",
  "post_message", "send_message", "chat_post_message", "slack_post_message", "reply_to_thread",
  "create_issue", "add_issue_comment", "create_comment", "add_comment", "create_pull_request",
  "create_or_update_file", "push_files", "git_push", "create_gist", "upload_file", "upload",
  "publish", "tweet", "post_tweet", "create_post", "share_file", "browser_navigate", "navigate",
];
// Package -> roles for well-known servers, used when no manifest is available.
export const KNOWN_SERVER_ROLES: Record<string, ReadonlySet<string>> = {
  "mcp-server-fetch": new Set(["untrusted", "sink"]),
  "@modelcontextprotocol/server-fetch": new Set(["untrusted", "sink"]),
  "@modelcontextprotocol/server-filesystem": new Set(["private"]),
  "@modelcontextprotocol/server-github": new Set(["untrusted", "private", "sink"]),
  "@modelcontextprotocol/server-gitlab": new Set(["untrusted", "private", "sink"]),
  "@modelcontextprotocol/server-slack": new Set(["untrusted", "private", "sink"]),
  "@modelcontextprotocol/server-brave-search": new Set(["untrusted"]),
  "@modelcontextprotocol/server-puppeteer": new Set(["untrusted", "sink"]),
  "@playwright/mcp": new Set(["untrusted", "sink"]),
  "@modelcontextprotocol/server-postgres": new Set(["private"]),
  "mcp-server-sqlite": new Set(["private"]),
  "@modelcontextprotocol/server-gdrive": new Set(["private"]),
  "mcp-server-git": new Set(["private"]),
  "ghcr.io/github/github-mcp-server": new Set(["untrusted", "private", "sink"]),
};
