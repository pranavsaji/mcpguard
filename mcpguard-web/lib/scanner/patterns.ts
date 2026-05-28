/**
 * Detection signatures — a faithful TypeScript port of the Python engine's
 * `patterns.py`. Pattern strings are kept identical so both engines agree.
 */

export const INJECTION_PATTERNS: RegExp[] = [
  /ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts?|context)/i,
  /disregard\s+(?:all\s+)?(?:previous|prior|above|the)\s+\w+/i,
  /forget\s+(?:everything|all|your)\b/i,
  /you\s+must\s+(?:always|never)\b/i,
  /do\s+not\s+(?:tell|inform|mention|reveal)\s+(?:the\s+)?user/i,
  /without\s+(?:telling|informing|notifying)\s+the\s+user/i,
  /\bnew\s+(?:instructions?|system\s+prompt)\b/i,
  /<\s*(?:system|important|secret)\s*>/i,
  /\bas\s+an?\s+ai\b.*\bmust\b/i,
];

export const EXFIL_PATTERNS: RegExp[] = [
  /\b(?:send|post|upload|exfiltrate|forward)\b.{0,40}\b(?:to|->)\b.{0,40}https?:\/\//i,
  /\bread\b.{0,30}(?:~\/\.ssh|\.env|id_rsa|\/etc\/passwd|credentials)/i,
  /\b(?:include|append|attach)\b.{0,30}\b(?:api[_-]?key|token|secret|password)\b/i,
];

// Zero-width / invisible / BiDi control characters used to smuggle text.
export const INVISIBLE_CHARS: string[] = [
  "​", "‌", "‍", "⁠", "﻿", "­",
  "‪", "‫", "‬", "‭", "‮",
  "⁦", "⁧", "⁨", "⁩",
];
export const INVISIBLE_CHAR_SET = new Set(INVISIBLE_CHARS);

export const HTML_COMMENT_RE = /<!--[\s\S]*?-->/;

export const CAPABILITY_KEYWORDS: Record<string, string[]> = {
  "code execution": ["exec", "eval", "execute_code", "run_code", "shell", "subprocess", "spawn"],
  "shell / command": ["run_command", "execute_command", "system", "os_command", "bash", "powershell"],
  "filesystem write": ["write_file", "delete_file", "remove_file", "rmdir", "unlink", "overwrite"],
  "arbitrary network": ["http_request", "fetch_url", "curl", "send_request", "open_url", "webhook"],
  "credential access": ["read_secret", "get_credentials", "dump_env", "list_tokens", "get_password"],
  database: ["execute_sql", "run_query", "drop_table", "delete_from"],
};

export const DANGEROUS_NAME_TOKENS = new Set([
  "exec", "eval", "shell", "command", "delete", "remove", "drop", "sudo", "admin",
]);

export const RCE_SOURCE_PATTERNS: Record<string, RegExp> = {
  "python: subprocess shell=True": /subprocess\.\w+\([^)]*shell\s*=\s*True/,
  "python: os.system": /\bos\.system\s*\(/,
  "python: os.popen": /\bos\.popen\s*\(/,
  "python: eval/exec": /\b(?:eval|exec)\s*\(/,
  "node: child_process.exec": /child_process\.(?:exec|execSync)\s*\(/,
  "node: new Function": /\bnew\s+Function\s*\(/,
  "shell: curl pipe to shell": /curl[^\n|]*\|\s*(?:ba)?sh\b/,
};

export const SECRET_NAME_RE =
  /(?:api[_-]?key|secret|token|password|passwd|access[_-]?key|private[_-]?key|client[_-]?secret)/i;

export const SECRET_VALUE_PATTERNS: Record<string, RegExp> = {
  "OpenAI key": /\bsk-[A-Za-z0-9]{20,}\b/,
  "Anthropic key": /\bsk-ant-[A-Za-z0-9_-]{20,}\b/,
  "GitHub token": /\bgh[pousr]_[A-Za-z0-9]{30,}\b/,
  "AWS access key id": /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
  "Slack token": /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,
  "Google API key": /\bAIza[0-9A-Za-z_-]{35}\b/,
  "Private key block": /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
};

const PLACEHOLDER_RE =
  /^\s*(?:\$\{?[\w.-]+\}?|<[^>]+>|\{\{[^}]+\}\}|(?:your|my|the)[_-].*|x{3,}|changeme|placeholder|todo|example|\*+)\s*$/i;

export function looksLikePlaceholder(value: string): boolean {
  return PLACEHOLDER_RE.test(value.trim());
}

export const PINNED_LAUNCHERS = new Set(["npx", "uvx", "pipx", "bunx"]);
export const NPM_PINNED_RE = /@\d[\w.-]*$/;
export const REMOTE_FETCH_RE = /https?:\/\/|git\+|github:/i;
