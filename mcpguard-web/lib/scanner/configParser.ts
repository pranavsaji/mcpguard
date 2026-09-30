/**
 * Parse MCP config / manifest JSON into server specs (TypeScript port of
 * `config_parser.py`). Accepts the same shapes as the Python engine:
 * `mcpServers`/`servers` maps, a single inline server, or a bare tool manifest.
 * Values are coerced with Python's `str()` / truthiness rules so both engines
 * build identical specs from the same JSON.
 */

import { JsonTooDeepError, orderedEntries, orderedMap, parseJson, pyOr, pyStr, pyTruthy } from "./pycompat";
import type { MCPManifest, MCPPrompt, MCPServerSpec, MCPTool, Transport } from "./types";

export class ConfigError extends Error {}

type Json = Record<string, unknown>;

function asRecord(value: unknown): Json | null {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Json) : null;
}

function asArray(value: unknown): Json[] {
  if (!Array.isArray(value)) return [];
  return value.filter((v): v is Json => !!asRecord(v));
}

function has(obj: Json, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

/** Python `obj.get(key, fallback)`. */
function get(obj: Json, key: string, fallback?: unknown): unknown {
  return has(obj, key) ? obj[key] : fallback;
}

/** Python `str(obj.get(key, fallback))`. */
function getStr(obj: Json, key: string, fallback = ""): string {
  return pyStr(get(obj, key, fallback));
}

/** Python `{str(k): str(v) for k, v in d.items()}`. */
function strMap(d: Json): Record<string, string> {
  return orderedMap(orderedEntries(d).map(([k, v]) => [k, pyStr(v)] as [string, string]));
}

function parseTool(t: Json): MCPTool {
  const schema = pyOr(pyOr(get(t, "inputSchema"), get(t, "input_schema")), {});
  const output = pyOr(pyOr(get(t, "outputSchema"), get(t, "output_schema")), {});
  const annotations = pyOr(get(t, "annotations"), {});
  return {
    name: getStr(t, "name"),
    description: getStr(t, "description"),
    inputSchema: asRecord(schema) ?? {},
    title: pyStr(pyOr(get(t, "title"), "")),
    annotations: asRecord(annotations) ?? {},
    outputSchema: asRecord(output) ?? {},
  };
}

function parsePrompt(p: Json): MCPPrompt {
  const args = orderedMap(
    asArray(get(p, "arguments")).map((a) => [getStr(a, "name"), getStr(a, "description")] as [string, string]),
  );
  return { name: getStr(p, "name"), description: getStr(p, "description"), arguments: args };
}

export function parseManifest(data: Json): MCPManifest {
  return {
    instructions: getStr(data, "instructions"),
    tools: asArray(get(data, "tools")).map(parseTool),
    resources: asArray(get(data, "resources")).map((r) => ({
      uri: getStr(r, "uri"),
      name: getStr(r, "name"),
      description: getStr(r, "description"),
    })),
    prompts: asArray(get(data, "prompts")).map(parsePrompt),
  };
}

const TRANSPORTS: readonly Transport[] = ["stdio", "http", "sse", "unknown"];

function inferTransport(command: unknown, url: unknown, declared: unknown): Transport {
  if (typeof declared === "string") {
    const d = declared.toLowerCase() as Transport;
    if (TRANSPORTS.includes(d)) return d;
  }
  if (pyTruthy(command)) return "stdio";
  if (typeof url === "string") return url.replace(/\/+$/, "").endsWith("sse") ? "sse" : "http";
  return "unknown";
}

/** Python: `tuple(str(a) for a in raw_args if a is not None) if isinstance(raw_args, list) else ()`. */
function parseArgs(entry: Json): string[] {
  const raw = get(entry, "args");
  if (!Array.isArray(raw)) return [];
  return raw.filter((a) => a !== null && a !== undefined).map(pyStr);
}

function parseServer(name: string, entry: Json): MCPServerSpec {
  const command = get(entry, "command");
  const url = get(entry, "url");

  const rawEnv = asRecord(get(entry, "env"));
  const rawHeaders = asRecord(get(entry, "headers"));

  const hasManifest = has(entry, "tools") || has(entry, "instructions");
  return {
    name,
    transport: inferTransport(command, url, get(entry, "type")),
    command: pyTruthy(command) ? pyStr(command) : null,
    args: parseArgs(entry),
    env: rawEnv ? strMap(rawEnv) : {},
    url: pyTruthy(url) ? pyStr(url) : null,
    headers: rawHeaders ? strMap(rawHeaders) : {},
    manifest: hasManifest ? parseManifest(entry) : null,
  };
}

export function parseConfig(data: Json): MCPServerSpec[] {
  const serversMap = asRecord(pyOr(get(data, "mcpServers"), get(data, "servers")));
  if (serversMap) {
    return orderedEntries(serversMap)
      .filter(([, entry]) => asRecord(entry))
      .map(([name, entry]) => parseServer(name, entry as Json));
  }

  // A bare manifest (tools/instructions but no launch info).
  if ((has(data, "tools") || has(data, "instructions")) && !has(data, "command") && !has(data, "url")) {
    return [
      {
        name: getStr(data, "name", "manifest"),
        transport: "unknown",
        command: null,
        args: [],
        env: {},
        url: null,
        headers: {},
        manifest: parseManifest(data),
      },
    ];
  }

  // A single inline server object.
  if (has(data, "command") || has(data, "url")) {
    return [parseServer(getStr(data, "name", "server"), data)];
  }

  throw new ConfigError(
    "Unrecognized config: expected an 'mcpServers'/'servers' map, a server object with 'command'/'url', or a manifest with 'tools'.",
  );
}

/** Parse a JSON string into server specs, with friendly errors. */
export function parseConfigText(text: string): MCPServerSpec[] {
  let data: unknown;
  try {
    data = parseJson(text); // JSON.parse + Python dict key order
  } catch (e) {
    if (e instanceof JsonTooDeepError) throw new ConfigError("Config is nested too deeply to be an MCP config.");
    throw new ConfigError(`Not valid JSON: ${(e as Error).message}`);
  }
  const record = asRecord(data);
  if (!record) throw new ConfigError("Top-level JSON must be an object.");
  return parseConfig(record);
}
