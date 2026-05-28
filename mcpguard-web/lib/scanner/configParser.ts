/**
 * Parse MCP config / manifest JSON into server specs (TypeScript port).
 * Accepts the same shapes as the Python engine: `mcpServers`/`servers` maps,
 * a single inline server, or a bare tool manifest.
 */

import type {
  MCPManifest,
  MCPServerSpec,
  MCPTool,
  Transport,
} from "./types";

export class ConfigError extends Error {}

type Json = Record<string, unknown>;

function asRecord(value: unknown): Json | null {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Json) : null;
}

function asArray(value: unknown): Json[] {
  if (!Array.isArray(value)) return [];
  return value.filter((v): v is Json => !!asRecord(v));
}

function str(value: unknown, fallback = ""): string {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return fallback;
}

export function parseManifest(data: Json): MCPManifest {
  const tools: MCPTool[] = asArray(data.tools).map((t) => {
    const schema = (t.inputSchema ?? t.input_schema) as unknown;
    return {
      name: str(t.name),
      description: str(t.description),
      inputSchema: asRecord(schema) ?? {},
    };
  });
  return {
    instructions: str(data.instructions),
    tools,
    resources: asArray(data.resources).map((r) => ({
      uri: str(r.uri),
      name: str(r.name),
      description: str(r.description),
    })),
    prompts: asArray(data.prompts).map((p) => ({
      name: str(p.name),
      description: str(p.description),
    })),
  };
}

function inferTransport(command: unknown, url: unknown, declared: unknown): Transport {
  if (typeof declared === "string") {
    const d = declared.toLowerCase();
    if (d === "stdio" || d === "http" || d === "sse") return d;
  }
  if (command) return "stdio";
  if (typeof url === "string") return url.replace(/\/+$/, "").endsWith("sse") ? "sse" : "http";
  return "unknown";
}

function parseServer(name: string, entry: Json): MCPServerSpec {
  const command = entry.command;
  const args = Array.isArray(entry.args) ? entry.args.map((a) => str(a)).filter(Boolean) : [];
  const env: Record<string, string> = {};
  const rawEnv = asRecord(entry.env);
  if (rawEnv) for (const [k, v] of Object.entries(rawEnv)) env[k] = str(v);

  const hasManifest = "tools" in entry || "instructions" in entry;
  return {
    name,
    transport: inferTransport(command, entry.url, entry.type),
    command: command ? str(command) : null,
    args,
    env,
    url: entry.url ? str(entry.url) : null,
    manifest: hasManifest ? parseManifest(entry) : null,
  };
}

export function parseConfig(data: Json): MCPServerSpec[] {
  const serversMap = asRecord(data.mcpServers) ?? asRecord(data.servers);
  if (serversMap) {
    return Object.entries(serversMap)
      .filter(([, entry]) => asRecord(entry))
      .map(([name, entry]) => parseServer(name, entry as Json));
  }

  if (("tools" in data || "instructions" in data) && !("command" in data) && !("url" in data)) {
    return [
      {
        name: str(data.name, "manifest"),
        transport: "unknown",
        command: null,
        args: [],
        env: {},
        url: null,
        manifest: parseManifest(data),
      },
    ];
  }

  if ("command" in data || "url" in data) {
    return [parseServer(str(data.name, "server"), data)];
  }

  throw new ConfigError(
    "Unrecognized config: expected an 'mcpServers'/'servers' map, a server object with 'command'/'url', or a manifest with 'tools'.",
  );
}

/** Parse a JSON string into server specs, with friendly errors. */
export function parseConfigText(text: string): MCPServerSpec[] {
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch (e) {
    throw new ConfigError(`Not valid JSON: ${(e as Error).message}`);
  }
  const record = asRecord(data);
  if (!record) throw new ConfigError("Top-level JSON must be an object.");
  return parseConfig(record);
}
