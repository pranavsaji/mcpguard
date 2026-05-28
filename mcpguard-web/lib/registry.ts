/**
 * Official MCP Registry integration (registry.modelcontextprotocol.io).
 *
 * Turns a registry server record into a scannable MCP config so a user can pick
 * a real, public server and run it through the scanner. Synthesis mirrors how
 * people actually configure these servers (e.g. `npx -y <pkg>`, secrets as
 * `${ENV}` references), so findings reflect real-world setups.
 */

export const REGISTRY_BASE = "https://registry.modelcontextprotocol.io/v0";

export type ServerKind = "npm" | "pypi" | "oci" | "remote" | "unknown";

interface RegistryEnvVar {
  name: string;
  description?: string;
  isRequired?: boolean;
  isSecret?: boolean;
}

interface RegistryArg {
  type?: "positional" | "named";
  value?: string;
  name?: string;
}

interface RegistryPackage {
  registryType?: string;
  identifier?: string;
  version?: string;
  runtimeHint?: string;
  transport?: { type?: string };
  runtimeArguments?: RegistryArg[];
  packageArguments?: RegistryArg[];
  environmentVariables?: RegistryEnvVar[];
}

interface RegistryRemote {
  type?: string;
  url?: string;
}

export interface RegistryServer {
  name: string;
  title?: string;
  description?: string;
  version?: string;
  repository?: { url?: string; source?: string };
  packages?: RegistryPackage[];
  remotes?: RegistryRemote[];
}

/** What the browser UI consumes: a card + a ready-to-scan config string. */
export interface PublicServer {
  id: string;
  name: string;
  title: string;
  description: string;
  version: string;
  kind: ServerKind;
  repo: string | null;
  configText: string;
}

/** A short, human key for the mcpServers map (last path segment). */
export function shortKey(name: string): string {
  const tail = name.split("/").pop() ?? name;
  return tail.replace(/[^a-zA-Z0-9_-]/g, "-") || "server";
}

function runtimeFor(pkg: RegistryPackage): string {
  if (pkg.runtimeHint) return pkg.runtimeHint;
  switch (pkg.registryType) {
    case "npm":
      return "npx";
    case "pypi":
      return "uvx";
    case "oci":
      return "docker";
    default:
      return "npx";
  }
}

function argValues(args: RegistryArg[] | undefined): string[] {
  if (!args) return [];
  return args
    .map((a) => (a.type === "named" && a.name ? a.name : a.value))
    .filter((v): v is string => typeof v === "string" && v.length > 0);
}

function envMap(vars: RegistryEnvVar[] | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const v of vars ?? []) {
    if (v.name) out[v.name] = `\${${v.name}}`; // reference, never a hardcoded value
  }
  return out;
}

export function kindOf(server: RegistryServer): ServerKind {
  const pkg = server.packages?.[0];
  if (pkg) {
    const t = pkg.registryType;
    if (t === "npm" || t === "pypi" || t === "oci") return t;
    return "unknown";
  }
  if (server.remotes?.length) return "remote";
  return "unknown";
}

/** Build an mcpServers config (as JSON text) for a registry server. */
export function synthesizeConfig(server: RegistryServer): string {
  const key = shortKey(server.name);
  const pkg = server.packages?.[0];

  let entry: Record<string, unknown>;
  if (pkg?.identifier) {
    const command = runtimeFor(pkg);
    const args = [...argValues(pkg.runtimeArguments)];
    if (command === "docker") args.push("run", "-i", "--rm");
    args.push(pkg.identifier); // unpinned, as the documented install commands are
    args.push(...argValues(pkg.packageArguments));
    entry = { command, args };
    const env = envMap(pkg.environmentVariables);
    if (Object.keys(env).length) entry.env = env;
  } else if (server.remotes?.length) {
    const remote = server.remotes[0];
    entry = { url: remote.url ?? "", type: remote.type === "sse" ? "sse" : "http" };
  } else {
    entry = { command: "echo", args: ["no launch metadata in registry"] };
  }

  return JSON.stringify({ mcpServers: { [key]: entry } }, null, 2);
}

export function toPublicServer(server: RegistryServer): PublicServer {
  return {
    id: `${server.name}@${server.version ?? "0"}`,
    name: server.name,
    title: server.title || shortKey(server.name),
    description: server.description ?? "",
    version: server.version ?? "",
    kind: kindOf(server),
    repo: server.repository?.url ?? null,
    configText: synthesizeConfig(server),
  };
}
