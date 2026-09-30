import { timingSafeEqual } from "node:crypto";
import { aiScanSpecs } from "@/lib/ai/aiScan";
import { AI_CHOICES, type AIChoice, availableJudges, buildJudge } from "@/lib/ai/build";
import { AIConfig, JudgeError } from "@/lib/ai/judge";
import { ConfigError, parseConfigText } from "@/lib/scanner";
import { SEVERITIES, type Severity } from "@/lib/scanner/types";

/**
 * Server-side AI scan. The browser engine can't call Jev / Claude — API keys must
 * never reach the client — so the dashboard posts here when "AI judge" is on.
 *
 * GET  /api/ai-scan  -> { available: { jev, claude }, tokenRequired }
 * POST /api/ai-scan  { config: string, gate?: Severity, ai?: "auto"|"jev"|"claude"|"ensemble",
 *                      threshold?: number }  -> ScanReport (+ `ai` block)
 *
 * This route spends money on every call. It requires a bearer token
 * (MCPGUARD_AI_ROUTE_TOKEN) whenever one is set, and always in production unless
 * MCPGUARD_AI_ROUTE_PUBLIC=1 is set explicitly. Inputs are size-capped.
 */

export const runtime = "nodejs";
export const maxDuration = 120;

const MAX_CONFIG_BYTES = 256 * 1024;
const MAX_TOOLS = 300;

function tokenRequired(): boolean {
  if (process.env.MCPGUARD_AI_ROUTE_TOKEN?.trim()) return true;
  return process.env.NODE_ENV === "production" && process.env.MCPGUARD_AI_ROUTE_PUBLIC !== "1";
}

function authorized(request: Request): boolean {
  const expected = process.env.MCPGUARD_AI_ROUTE_TOKEN?.trim();
  if (!expected) return !tokenRequired(); // production without a token: closed
  const header = request.headers.get("authorization") ?? "";
  const given = header.startsWith("Bearer ") ? header.slice(7).trim() : (request.headers.get("x-mcpguard-token") ?? "");
  const a = Buffer.from(given);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

export async function GET(): Promise<Response> {
  return Response.json({ available: availableJudges(), tokenRequired: tokenRequired() });
}

export async function POST(request: Request): Promise<Response> {
  if (!authorized(request)) {
    return Response.json(
      { error: "AI scan requires a valid token (set MCPGUARD_AI_ROUTE_TOKEN on the server and send it as a Bearer token)." },
      { status: 401 },
    );
  }
  const length = Number(request.headers.get("content-length") ?? 0);
  if (length > MAX_CONFIG_BYTES * 2) {
    return Response.json({ error: "Request too large." }, { status: 413 });
  }
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: "Request body must be JSON." }, { status: 400 });
  }
  const { config, gate, ai, threshold } = (body ?? {}) as Record<string, unknown>;
  if (typeof config !== "string" || !config.trim()) {
    return Response.json({ error: "Field 'config' (JSON string) is required." }, { status: 400 });
  }
  if (Buffer.byteLength(config) > MAX_CONFIG_BYTES) {
    return Response.json({ error: `Config larger than ${MAX_CONFIG_BYTES / 1024} KB.` }, { status: 413 });
  }
  const gateSeverity: Severity =
    typeof gate === "string" && (SEVERITIES as readonly string[]).includes(gate) ? (gate as Severity) : "high";
  const choice: AIChoice =
    typeof ai === "string" && (AI_CHOICES as readonly string[]).includes(ai) ? (ai as AIChoice) : "auto";
  const aiThreshold = typeof threshold === "number" && threshold > 0 && threshold <= 1 ? threshold : 0.8;

  let specs;
  try {
    specs = parseConfigText(config);
  } catch (e) {
    if (e instanceof ConfigError) return Response.json({ error: e.message }, { status: 400 });
    return Response.json({ error: "Internal parse error." }, { status: 500 });
  }
  const toolCount = specs.reduce((n, s) => n + (s.manifest?.tools.length ?? 0), 0);
  if (toolCount > MAX_TOOLS) {
    return Response.json({ error: `Too many tools for an AI scan (${toolCount} > ${MAX_TOOLS}).` }, { status: 413 });
  }

  let aiConfig: AIConfig;
  try {
    aiConfig = new AIConfig(buildJudge(choice), aiThreshold);
  } catch (e) {
    const message = e instanceof JudgeError ? e.message : "Could not initialise the AI judge.";
    return Response.json({ error: message }, { status: 503 });
  }

  try {
    const report = await aiScanSpecs(specs, gateSeverity, aiConfig);
    return Response.json(
      { ...report, ai: { judge: aiConfig.judge.name, threshold: aiThreshold, errors: [...new Set(aiConfig.errors)] } },
      { headers: { "X-MCPGuard-OK": String(report.ok) } },
    );
  } catch {
    return Response.json({ error: "Internal AI scan error." }, { status: 500 });
  }
}
