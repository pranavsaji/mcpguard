import { ConfigError, scanConfigText } from "@/lib/scanner";
import { SEVERITIES, type Severity } from "@/lib/scanner/types";

/**
 * POST /api/scan
 * Body: { config: string (JSON text), gate?: "info"|"low"|"medium"|"high"|"critical" }
 * Returns: ScanReport JSON. HTTP 200 always when scannable; the `ok` field and
 * the `X-MCPGuard-OK` header carry the CI gate signal. 400 on bad input.
 */
export async function POST(request: Request): Promise<Response> {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: "Request body must be JSON." }, { status: 400 });
  }

  const { config, gate } = (body ?? {}) as { config?: unknown; gate?: unknown };
  if (typeof config !== "string" || !config.trim()) {
    return Response.json({ error: "Field 'config' (JSON string) is required." }, { status: 400 });
  }

  const threshold: Severity =
    typeof gate === "string" && (SEVERITIES as readonly string[]).includes(gate)
      ? (gate as Severity)
      : "high";

  try {
    const report = scanConfigText(config, threshold);
    return Response.json(report, {
      headers: { "X-MCPGuard-OK": String(report.ok) },
    });
  } catch (e) {
    if (e instanceof ConfigError) {
      return Response.json({ error: e.message }, { status: 400 });
    }
    return Response.json({ error: "Internal scan error." }, { status: 500 });
  }
}
