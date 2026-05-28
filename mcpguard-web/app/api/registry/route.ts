import { REGISTRY_BASE, type RegistryServer, toPublicServer } from "@/lib/registry";

/**
 * GET /api/registry?search=<q>&limit=<n>
 * Server-side proxy to the official MCP Registry (avoids browser CORS and lets
 * us synthesize a scannable config per server). Returns { servers: PublicServer[] }.
 */
export async function GET(request: Request): Promise<Response> {
  const { searchParams } = new URL(request.url);
  const search = searchParams.get("search")?.trim() ?? "";
  const limit = Math.min(Math.max(Number(searchParams.get("limit")) || 30, 1), 60);

  const upstream = new URL(`${REGISTRY_BASE}/servers`);
  upstream.searchParams.set("limit", String(limit));
  if (search) upstream.searchParams.set("search", search);

  try {
    const res = await fetch(upstream, {
      headers: { accept: "application/json" },
      next: { revalidate: 300 },
      signal: AbortSignal.timeout(12_000),
    });
    if (!res.ok) {
      return Response.json({ error: `Registry returned ${res.status}` }, { status: 502 });
    }
    const data = (await res.json()) as {
      servers?: Array<{ server?: RegistryServer; _meta?: Record<string, unknown> }>;
    };

    // Keep the latest active version of each named server.
    const latest = new Map<string, ReturnType<typeof toPublicServer>>();
    for (const item of data.servers ?? []) {
      if (!item.server?.name) continue;
      const meta = item._meta?.["io.modelcontextprotocol.registry/official"] as
        | { isLatest?: boolean; status?: string }
        | undefined;
      if (meta && meta.isLatest === false) continue;
      const pub = toPublicServer(item.server);
      latest.set(item.server.name, pub);
    }

    return Response.json({ servers: [...latest.values()] });
  } catch (e) {
    return Response.json(
      { error: `Could not reach the MCP registry: ${(e as Error).message}` },
      { status: 502 },
    );
  }
}
