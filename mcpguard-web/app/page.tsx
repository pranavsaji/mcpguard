import { Dashboard } from "@/components/Dashboard";
import { ENGINE_VERSION, RULE_CATALOG } from "@/lib/scanner";

export default function Home() {
  return (
    <main className="mx-auto w-full max-w-7xl flex-1 px-5 py-8 sm:px-8">
      {/* Header */}
      <header className="mb-8 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="flex items-center gap-2.5">
            <span className="grid h-9 w-9 place-items-center rounded-lg bg-sky-500/15 text-lg ring-1 ring-sky-500/30">
              🛡️
            </span>
            <h1 className="text-2xl font-bold tracking-tight text-slate-50">MCPGuard</h1>
            <span className="rounded-full bg-slate-700/40 px-2 py-0.5 font-mono text-[11px] text-slate-400">
              v{ENGINE_VERSION}
            </span>
          </div>
          <p className="mt-2 max-w-2xl text-sm text-slate-400">
            Security scanner for{" "}
            <span className="text-slate-200">Model Context Protocol</span> servers — the{" "}
            <span className="font-mono text-slate-300">npm audit</span> for MCP. Catches tool
            poisoning, prompt injection, tool shadowing, toxic data flows, excessive agency, leaked
            secrets, vulnerable or malicious packages, dangerous launch configs, and insecure
            transport.
          </p>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {RULE_CATALOG.map((r) => (
            <span
              key={r.id}
              title={`${r.name} — maps to ${r.maps}`}
              className="rounded-md border border-[var(--color-border)] bg-[var(--color-panel)]/60 px-2 py-1 font-mono text-[11px] text-slate-400"
            >
              {r.id}
            </span>
          ))}
        </div>
      </header>

      <Dashboard />

      <footer className="mt-12 border-t border-[var(--color-border)] pt-5 text-xs text-slate-500">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
          <span>
            Findings map to OWASP LLM Top 10, OWASP Agentic Top 10, and 2026 MCP CVE classes.
          </span>
          <span className="font-mono">POST /api/scan {"{ config, gate }"}</span>
        </div>
      </footer>
    </main>
  );
}
