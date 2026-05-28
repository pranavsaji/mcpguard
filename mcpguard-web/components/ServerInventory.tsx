import { commandLine, type MCPServerSpec, type ScanReport, type Severity } from "@/lib/scanner/types";
import { SEVERITY_STYLE } from "@/lib/ui";

function slug(name: string): string {
  return `target-${name.replace(/[^a-zA-Z0-9_-]/g, "-")}`;
}

const TRANSPORT_LABEL: Record<string, string> = {
  stdio: "stdio",
  http: "http",
  sse: "sse",
  unknown: "manifest",
};

/**
 * A compact inventory of *every* MCP server in the config — including clean
 * ones — so the full attack surface is visible at a glance. Each card jumps to
 * that server's findings.
 */
export function ServerInventory({
  specs,
  report,
}: {
  specs: MCPServerSpec[];
  report: ScanReport;
}) {
  const byName = new Map(report.results.map((r) => [r.target, r]));

  return (
    <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-panel)]/70 p-4 backdrop-blur">
      <div className="mb-3 flex items-center gap-2">
        <h2 className="text-sm font-semibold text-slate-200">Servers</h2>
        <span className="rounded-full bg-slate-700/40 px-2 py-0.5 text-[11px] text-slate-400">
          {specs.length}
        </span>
      </div>

      <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
        {specs.map((spec) => {
          const result = byName.get(spec.name);
          const total = result?.summary.total ?? 0;
          const worst = result?.summary.max_severity ?? null;
          const isRemote = spec.transport === "http" || spec.transport === "sse";
          const target = spec.url || commandLine(spec) || "—";

          return (
            <a
              key={spec.name}
              href={`#${slug(spec.name)}`}
              className="group flex flex-col gap-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-2)] p-3 transition hover:border-sky-500/40"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="truncate font-medium text-slate-100">{spec.name}</span>
                <StatusPill worst={worst} total={total} isRemote={isRemote} />
              </div>
              <div className="flex items-center gap-1.5">
                <span className="rounded bg-slate-700/40 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide text-slate-400">
                  {TRANSPORT_LABEL[spec.transport] ?? spec.transport}
                </span>
                <code className="mono truncate text-[11px] text-slate-500" title={target}>
                  {target}
                </code>
              </div>
            </a>
          );
        })}
      </div>
    </div>
  );
}

function StatusPill({
  worst,
  total,
  isRemote,
}: {
  worst: Severity | null;
  total: number;
  isRemote: boolean;
}) {
  if (total === 0 && isRemote) {
    return (
      <span
        title="Remote/hosted server — no local command, secrets, or tool manifest to statically scan. Connect to enumerate its tools."
        className="inline-flex shrink-0 items-center gap-1 rounded-md bg-slate-500/15 px-1.5 py-0.5 text-[11px] font-semibold text-slate-300 ring-1 ring-slate-500/40"
      >
        no local surface
      </span>
    );
  }
  if (total === 0 || worst === null) {
    return (
      <span className="inline-flex shrink-0 items-center gap-1 rounded-md bg-emerald-500/15 px-1.5 py-0.5 text-[11px] font-semibold text-emerald-300 ring-1 ring-emerald-500/40">
        clean ✓
      </span>
    );
  }
  const s = SEVERITY_STYLE[worst];
  return (
    <span
      className={`inline-flex shrink-0 items-center gap-1 rounded-md px-1.5 py-0.5 text-[11px] font-semibold ${s.badge}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} />
      {total}
    </span>
  );
}
