"use client";

import { useMemo, useRef, useState } from "react";
import { ConfigError, parseConfigText } from "@/lib/scanner/configParser";
import { scanSpecs } from "@/lib/scanner/scan";
import type { MCPServerSpec, ScanReport, Severity } from "@/lib/scanner/types";
import { SAMPLES, loadSampleText } from "@/lib/samples";
import { SEVERITY_ORDER, SEVERITY_STYLE } from "@/lib/ui";
import { FindingCard } from "./FindingCard";
import { RegistryBrowser } from "./RegistryBrowser";
import { ServerInventory } from "./ServerInventory";

const GATES: Severity[] = ["info", "low", "medium", "high", "critical"];

export function Dashboard() {
  const [configText, setConfigText] = useState("");
  const [gate, setGate] = useState<Severity>("high");
  const [report, setReport] = useState<ScanReport | null>(null);
  const [specs, setSpecs] = useState<MCPServerSpec[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [activeSeverities, setActiveSeverities] = useState<Set<Severity>>(new Set());
  const [query, setQuery] = useState("");
  const fileRef = useRef<HTMLInputElement>(null);

  function runScan(text: string, g: Severity = gate) {
    setError(null);
    if (!text.trim()) {
      setReport(null);
      setSpecs([]);
      setError("Paste an MCP config or load a sample to scan.");
      return;
    }
    try {
      const parsed = parseConfigText(text);
      setSpecs(parsed);
      setReport(scanSpecs(parsed, g));
      setActiveSeverities(new Set());
    } catch (e) {
      setReport(null);
      setSpecs([]);
      setError(e instanceof ConfigError ? e.message : "Unexpected error while scanning.");
    }
  }

  async function loadSample(id: string) {
    try {
      const text = await loadSampleText(id);
      setConfigText(text);
      runScan(text);
    } catch {
      setError("Could not load that sample.");
    }
  }

  function onUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    file.text().then((text) => {
      setConfigText(text);
      runScan(text);
    });
  }

  function toggleSeverity(s: Severity) {
    setActiveSeverities((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  }

  function exportJson() {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "mcpguard-report.json";
    a.click();
    URL.revokeObjectURL(url);
  }

  const totals = report?.summary.by_severity ?? {};
  const totalFindings = report?.summary.total_findings ?? 0;

  const filtered = useMemo(() => {
    if (!report) return [];
    const q = query.trim().toLowerCase();
    return report.results.map((target) => ({
      ...target,
      findings: target.findings.filter((f) => {
        if (activeSeverities.size && !activeSeverities.has(f.severity)) return false;
        if (!q) return true;
        return (
          f.title.toLowerCase().includes(q) ||
          f.rule_id.toLowerCase().includes(q) ||
          f.evidence.toLowerCase().includes(q) ||
          (f.location.tool ?? "").toLowerCase().includes(q)
        );
      }),
    }));
  }, [report, activeSeverities, query]);

  const visibleCount = filtered.reduce((n, t) => n + t.findings.length, 0);

  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,420px)_minmax(0,1fr)]">
      {/* ---- Input panel ---- */}
      <section className="rounded-xl border border-[var(--color-border)] bg-[var(--color-panel)]/70 p-4 backdrop-blur">
        <div className="mb-3 flex items-center justify-between gap-2">
          <h2 className="text-sm font-semibold text-slate-200">MCP configuration</h2>
          <RegistryBrowser
            onPick={(text) => {
              setConfigText(text);
              runScan(text);
            }}
          />
        </div>

        <div className="mb-3">
          <div className="mb-1.5 text-[11px] font-medium uppercase tracking-wide text-slate-500">
            Load a sample
          </div>
          <div className="flex flex-wrap gap-1.5">
            {SAMPLES.map((s) => (
              <button
                key={s.id}
                onClick={() => loadSample(s.id)}
                title={s.hint}
                className={`rounded-md px-2 py-1 text-xs font-medium ring-1 transition ${
                  s.expect === "clean"
                    ? "bg-emerald-500/10 text-emerald-300 ring-emerald-500/30 hover:bg-emerald-500/20"
                    : "bg-red-500/10 text-red-300 ring-red-500/30 hover:bg-red-500/20"
                }`}
              >
                {s.label}
              </button>
            ))}
          </div>
        </div>

        <textarea
          value={configText}
          onChange={(e) => setConfigText(e.target.value)}
          spellCheck={false}
          placeholder={'{\n  "mcpServers": {\n    "my-server": { "command": "npx", "args": ["-y", "@scope/server"] }\n  }\n}'}
          className="h-72 w-full resize-y rounded-lg border border-[var(--color-border)] bg-black/30 p-3 text-xs leading-relaxed text-slate-200 outline-none ring-sky-500/0 transition focus:border-sky-500/50 focus:ring-2 focus:ring-sky-500/20"
        />

        <div className="mt-3 flex flex-wrap items-center gap-2">
          <button
            onClick={() => runScan(configText)}
            className="rounded-lg bg-sky-500 px-4 py-2 text-sm font-semibold text-white shadow-lg shadow-sky-500/20 transition hover:bg-sky-400 active:scale-[0.98]"
          >
            Scan
          </button>
          <button
            onClick={() => fileRef.current?.click()}
            className="rounded-lg border border-[var(--color-border)] px-3 py-2 text-sm text-slate-300 transition hover:bg-white/5"
          >
            Upload file
          </button>
          <input
            ref={fileRef}
            type="file"
            accept=".json,application/json"
            onChange={onUpload}
            className="hidden"
          />
          <label className="ml-auto flex items-center gap-2 text-xs text-slate-400">
            Gate
            <select
              value={gate}
              onChange={(e) => {
                const g = e.target.value as Severity;
                setGate(g);
                if (configText.trim()) runScan(configText, g);
              }}
              className="rounded-md border border-[var(--color-border)] bg-[var(--color-panel-2)] px-2 py-1 text-xs text-slate-200 outline-none"
            >
              {GATES.map((g) => (
                <option key={g} value={g}>
                  ≥ {g}
                </option>
              ))}
            </select>
          </label>
        </div>

        {error && (
          <p className="mt-3 rounded-md bg-red-500/10 px-3 py-2 text-xs text-red-300 ring-1 ring-red-500/30">
            {error}
          </p>
        )}

        <p className="mt-4 text-[11px] leading-relaxed text-slate-500">
          Detects tool poisoning, hidden content, excessive agency, leaked secrets, and unpinned
          launches. Source-level RCE (CMD01) and live rug-pull (MAN01) checks run in the{" "}
          <span className="font-mono text-slate-400">mcpguard</span> CLI. Everything runs locally in
          your browser — no config is uploaded.
        </p>
      </section>

      {/* ---- Results ---- */}
      <section className="min-w-0">
        {!report ? (
          <EmptyState />
        ) : (
          <div className="space-y-5">
            {/* Summary bar */}
            <div className="flex flex-wrap items-center gap-3 rounded-xl border border-[var(--color-border)] bg-[var(--color-panel)]/70 p-4 backdrop-blur">
              <span
                className={`inline-flex items-center gap-2 rounded-lg px-3 py-1.5 text-sm font-bold ${
                  report.ok
                    ? "bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/40"
                    : "bg-red-500/15 text-red-300 ring-1 ring-red-500/40"
                }`}
              >
                {report.ok ? "PASS" : "FAIL"}
                <span className="font-normal opacity-70">gate ≥ {report.gate}</span>
              </span>

              <div className="flex flex-wrap items-center gap-2">
                {SEVERITY_ORDER.map((s) =>
                  totals[s] ? (
                    <button
                      key={s}
                      onClick={() => toggleSeverity(s)}
                      className={`inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-xs font-semibold transition ${
                        SEVERITY_STYLE[s].badge
                      } ${activeSeverities.size && !activeSeverities.has(s) ? "opacity-35" : ""}`}
                    >
                      <span className={`h-1.5 w-1.5 rounded-full ${SEVERITY_STYLE[s].dot}`} />
                      {totals[s]} {s}
                    </button>
                  ) : null,
                )}
              </div>

              <div className="ml-auto flex items-center gap-2">
                <span className="text-xs text-slate-400">
                  {totalFindings} finding{totalFindings === 1 ? "" : "s"} ·{" "}
                  {report.summary.targets} target{report.summary.targets === 1 ? "" : "s"}
                </span>
                <button
                  onClick={exportJson}
                  className="rounded-md border border-[var(--color-border)] px-2.5 py-1 text-xs text-slate-300 transition hover:bg-white/5"
                >
                  Export JSON
                </button>
              </div>
            </div>

            {/* Server inventory — every server, including clean ones */}
            <ServerInventory specs={specs} report={report} />

            {/* Filter row */}
            {totalFindings > 0 && (
              <div className="flex items-center gap-3">
                <input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Filter by rule, tool, title, evidence…"
                  className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-2)] px-3 py-2 text-sm text-slate-200 outline-none transition focus:border-sky-500/50"
                />
                {(activeSeverities.size > 0 || query) && (
                  <button
                    onClick={() => {
                      setActiveSeverities(new Set());
                      setQuery("");
                    }}
                    className="shrink-0 text-xs text-slate-400 underline-offset-2 hover:underline"
                  >
                    Clear filters
                  </button>
                )}
              </div>
            )}

            {/* Per-target findings */}
            {filtered.map((target) => {
              const spec = specs.find((s) => s.name === target.target);
              const isRemote = spec?.transport === "http" || spec?.transport === "sse";
              return (
              <div
                key={target.target}
                id={`target-${target.target.replace(/[^a-zA-Z0-9_-]/g, "-")}`}
                className="scroll-mt-4 space-y-2"
              >
                <div className="flex items-center gap-2 text-sm">
                  <span className="text-slate-500">▸</span>
                  <span className="font-semibold text-slate-100">{target.target}</span>
                  <span className="text-xs text-slate-500">
                    {target.summary.total} finding{target.summary.total === 1 ? "" : "s"}
                  </span>
                </div>
                {target.findings.length === 0 ? (
                  <p className="rounded-lg border border-dashed border-[var(--color-border)] px-4 py-3 text-sm text-slate-500">
                    {target.summary.total > 0
                      ? "No findings match the current filters."
                      : isRemote
                        ? "Remote/hosted server — no local command, secrets, or tool manifest to statically scan. Static checks pass by definition; tool-poisoning & excessive-agency checks need a live connection (mcpguard --connect)."
                        : "No findings — clean ✓"}
                  </p>
                ) : (
                  <div className="space-y-2">
                    {target.findings.map((f, i) => (
                      <FindingCard key={`${f.rule_id}-${i}`} finding={f} />
                    ))}
                  </div>
                )}
              </div>
              );
            })}

            {report.results.length > 0 && visibleCount === 0 && totalFindings > 0 && (
              <p className="text-center text-sm text-slate-500">No findings match the filters.</p>
            )}
          </div>
        )}
      </section>
    </div>
  );
}

function EmptyState() {
  return (
    <div className="flex h-full min-h-72 flex-col items-center justify-center rounded-xl border border-dashed border-[var(--color-border)] bg-[var(--color-panel)]/30 p-10 text-center">
      <div className="mb-3 text-4xl">🛡️</div>
      <h3 className="text-lg font-semibold text-slate-200">Scan an MCP server</h3>
      <p className="mt-1 max-w-sm text-sm text-slate-500">
        Paste a config, upload a file, or load a sample. Results appear here with severity, evidence,
        and a fix for each finding.
      </p>
    </div>
  );
}
