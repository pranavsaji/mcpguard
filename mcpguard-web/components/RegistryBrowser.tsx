"use client";

import { useCallback, useEffect, useState } from "react";
import type { PublicServer, ServerKind } from "@/lib/registry";

const KIND_STYLE: Record<ServerKind, string> = {
  npm: "bg-red-500/15 text-red-300 ring-red-500/30",
  pypi: "bg-sky-500/15 text-sky-300 ring-sky-500/30",
  oci: "bg-indigo-500/15 text-indigo-300 ring-indigo-500/30",
  remote: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30",
  unknown: "bg-slate-500/15 text-slate-300 ring-slate-500/30",
};

export function RegistryBrowser({
  onPick,
}: {
  onPick: (configText: string, label: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [servers, setServers] = useState<PublicServer[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (search: string) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/registry?limit=40${search ? `&search=${encodeURIComponent(search)}` : ""}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "Failed to load");
      // Installable servers (npm/pypi/oci) produce real findings; surface them
      // above remote/hosted servers which have no local surface to scan.
      const rank: Record<ServerKind, number> = { npm: 0, pypi: 1, oci: 2, remote: 3, unknown: 4 };
      const sorted = [...((data.servers ?? []) as PublicServer[])].sort(
        (a, b) => rank[a.kind] - rank[b.kind],
      );
      setServers(sorted);
    } catch (e) {
      setError((e as Error).message);
      setServers([]);
    } finally {
      setLoading(false);
    }
  }, []);

  // Load on open (immediately) and on search (debounced). One effect, no
  // synchronous setState in the effect body.
  useEffect(() => {
    if (!open) return;
    const t = setTimeout(() => load(query), query ? 350 : 0);
    return () => clearTimeout(t);
  }, [query, open, load]);

  return (
    <>
      <button
        onClick={() => setOpen(true)}
        className="flex items-center gap-1.5 rounded-md bg-indigo-500/10 px-2 py-1 text-xs font-medium text-indigo-300 ring-1 ring-indigo-500/30 transition hover:bg-indigo-500/20"
      >
        🌐 Browse public servers
      </button>

      {open && (
        <div
          className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 p-4 backdrop-blur-sm sm:p-8"
          onClick={() => setOpen(false)}
        >
          <div
            className="animate-in flex max-h-[85vh] w-full max-w-2xl flex-col overflow-hidden rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-[var(--color-border)] px-4 py-3">
              <div>
                <h2 className="text-sm font-semibold text-slate-100">Public MCP servers</h2>
                <p className="text-[11px] text-slate-500">
                  Live from the official MCP Registry · pick one to scan it ·{" "}
                  <span className="text-red-300/80">npm</span>/
                  <span className="text-sky-300/80">pypi</span> servers produce findings;{" "}
                  <span className="text-emerald-300/80">remote</span> ones have no local surface
                </p>
              </div>
              <button
                onClick={() => setOpen(false)}
                className="rounded-md px-2 py-1 text-slate-400 transition hover:bg-white/5 hover:text-slate-200"
              >
                ✕
              </button>
            </div>

            <div className="border-b border-[var(--color-border)] p-3">
              <input
                autoFocus
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search servers (e.g. github, filesystem, postgres)…"
                className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-2)] px-3 py-2 text-sm text-slate-200 outline-none transition focus:border-sky-500/50"
              />
            </div>

            <div className="flex-1 overflow-y-auto p-3">
              {loading && <p className="py-8 text-center text-sm text-slate-500">Loading…</p>}
              {error && (
                <p className="rounded-md bg-red-500/10 px-3 py-2 text-xs text-red-300 ring-1 ring-red-500/30">
                  {error}
                </p>
              )}
              {!loading && !error && servers.length === 0 && (
                <p className="py-8 text-center text-sm text-slate-500">No servers found.</p>
              )}
              <div className="space-y-2">
                {servers.map((s) => (
                  <button
                    key={s.id}
                    onClick={() => {
                      onPick(s.configText, s.title);
                      setOpen(false);
                    }}
                    className="group block w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-2)] p-3 text-left transition hover:border-sky-500/40"
                  >
                    <div className="flex items-center gap-2">
                      <span
                        className={`rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ring-1 ${KIND_STYLE[s.kind]}`}
                      >
                        {s.kind}
                      </span>
                      <span className="truncate font-medium text-slate-100">{s.title}</span>
                      <span className="ml-auto shrink-0 text-[11px] text-slate-500 opacity-0 transition group-hover:opacity-100">
                        Scan →
                      </span>
                    </div>
                    <p className="mono mt-1 truncate text-[11px] text-slate-500">{s.name}</p>
                    {s.description && (
                      <p className="mt-1 line-clamp-2 text-xs text-slate-400">{s.description}</p>
                    )}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
