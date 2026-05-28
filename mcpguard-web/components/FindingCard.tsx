import { useState } from "react";
import type { Finding } from "@/lib/scanner/types";
import { SEVERITY_STYLE } from "@/lib/ui";
import { SeverityBadge } from "./SeverityBadge";

function locationString(loc: Finding["location"]): string {
  const parts: string[] = [];
  if (loc.server) parts.push(`server=${loc.server}`);
  if (loc.tool) parts.push(`tool=${loc.tool}`);
  if (loc.field) parts.push(`field=${loc.field}`);
  if (loc.path) parts.push(loc.line != null ? `${loc.path}:${loc.line}` : loc.path);
  return parts.join("  ") || "—";
}

export function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const accent = SEVERITY_STYLE[finding.severity];

  return (
    <div
      className={`animate-in rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-2)] ${accent.ring}`}
    >
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-start gap-3 px-4 py-3 text-left"
      >
        <span className={`mt-0.5 h-8 w-1 shrink-0 rounded-full ${accent.dot}`} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            <span className="rounded bg-slate-700/40 px-1.5 py-0.5 font-mono text-xs text-slate-300">
              {finding.rule_id}
            </span>
            <span className="font-medium text-slate-100">{finding.title}</span>
          </div>
          <div className="mono mt-1 truncate text-xs text-[var(--color-muted)]">
            {locationString(finding.location)}
          </div>
        </div>
        <svg
          className={`mt-1 h-4 w-4 shrink-0 text-slate-500 transition-transform ${open ? "rotate-180" : ""}`}
          viewBox="0 0 20 20"
          fill="currentColor"
        >
          <path
            fillRule="evenodd"
            d="M5.23 7.21a.75.75 0 011.06.02L10 11.17l3.71-3.94a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z"
          />
        </svg>
      </button>

      {open && (
        <div className="space-y-3 border-t border-[var(--color-border)] px-4 py-3 pl-8 text-sm">
          <div>
            <div className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">
              Evidence
            </div>
            <code className="mono block rounded bg-black/40 px-3 py-2 text-xs text-amber-200/90">
              {finding.evidence}
            </code>
          </div>
          <div>
            <div className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">
              Remediation
            </div>
            <p className="text-slate-300">{finding.remediation}</p>
          </div>
          {finding.mappings.length > 0 && (
            <div className="flex flex-wrap items-center gap-1.5">
              {finding.mappings.map((m) => (
                <span
                  key={m}
                  className="mono rounded bg-slate-700/30 px-1.5 py-0.5 text-[11px] text-slate-400"
                >
                  {m}
                </span>
              ))}
              {finding.confidence < 1 && (
                <span className="ml-auto text-[11px] text-slate-500">
                  confidence {Math.round(finding.confidence * 100)}%
                </span>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
