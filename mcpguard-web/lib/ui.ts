import type { Severity } from "@/lib/scanner/types";

/** Tailwind class bundles per severity, used by badges and accents. */
export const SEVERITY_STYLE: Record<
  Severity,
  { badge: string; dot: string; ring: string; text: string; label: string }
> = {
  critical: {
    badge: "bg-red-500/15 text-red-300 ring-1 ring-red-500/40",
    dot: "bg-red-500",
    ring: "ring-red-500/40",
    text: "text-red-300",
    label: "Critical",
  },
  high: {
    badge: "bg-orange-500/15 text-orange-300 ring-1 ring-orange-500/40",
    dot: "bg-orange-500",
    ring: "ring-orange-500/40",
    text: "text-orange-300",
    label: "High",
  },
  medium: {
    badge: "bg-amber-400/15 text-amber-300 ring-1 ring-amber-400/40",
    dot: "bg-amber-400",
    ring: "ring-amber-400/40",
    text: "text-amber-300",
    label: "Medium",
  },
  low: {
    badge: "bg-sky-500/15 text-sky-300 ring-1 ring-sky-500/40",
    dot: "bg-sky-500",
    ring: "ring-sky-500/40",
    text: "text-sky-300",
    label: "Low",
  },
  info: {
    badge: "bg-slate-500/15 text-slate-300 ring-1 ring-slate-500/40",
    dot: "bg-slate-500",
    ring: "ring-slate-500/40",
    text: "text-slate-300",
    label: "Info",
  },
};

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
