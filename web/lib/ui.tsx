import type { ReactNode } from "react";
import type { FindingState, Severity } from "./types";

export const SEV_COLOR: Record<Severity, string> = {
  critical: "var(--crit)", high: "var(--high)", medium: "var(--med)",
  low: "var(--low)", info: "var(--info)", unknown: "var(--faint)",
};

const SEV_BG: Record<Severity, string> = {
  critical: "rgba(244,63,94,.14)", high: "rgba(251,146,60,.14)",
  medium: "rgba(234,179,8,.14)", low: "rgba(56,189,248,.14)",
  info: "rgba(100,116,139,.14)", unknown: "rgba(92,107,122,.12)",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  const s = (severity || "unknown") as Severity;
  return (
    <span className="inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide"
      style={{ color: SEV_COLOR[s], background: SEV_BG[s], border: `1px solid ${SEV_COLOR[s]}33` }}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: SEV_COLOR[s] }} />
      {s}
    </span>
  );
}

const STATE_STYLE: Record<FindingState, { label: string; color: string }> = {
  DISCOVERED: { label: "Discovered", color: "var(--faint)" },
  CANDIDATE: { label: "Candidate", color: "var(--low)" },
  TRIAGED: { label: "Triaged", color: "var(--low)" },
  VALIDATION_PENDING: { label: "Validation pending", color: "var(--med)" },
  VALIDATED: { label: "Validated", color: "var(--accent)" },
  HUMAN_CONFIRMED: { label: "Confirmed", color: "var(--crit)" },
  FALSE_POSITIVE: { label: "False positive", color: "var(--faint)" },
};

export function StateBadge({ state }: { state: FindingState }) {
  const s = STATE_STYLE[state] ?? { label: state, color: "var(--faint)" };
  return (
    <span className="mono inline-flex items-center rounded border px-2 py-0.5 text-[11px]"
      style={{ color: s.color, borderColor: `${s.color}44` }}>
      {s.label}
    </span>
  );
}

export function MethodBadge({ method }: { method: string }) {
  const map: Record<string, string> = {
    taint: "cross-file taint", source_audit: "per-file audit",
    secrets: "secrets", recon: "recon",
  };
  return (
    <span className="mono rounded border border-border px-1.5 py-0.5 text-[11px] text-muted">
      {map[method] ?? method}
    </span>
  );
}

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <div className={`card p-4 ${className}`}>{children}</div>;
}

export function Stat({ label, value, accent, delay }: { label: string; value: ReactNode; accent?: string; delay?: number }) {
  return (
    <div className="card rise px-4 py-3" style={delay ? { animationDelay: `${delay}ms` } : undefined}>
      <div className="text-[11px] uppercase tracking-wide text-faint">{label}</div>
      <div className="mt-1 text-2xl font-semibold" style={accent ? { color: accent } : undefined}>{value}</div>
    </div>
  );
}

export function cls(...xs: (string | false | null | undefined)[]) {
  return xs.filter(Boolean).join(" ");
}
