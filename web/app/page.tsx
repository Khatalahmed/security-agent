"use client";
import Link from "next/link";
import { api } from "@/lib/api";
import { useAsync } from "@/lib/use-async";
import { Stat, SeverityBadge, cls } from "@/lib/ui";
import { Loading, ErrorState, Empty, PageTitle } from "@/components/states";
import { ArchitectureCard } from "@/components/architecture-card";
import { ScanLine, Cpu, Lock, Clock } from "lucide-react";

export default function Overview() {
  const scans = useAsync(() => api.scans(), []);
  const cfg = useAsync(() => api.config(), []);

  if (scans.loading || cfg.loading) return <Loading label="Loading console…" />;
  if (scans.error) return <ErrorState message={scans.error} />;

  const all = scans.data ?? [];
  const latest = all[0];
  const totals = all.reduce(
    (a, s) => {
      (["critical", "high", "medium", "low", "info"] as const).forEach((k) => (a[k] += s.severity_counts?.[k] ?? 0));
      a.findings += s.findings; return a;
    },
    { critical: 0, high: 0, medium: 0, low: 0, info: 0, findings: 0 }
  );

  return (
    <div>
      <PageTitle title="Overview" subtitle="AI-assisted application security analysis — running locally."
        right={
          <Link href="/scan/new" className="flex items-center gap-2 rounded-md px-3 py-2 text-sm font-medium text-white"
            style={{ background: "var(--accent)" }}>
            <ScanLine size={15} /> Start Security Scan
          </Link>
        } />

      {/* local-first banner */}
      <div className="card mb-5 flex flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3">
        <div className="flex items-center gap-2 text-sm"><Cpu size={15} style={{ color: "var(--ok)" }} />
          <span className="text-muted">Inference</span> <b>{cfg.data?.provider} · {cfg.data?.model}</b></div>
        <div className="flex items-center gap-2 text-sm"><Lock size={15} style={{ color: "var(--ok)" }} />
          <span className="text-muted">Mode</span> <b>{cfg.data?.local_only ? "local-only (source stays on this machine)" : "hosted provider configured"}</b></div>
        <div className="mono ml-auto text-xs text-faint">ctx {cfg.data?.num_ctx} · skills: {cfg.data?.skills_enabled.join(", ")}</div>
      </div>

      <div className="grid gap-5 lg:grid-cols-[1fr_380px]">
        <div>
          <div className="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-3">
            <Stat label="Scans" value={all.length} delay={0} />
            <Stat label="Findings" value={totals.findings} delay={70} />
            <Stat label="Critical" value={totals.critical} accent="var(--crit)" delay={140} />
            <Stat label="High" value={totals.high} accent="var(--high)" delay={210} />
            <Stat label="Medium" value={totals.medium} accent="var(--med)" delay={280} />
            <Stat label="Low" value={totals.low} accent="var(--low)" delay={350} />
          </div>

          <div className="card p-4">
            <div className="mb-3 flex items-center justify-between">
              <div className="text-sm font-semibold">Recent scans</div>
              <Link href="/scans" className="text-xs text-accent hover:underline">view all</Link>
            </div>
            {all.length === 0 ? (
              <Empty title="No scans yet" hint="Run your first local security scan to populate the console." />
            ) : (
              <div className="space-y-1.5">
                {all.slice(0, 6).map((s) => (
                  <Link key={s.scan_id} href={`/scans`}
                    className="flex items-center gap-3 rounded-md border border-border bg-panel2 px-3 py-2 hover:border-borderstrong">
                    <span className="mono truncate text-xs text-fg" style={{ maxWidth: 260 }}>{s.scan_id}</span>
                    <span className="mono text-[11px] text-faint">{s.mode}</span>
                    <div className="ml-auto flex items-center gap-1.5">
                      {(["critical", "high", "medium", "low"] as const).map((k) =>
                        s.severity_counts?.[k] ? (
                          <span key={k} className="mono text-[11px]"><SeverityBadge severity={k} /> {s.severity_counts[k]}</span>
                        ) : null
                      )}
                      {s.findings === 0 && <span className="mono text-[11px] text-faint">0 findings</span>}
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </div>

          {latest && (
            <div className="card mt-4 p-4">
              <div className="mb-2 flex items-center gap-2 text-sm font-semibold"><Clock size={14} /> Last scan</div>
              <div className="mono text-xs text-muted">{latest.scan_id}</div>
              <div className="mono mt-1 text-[11px] text-faint">{latest.target}</div>
            </div>
          )}
        </div>

        <ArchitectureCard />
      </div>
    </div>
  );
}
