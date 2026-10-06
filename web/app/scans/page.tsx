"use client";
import Link from "next/link";
import { api } from "@/lib/api";
import { useAsync } from "@/lib/use-async";
import { SeverityBadge } from "@/lib/ui";
import { Loading, ErrorState, Empty, PageTitle } from "@/components/states";

export default function ScansPage() {
  const { data, loading, error } = useAsync(() => api.scans(), []);
  if (loading) return <Loading />;
  if (error) return <ErrorState message={error} />;
  const scans = data ?? [];

  return (
    <div>
      <PageTitle title="Scans" subtitle="Every analysis run recorded by the engine." />
      {scans.length === 0 ? (
        <Empty title="No scans yet" hint="Run your first local security scan." />
      ) : (
        <div className="card overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-[11px] uppercase tracking-wide text-faint">
                <th className="px-3 py-2.5 font-medium">Scan</th>
                <th className="px-3 py-2.5 font-medium">Mode</th>
                <th className="px-3 py-2.5 font-medium">Model</th>
                <th className="px-3 py-2.5 font-medium">Findings</th>
                <th className="px-3 py-2.5 font-medium">Severity</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((s) => (
                <tr key={s.scan_id} className="border-b border-border/60 hover:bg-panel2">
                  <td className="mono max-w-[320px] truncate px-3 py-2.5 text-xs">{s.scan_id}</td>
                  <td className="mono px-3 py-2.5 text-xs text-muted">{s.mode}</td>
                  <td className="mono px-3 py-2.5 text-xs text-muted">{s.model}</td>
                  <td className="px-3 py-2.5">{s.findings}</td>
                  <td className="px-3 py-2.5">
                    <div className="flex flex-wrap items-center gap-1.5">
                      {(["critical", "high", "medium", "low"] as const)
                        .filter((k) => s.severity_counts?.[k])
                        .map((k) => <span key={k} className="flex items-center gap-1 text-[11px]"><SeverityBadge severity={k} />{s.severity_counts[k]}</span>)}
                      {s.findings === 0 && <span className="text-[11px] text-faint">clean</span>}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
