"use client";
import Link from "next/link";
import { api } from "@/lib/api";
import { useAsync } from "@/lib/use-async";
import { SeverityBadge } from "@/lib/ui";
import { Loading, ErrorState, Empty, PageTitle } from "@/components/states";
import { Share2, ArrowRight } from "lucide-react";

export default function DataFlowIndex() {
  const { data, loading, error } = useAsync(() => api.findings(), []);
  if (loading) return <Loading />;
  if (error) return <ErrorState message={error} />;

  const flows = (data ?? []).filter(
    (f) => f.method === "taint" || (Array.isArray(f.evidence?.chain) && f.evidence.chain!.length > 0)
  );

  return (
    <div>
      <PageTitle title="Data Flow"
        subtitle="Cross-file source → sink chains found by the AST taint engine. Each is reconstructed from real analysis evidence." />
      {flows.length === 0 ? (
        <Empty title="No cross-file flows yet" hint="Run a scan with the `taint` skill to produce source → sink chains." />
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {flows.map((f) => {
            const chain = (f.evidence?.chain ?? []) as string[];
            return (
              <Link key={f.id} href={`/findings/${encodeURIComponent(f.id)}`}
                className="card p-4 transition-colors hover:border-borderstrong">
                <div className="flex items-center justify-between">
                  <span className="flex items-center gap-1.5 text-sm font-medium"><Share2 size={14} className="text-muted" />{f.vuln_class}</span>
                  <SeverityBadge severity={f.severity} />
                </div>
                <div className="mono mt-3 space-y-1 text-[11px] text-muted">
                  {chain.map((c, i) => (
                    <div key={i} className="flex items-center gap-1.5">
                      {i > 0 && <ArrowRight size={10} className="text-faint" />}
                      <span className={i === chain.length - 1 ? "text-high" : ""}>{c}</span>
                    </div>
                  ))}
                  {f.evidence?.sink && <div className="text-crit">⇒ {f.evidence.sink.callee} @ {f.evidence.sink.line}</div>}
                </div>
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}
