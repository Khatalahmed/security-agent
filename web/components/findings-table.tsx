"use client";
import Link from "next/link";
import { useMemo, useState } from "react";
import { Search } from "lucide-react";
import type { Finding, Severity } from "@/lib/types";
import { SeverityBadge, StateBadge, MethodBadge, cls } from "@/lib/ui";

const SEV_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0, unknown: 0 };
const SEVS: Severity[] = ["critical", "high", "medium", "low", "info"];

export function FindingsTable({ findings }: { findings: Finding[] }) {
  const [q, setQ] = useState("");
  const [sev, setSev] = useState<Severity | "all">("all");
  const [method, setMethod] = useState<string>("all");
  const [state, setState] = useState<string>("all");

  const methods = useMemo(() => Array.from(new Set(findings.map((f) => f.method))), [findings]);
  const states = useMemo(() => Array.from(new Set(findings.map((f) => f.state))), [findings]);

  const rows = useMemo(() => {
    return findings
      .filter((f) => sev === "all" || f.severity === sev)
      .filter((f) => method === "all" || f.method === method)
      .filter((f) => state === "all" || f.state === state)
      .filter((f) => {
        if (!q.trim()) return true;
        const hay = `${f.vuln_class} ${f.location} ${f.target} ${f.description}`.toLowerCase();
        return hay.includes(q.toLowerCase());
      })
      .sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity]);
  }, [findings, q, sev, method, state]);

  const Sel = ({ v, set, opts, label }: { v: string; set: (s: string) => void; opts: string[]; label: string }) => (
    <select value={v} onChange={(e) => set(e.target.value)}
      className="rounded-md border border-border bg-panel px-2.5 py-1.5 text-xs text-fg outline-none focus:border-borderstrong">
      <option value="all">{label}: all</option>
      {opts.map((o) => <option key={o} value={o}>{o}</option>)}
    </select>
  );

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="relative">
          <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-faint" />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search class, file, evidence…"
            className="w-64 rounded-md border border-border bg-panel py-1.5 pl-8 pr-2 text-xs outline-none focus:border-borderstrong" />
        </div>
        <Sel v={sev} set={(s) => setSev(s as Severity | "all")} opts={SEVS} label="severity" />
        <Sel v={method} set={setMethod} opts={methods} label="method" />
        <Sel v={state} set={setState} opts={states} label="status" />
        <span className="ml-auto mono text-xs text-faint">{rows.length} / {findings.length}</span>
      </div>

      {rows.length === 0 ? (
        <div className="card p-8 text-center text-sm text-muted">No findings match the current filters.</div>
      ) : (
        <div className="card overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-[11px] uppercase tracking-wide text-faint">
                <th className="px-3 py-2.5 font-medium">Severity</th>
                <th className="px-3 py-2.5 font-medium">Vulnerability</th>
                <th className="px-3 py-2.5 font-medium">Location</th>
                <th className="px-3 py-2.5 font-medium">Method</th>
                <th className="px-3 py-2.5 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((f, i) => (
                <tr key={f.id} className={cls("border-b border-border/60 hover:bg-panel2", i % 2 ? "bg-black/10" : "")}>
                  <td className="px-3 py-2.5"><SeverityBadge severity={f.severity} /></td>
                  <td className="px-3 py-2.5">
                    <Link href={`/findings/${encodeURIComponent(f.id)}`} className="font-medium text-fg hover:text-accent">
                      {f.vuln_class}
                    </Link>
                  </td>
                  <td className="mono px-3 py-2.5 text-xs text-muted">{f.location || f.target}</td>
                  <td className="px-3 py-2.5"><MethodBadge method={f.method} /></td>
                  <td className="px-3 py-2.5"><StateBadge state={f.state} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
