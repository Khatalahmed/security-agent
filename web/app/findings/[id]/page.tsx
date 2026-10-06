"use client";
import { useParams } from "next/navigation";
import { useState } from "react";
import { api, ApiError } from "@/lib/api";
import { useAsync } from "@/lib/use-async";
import { SeverityBadge, StateBadge, MethodBadge } from "@/lib/ui";
import { Loading, ErrorState, PageTitle } from "@/components/states";
import { DataFlowGraph } from "@/components/dataflow-graph";
import type { Finding } from "@/lib/types";
import { CheckCircle2, XCircle, ShieldCheck, FlaskConical } from "lucide-react";

export default function FindingDetail() {
  const { id } = useParams<{ id: string }>();
  const f = useAsync(() => api.finding(id), [id]);
  const flow = useAsync(() => api.dataflow(id), [id]);
  const [busy, setBusy] = useState(false);
  const [actionErr, setActionErr] = useState<string | null>(null);
  const [override, setOverride] = useState<Finding | null>(null);

  if (f.loading) return <Loading label="Loading finding…" />;
  if (f.error || !f.data) return <ErrorState message={f.error ?? "not found"} />;
  const finding = override ?? f.data;

  const terminal = finding.state === "HUMAN_CONFIRMED" || finding.state === "FALSE_POSITIVE";
  const act = async (which: "confirm" | "fp") => {
    setBusy(true); setActionErr(null);
    try {
      const updated = which === "confirm" ? await api.confirm(id) : await api.falsePositive(id);
      setOverride(updated);
    } catch (e) {
      setActionErr(e instanceof ApiError ? e.message : String(e));
    } finally { setBusy(false); }
  };

  const ev = finding.evidence ?? {};
  const val = ev.validation as { verdict?: string; confidence?: string } | undefined;

  return (
    <div>
      <PageTitle title={finding.vuln_class}
        subtitle={finding.target}
        right={<div className="flex items-center gap-2"><SeverityBadge severity={finding.severity} /><StateBadge state={finding.state} /></div>} />

      {/* meta row */}
      <div className="card mb-4 flex flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3 text-sm">
        <span><span className="text-faint">Method </span><MethodBadge method={finding.method} /></span>
        <span><span className="text-faint">Confidence </span><b className="mono">{finding.confidence || "n/a"}</b></span>
        <span><span className="text-faint">Location </span><b className="mono text-xs">{finding.location}</b></span>
        <span className="mono text-xs text-faint">{finding.id}</span>
      </div>

      <div className="grid gap-4 lg:grid-cols-[1fr_320px]">
        <div className="min-w-0 space-y-4">
          {/* why */}
          <section className="card p-4">
            <h2 className="mb-2 text-xs font-semibold uppercase tracking-widest text-faint">Why this is a finding</h2>
            <p className="text-sm leading-relaxed text-fg/90">{finding.description || "No model rationale recorded."}</p>
          </section>

          {/* hero: data flow */}
          <section data-tour="dataflow">
            <h2 className="mb-2 text-xs font-semibold uppercase tracking-widest text-faint">Source → Sink data flow</h2>
            {flow.loading ? <Loading label="Building graph…" />
              : flow.error ? <ErrorState message={flow.error} />
                : flow.data?.available ? <DataFlowGraph flow={flow.data} />
                  : (
                    <div className="card p-5 text-sm text-muted">
                      {flow.data?.message ?? "No cross-file chain for this finding."}
                    </div>
                  )}
          </section>

          {finding.poc && (
            <section className="card p-4">
              <h2 className="mb-2 text-xs font-semibold uppercase tracking-widest text-faint">Proof of concept</h2>
              <pre className="mono overflow-x-auto rounded-md border border-border bg-black/30 p-3 text-xs text-fg/90">{finding.poc}</pre>
            </section>
          )}
          {finding.remediation && (
            <section className="card p-4">
              <h2 className="mb-2 text-xs font-semibold uppercase tracking-widest text-faint">Remediation</h2>
              <p className="text-sm leading-relaxed text-fg/90">{finding.remediation}</p>
            </section>
          )}
        </div>

        {/* side: actions + validation */}
        <div className="space-y-4">
          <section data-tour="confirm" className="card p-4">
            <h2 className="mb-3 text-xs font-semibold uppercase tracking-widest text-faint">Human review</h2>
            {terminal ? (
              <div className="flex items-center gap-2 text-sm">
                {finding.state === "HUMAN_CONFIRMED"
                  ? <><ShieldCheck size={16} style={{ color: "var(--crit)" }} /> Confirmed by a human reviewer.</>
                  : <>Marked a false positive.</>}
              </div>
            ) : (
              <div className="space-y-2">
                <button disabled={busy} onClick={() => act("confirm")}
                  className="flex w-full items-center justify-center gap-2 rounded-md px-3 py-2 text-sm font-medium text-white disabled:opacity-50"
                  style={{ background: "var(--crit)" }}>
                  <CheckCircle2 size={15} /> Confirm Finding
                </button>
                <button disabled={busy} onClick={() => act("fp")}
                  className="flex w-full items-center justify-center gap-2 rounded-md border border-border px-3 py-2 text-sm font-medium text-muted hover:text-fg disabled:opacity-50">
                  <XCircle size={15} /> Mark False Positive
                </button>
                <p className="text-[11px] leading-relaxed text-faint">
                  Confirm walks the engine’s legal lifecycle
                  (candidate → validation_pending → validated → confirmed).
                  These transitions are human-only in the backend.
                </p>
                {actionErr && <p className="mono text-[11px]" style={{ color: "var(--crit)" }}>{actionErr}</p>}
              </div>
            )}
          </section>

          <section className="card p-4">
            <h2 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-widest text-faint">
              <FlaskConical size={12} /> Automated validation
            </h2>
            {val?.verdict ? (
              <div className="text-sm">
                <div>verdict: <b className="mono">{val.verdict}</b></div>
                {val.confidence && <div className="text-muted">confidence: {val.confidence}</div>}
              </div>
            ) : <div className="text-xs text-faint">Not validated. Run `validate` to add a skeptical second opinion.</div>}
          </section>

          {ev.sink && (
            <section className="card p-4">
              <h2 className="mb-2 text-xs font-semibold uppercase tracking-widest text-faint">Sink</h2>
              <div className="mono text-xs text-muted">{ev.sink.callee} @ line {ev.sink.line}</div>
              <div className="mono mt-1 text-[11px] text-faint">class: {ev.sink.class}</div>
            </section>
          )}
        </div>
      </div>
    </div>
  );
}
