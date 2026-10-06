"use client";
import { useEffect, useRef, useState } from "react";
import { api, ApiError } from "@/lib/api";
import { PageTitle } from "@/components/states";
import type { Job } from "@/lib/types";
import { ScanLine, Check, Loader2, Circle, CircleDot } from "lucide-react";

export default function NewScan() {
  const [repo, setRepo] = useState("");
  const [skills, setSkills] = useState<string[]>(["source_audit"]);
  const [taint, setTaint] = useState(false);
  const [rag, setRag] = useState(false);
  const [job, setJob] = useState<Job | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const poll = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => () => { if (poll.current) clearInterval(poll.current); }, []);

  const toggleSkill = (s: string) =>
    setSkills((xs) => (xs.includes(s) ? xs.filter((x) => x !== s) : [...xs, s]));

  async function start() {
    setErr(null);
    try {
      const j = await api.startScan({ repo, skills, taint_all_chains: taint && skills.includes("taint"), rag });
      setJob(j);
      poll.current = setInterval(async () => {
        try {
          const u = await api.job(j.id);
          setJob(u);
          if (u.status === "succeeded" || u.status === "failed") { if (poll.current) clearInterval(poll.current); }
        } catch {}
      }, 1500);
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : String(e));
    }
  }

  const running = job && (job.status === "queued" || job.status === "running");

  return (
    <div className="max-w-3xl">
      <PageTitle title="New Scan" subtitle="Runs the real engine locally via Ollama. Source stays on this machine." />

      <div data-tour="scan-form" className="card space-y-4 p-5">
        <Field label="Repository / path" hint="An absolute or relative path on this machine (the backend validates it).">
          <input value={repo} onChange={(e) => setRepo(e.target.value)} placeholder="e.g. evaluation/fixtures_hard4/vulnerable/cmdi_mid_concat"
            className="mono w-full rounded-md border border-border bg-panel px-3 py-2 text-sm outline-none focus:border-borderstrong" />
        </Field>

        <Field label="Analysis">
          <div className="flex flex-wrap gap-2">
            {["source_audit", "secrets", "taint"].map((s) => (
              <button key={s} onClick={() => toggleSkill(s)}
                className="mono rounded-md border px-2.5 py-1.5 text-xs"
                style={skills.includes(s)
                  ? { borderColor: "var(--accent)", color: "var(--accent)", background: "rgba(59,130,246,.1)" }
                  : { borderColor: "var(--border)", color: "var(--muted)" }}>
                {s}
              </button>
            ))}
          </div>
        </Field>

        <div className="flex flex-wrap gap-5 text-sm">
          <Toggle label="Cross-file taint on same-file chains" on={taint} set={setTaint} disabled={!skills.includes("taint")} />
          <Toggle label="RAG (disclosed-vuln patterns)" on={rag} set={setRag} />
        </div>

        <button onClick={start} disabled={!repo || !!running}
          className="flex items-center gap-2 rounded-md px-4 py-2.5 text-sm font-semibold text-white disabled:opacity-50"
          style={{ background: "var(--accent)" }}>
          {running ? <Loader2 size={15} className="animate-spin" /> : <ScanLine size={15} />}
          {running ? "Scanning…" : "Start Security Scan"}
        </button>
        {err && <p className="mono text-xs" style={{ color: "var(--crit)" }}>{err}</p>}
      </div>

      {job && (
        <div className="card mt-4 p-5">
          <div className="mb-3 flex items-center justify-between">
            <div className="text-sm font-semibold">Pipeline</div>
            <span className="mono text-xs text-faint">{job.scan_id} · {job.status}</span>
          </div>
          <div className="space-y-1.5">
            {job.stages.map((st) => (
              <div key={st.key} className="flex items-center gap-2.5 text-sm">
                {st.state === "done" ? <Check size={15} style={{ color: "var(--ok)" }} />
                  : st.state === "active" ? <CircleDot size={15} className="animate-pulse" style={{ color: "var(--accent)" }} />
                    : <Circle size={15} className="text-faint" />}
                <span className={st.state === "pending" ? "text-faint" : "text-fg"}>{st.label}</span>
              </div>
            ))}
          </div>
          {job.log_tail.length > 0 && (
            <pre className="mono mt-3 max-h-40 overflow-auto rounded-md border border-border bg-black/30 p-2 text-[11px] text-muted">
              {job.log_tail.join("\n")}
            </pre>
          )}
          {job.status === "succeeded" && (
            <a href={`/scans`} className="mt-3 inline-block text-sm text-accent hover:underline">View results →</a>
          )}
          {job.status === "failed" && <p className="mono mt-2 text-xs" style={{ color: "var(--crit)" }}>{job.error}</p>}
        </div>
      )}
    </div>
  );
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="mb-1 block text-xs font-medium text-muted">{label}</label>
      {children}
      {hint && <p className="mt-1 text-[11px] text-faint">{hint}</p>}
    </div>
  );
}
function Toggle({ label, on, set, disabled }: { label: string; on: boolean; set: (b: boolean) => void; disabled?: boolean }) {
  return (
    <label className={`flex items-center gap-2 ${disabled ? "opacity-40" : "cursor-pointer"}`}>
      <input type="checkbox" checked={on} disabled={disabled} onChange={(e) => set(e.target.checked)} />
      <span className="text-xs text-muted">{label}</span>
    </label>
  );
}
