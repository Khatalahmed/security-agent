"use client";
import { ArrowDown } from "lucide-react";

// The real pipeline, in order. Mirrors the engine's audit flow.
const STEPS = [
  { k: "repo", label: "Repository", sub: "source tree", tone: "var(--muted)" },
  { k: "audit", label: "Source Audit", sub: "per-file LLM pass", tone: "var(--accent)" },
  { k: "ast", label: "AST / Call Graph", sub: "deterministic", tone: "var(--low)" },
  { k: "taint", label: "Cross-file Taint", sub: "source → sink chains", tone: "var(--high)" },
  { k: "ollama", label: "Local Ollama", sub: "qwen2.5-coder · on-device", tone: "var(--ok)" },
  { k: "validate", label: "Validation", sub: "skeptical re-check", tone: "var(--accent)" },
  { k: "dedup", label: "Dedup / Authority", sub: "merge + taint veto", tone: "var(--low)" },
  { k: "human", label: "Human Confirmation", sub: "the gate", tone: "var(--crit)" },
  { k: "report", label: "Reports", sub: "md · json · html · sarif", tone: "var(--muted)" },
];

export function ArchitectureCard() {
  return (
    <div className="card p-5">
      <div className="mb-4 flex items-center justify-between">
        <div>
          <div className="text-sm font-semibold">Analysis pipeline</div>
          <div className="text-xs text-muted">Deterministic program analysis + local LLM reasoning + a human gate.</div>
        </div>
        <span className="mono rounded border border-border px-2 py-0.5 text-[10px] text-faint">local-only</span>
      </div>
      <div className="flex flex-col items-stretch gap-0">
        {STEPS.map((s, i) => (
          <div key={s.k}>
            <div className="group flex items-center gap-3 rounded-md border border-border bg-panel2 px-3 py-2 transition-colors hover:border-borderstrong">
              <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: s.tone }} />
              <span className="text-sm font-medium">{s.label}</span>
              <span className="mono ml-auto text-[11px] text-faint">{s.sub}</span>
            </div>
            {i < STEPS.length - 1 && (
              <div className="flex justify-center py-0.5 text-faint"><ArrowDown size={13} /></div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
