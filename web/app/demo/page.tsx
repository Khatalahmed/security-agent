"use client";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "@/lib/api";
import type { Benchmark, DataFlow, Finding, OllamaStatus } from "@/lib/types";
import {
  ShieldCheck, Cpu, Lock, Radio, ArrowRightLeft, Crosshair, Bug, Check,
  Play, Pause, SkipBack, SkipForward, RotateCcw, Maximize, FileCode2, GitBranch,
} from "lucide-react";

/* ------------------------------------------------------------------ data -- */
interface DemoData { ollama: OllamaStatus | null; hero: Finding | null; flow: DataFlow | null; benches: Benchmark[]; }

function useDemoData() {
  const [d, setD] = useState<DemoData | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    (async () => {
      try {
        const [ollama, findings, benches] = await Promise.all([
          api.ollama().catch(() => null), api.findings(), api.benchmarks(),
        ]);
        // hero = taint finding with the longest cross-file chain (most cinematic)
        const taint = findings
          .filter((f) => Array.isArray(f.evidence?.chain) && (f.evidence!.chain as string[]).length >= 2)
          .sort((a, b) => (b.evidence!.chain as string[]).length - (a.evidence!.chain as string[]).length);
        const hero = taint[0] ?? findings[0] ?? null;
        const flow = hero ? await api.dataflow(hero.id).catch(() => null) : null;
        setD({ ollama, hero, flow, benches: benches.filter((b) => !b.mock && b.aggregate) });
      } catch (e) { setErr(String(e)); }
    })();
  }, []);
  return { d, err };
}

/* --------------------------------------------------------------- controller */
const SCENES = [
  { id: "title", ms: 6500 },
  { id: "pipeline", ms: 10000 },
  { id: "analyze", ms: 12500 },
  { id: "flow", ms: 16500 },
  { id: "evidence", ms: 13500 },
  { id: "bench", ms: 11500 },
  { id: "end", ms: 9000 },
] as const;
const TOTAL = SCENES.reduce((a, s) => a + s.ms, 0);

export default function DemoPage() {
  const { d, err } = useDemoData();
  const [started, setStarted] = useState(false);
  const [scene, setScene] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [showCtl, setShowCtl] = useState(true);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const hideCtl = useRef<ReturnType<typeof setTimeout> | null>(null);

  const go = useCallback((i: number) => setScene(Math.max(0, Math.min(SCENES.length - 1, i))), []);

  // auto-advance
  useEffect(() => {
    if (!playing) return;
    if (scene >= SCENES.length - 1) { setPlaying(false); return; }
    timer.current = setTimeout(() => setScene((s) => s + 1), SCENES[scene].ms);
    return () => { if (timer.current) clearTimeout(timer.current); };
  }, [playing, scene]);

  // controls auto-hide while playing
  const bump = useCallback(() => {
    setShowCtl(true);
    if (hideCtl.current) clearTimeout(hideCtl.current);
    hideCtl.current = setTimeout(() => playing && setShowCtl(false), 2600);
  }, [playing]);

  // keyboard
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === " ") { e.preventDefault(); setPlaying((p) => !p); }
      else if (e.key === "ArrowRight") { setPlaying(false); go(scene + 1); }
      else if (e.key === "ArrowLeft") { setPlaying(false); go(scene - 1); }
      else if (e.key.toLowerCase() === "r") { setScene(0); setPlaying(true); }
      else if (e.key.toLowerCase() === "f") { document.fullscreenElement ? document.exitFullscreen() : document.documentElement.requestFullscreen(); }
      bump();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [scene, go, bump]);

  const begin = () => { setStarted(true); setScene(0); setPlaying(true); bump(); };

  if (err) return <Center><div className="text-sm" style={{ color: "var(--crit)" }}>Demo needs the API at :8000 — {err}</div></Center>;
  if (!d) return <Center><div className="anim-fadein text-muted">Preparing demo…</div></Center>;

  return (
    <div className="relative h-screen w-screen overflow-hidden bg-bg text-fg" onMouseMove={bump}>
      <div className="demo-grid absolute inset-0 opacity-70" />
      <div className="demo-vignette pointer-events-none absolute inset-0" />

      {/* persistent corner chrome */}
      <div className="absolute left-5 top-5 z-20 flex items-center gap-2 text-xs">
        <div className="grid h-7 w-7 place-items-center rounded-md" style={{ background: "var(--accent-dim)" }}>
          <ShieldCheck size={15} style={{ color: "var(--accent)" }} />
        </div>
        <span className="font-semibold tracking-tight">Local Security Agent</span>
        <span className="mono rounded border border-border px-1.5 py-0.5 text-[10px] text-faint">guided demo</span>
      </div>
      <div className="absolute right-5 top-5 z-20">
        <OllamaPill o={d.ollama} />
      </div>

      {/* stage */}
      <div key={scene} className="absolute inset-0 z-10 flex items-center justify-center px-6">
        {SCENES[scene].id === "title" && <Title o={d.ollama} />}
        {SCENES[scene].id === "pipeline" && <Pipeline />}
        {SCENES[scene].id === "analyze" && <Analyze repo={d.hero?.target ?? ""} model={d.ollama?.active_model ?? "qwen2.5-coder:7b"} />}
        {SCENES[scene].id === "flow" && d.flow && <FlowScene finding={d.hero!} flow={d.flow} />}
        {SCENES[scene].id === "evidence" && <Evidence finding={d.hero!} />}
        {SCENES[scene].id === "bench" && <Bench benches={d.benches} />}
        {SCENES[scene].id === "end" && <EndCard />}
      </div>

      {/* start overlay */}
      {!started && (
        <div className="absolute inset-0 z-30 flex flex-col items-center justify-center gap-6 bg-bg/80 backdrop-blur">
          <div className="anim-fadeup text-center">
            <div className="text-[13px] font-semibold uppercase tracking-[0.3em] text-faint">Local Security Agent</div>
            <h1 className="mt-3 text-5xl font-semibold tracking-tight">Source → Sink, on-device.</h1>
            <p className="mx-auto mt-3 max-w-xl text-muted">A ~80-second guided tour of local program analysis + LLM reasoning. Real findings, real taint chains, real numbers.</p>
          </div>
          <button onClick={begin} className="anim-pop flex items-center gap-2 rounded-lg px-6 py-3 text-base font-semibold text-white"
            style={{ background: "var(--accent)" }}>
            <Play size={18} /> Begin demo
          </button>
          <div className="mono text-[11px] text-faint">space play/pause · ← → step · R restart · F fullscreen</div>
        </div>
      )}

      {/* controls */}
      <div className={`absolute inset-x-0 bottom-0 z-20 transition-opacity duration-500 ${showCtl || !playing ? "opacity-100" : "opacity-0"}`}>
        <div className="h-0.5 w-full bg-border">
          <div className="h-full transition-all" style={{ width: `${((scene) / (SCENES.length - 1)) * 100}%`, background: "var(--accent)" }} />
        </div>
        <div className="flex items-center justify-center gap-3 bg-gradient-to-t from-black/60 to-transparent px-4 py-3">
          <Ctl onClick={() => { setPlaying(false); go(scene - 1); }}><SkipBack size={16} /></Ctl>
          <Ctl onClick={() => setPlaying((p) => !p)} primary>{playing ? <Pause size={16} /> : <Play size={16} />}</Ctl>
          <Ctl onClick={() => { setPlaying(false); go(scene + 1); }}><SkipForward size={16} /></Ctl>
          <Ctl onClick={() => { setScene(0); setPlaying(true); }}><RotateCcw size={16} /></Ctl>
          <div className="mx-2 flex items-center gap-1.5">
            {SCENES.map((s, i) => (
              <button key={s.id} onClick={() => { setPlaying(false); go(i); }}
                className="h-1.5 rounded-full transition-all" title={s.id}
                style={{ width: i === scene ? 22 : 7, background: i === scene ? "var(--accent)" : "var(--border-strong)" }} />
            ))}
          </div>
          <Ctl onClick={() => (document.fullscreenElement ? document.exitFullscreen() : document.documentElement.requestFullscreen())}><Maximize size={16} /></Ctl>
        </div>
      </div>
    </div>
  );
}

/* --------------------------------------------------------------- scenes --- */
function Title({ o }: { o: OllamaStatus | null }) {
  const chips = ["AST", "Call graph", "Cross-file taint", "Local Ollama", "Validation", "Human gate"];
  return (
    <div className="text-center">
      <div className="anim-fadeup text-[13px] font-semibold uppercase tracking-[0.35em] text-faint" style={{ animationDelay: "0ms" }}>
        Local Security Agent
      </div>
      <h1 className="anim-fadeup mt-4 text-6xl font-semibold leading-tight tracking-tight" style={{ animationDelay: "120ms" }}>
        AI security analysis<br />that never leaves<br /><span style={{ color: "var(--accent)" }}>your machine.</span>
      </h1>
      <div className="anim-fadeup mt-7 flex flex-wrap justify-center gap-2" style={{ animationDelay: "420ms" }}>
        {chips.map((c, i) => (
          <span key={c} className="anim-pop mono rounded-full border border-border bg-panel px-3 py-1 text-xs text-muted"
            style={{ animationDelay: `${600 + i * 90}ms` }}>{c}</span>
        ))}
      </div>
      <div className="anim-fadeup mt-8 inline-flex items-center gap-2 text-sm text-muted" style={{ animationDelay: "1200ms" }}>
        <Lock size={14} style={{ color: "var(--ok)" }} /> {o?.online ? `${o.active_model} · running locally` : "local-first"}
      </div>
    </div>
  );
}

const PIPE = [
  { l: "Source tree", i: FileCode2, c: "var(--muted)" },
  { l: "AST / Call graph", i: ArrowRightLeft, c: "var(--low)" },
  { l: "Cross-file taint", i: Crosshair, c: "var(--high)" },
  { l: "Local Ollama", i: Cpu, c: "var(--ok)" },
  { l: "Validation", i: ShieldCheck, c: "var(--accent)" },
  { l: "Finding", i: Bug, c: "var(--crit)" },
  { l: "Human confirm", i: Check, c: "var(--crit)" },
  { l: "Report", i: FileCode2, c: "var(--muted)" },
];
function Pipeline() {
  return (
    <div className="w-full max-w-5xl text-center">
      <h2 className="anim-fadeup text-sm font-semibold uppercase tracking-[0.3em] text-faint">One local pipeline</h2>
      <p className="anim-fadeup mt-2 text-2xl font-medium" style={{ animationDelay: "120ms" }}>Deterministic analysis, then the model reasons over the evidence.</p>
      <div className="mt-10 flex flex-wrap items-stretch justify-center gap-2">
        {PIPE.map((p, i) => {
          const Icon = p.i;
          return (
            <div key={p.l} className="flex items-center gap-2">
              <div className="anim-pop flex w-[120px] flex-col items-center gap-2 rounded-xl border border-border bg-panel px-3 py-4"
                style={{ animationDelay: `${i * 220}ms` }}>
                <Icon size={20} style={{ color: p.c }} />
                <span className="text-xs font-medium leading-tight">{p.l}</span>
              </div>
              {i < PIPE.length - 1 && <span className="anim-fadein text-faint" style={{ animationDelay: `${i * 220 + 160}ms` }}>→</span>}
            </div>
          );
        })}
      </div>
    </div>
  );
}

const STEPS = ["Repository indexed", "Files discovered", "AST analysis", "Call graph built",
  "Cross-file taint", "Local LLM reasoning", "Validation", "Deduplication", "Report generated"];
function Analyze({ repo, model }: { repo: string; model: string }) {
  const [done, setDone] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setDone((n) => (n < STEPS.length ? n + 1 : n)), 950);
    return () => clearInterval(t);
  }, []);
  const base = repo.split(/[\\/]/).slice(-2).join("/") || "repository";
  return (
    <div className="grid w-full max-w-5xl gap-6 lg:grid-cols-2">
      <div className="anim-fadeup">
        <div className="text-sm font-semibold uppercase tracking-[0.3em] text-faint">Analyzing</div>
        <div className="mono mt-2 text-xl text-fg">{base}</div>
        <div className="mono mt-1 text-xs text-ok">local inference · ollama · {model}</div>
        <div className="mt-6 space-y-2.5">
          {STEPS.map((s, i) => (
            <div key={s} className="flex items-center gap-3 text-sm">
              {i < done ? <Check size={16} style={{ color: "var(--ok)" }} />
                : i === done ? <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-border" style={{ borderTopColor: "var(--accent)" }} />
                  : <span className="h-3.5 w-3.5 rounded-full border border-border" />}
              <span className={i <= done ? "text-fg" : "text-faint"}>{s}</span>
            </div>
          ))}
        </div>
      </div>
      <div className="anim-fadein relative overflow-hidden rounded-xl border border-border bg-black/40 p-4" style={{ animationDelay: "200ms" }}>
        <div className="scanline" />
        <pre className="mono text-[11px] leading-relaxed text-muted/80">{`@app.route("/convert")
def convert():
    fmt = request.args.get("format")  # SOURCE
    return execute(build_cmd(fmt))
# ────────────────────────────────
def _run(cmd):
    return os.popen(cmd).read()       # SINK
`}</pre>
        <div className="mono mt-3 text-[11px] text-faint">reconstructing source → sink across files…</div>
      </div>
    </div>
  );
}

const ROLE_ICON = { source: Radio, transformation: ArrowRightLeft, sanitizer: ShieldCheck, sink: Crosshair, finding: Bug } as const;
const ROLE_COLOR = { source: "var(--accent)", transformation: "var(--muted)", sanitizer: "var(--ok)", sink: "var(--high)", finding: "var(--crit)" } as const;
function FlowScene({ finding, flow }: { finding: Finding; flow: DataFlow }) {
  const nodes = flow.nodes;
  return (
    <div className="w-full max-w-5xl">
      <div className="anim-fadeup mb-4 text-center">
        <div className="text-sm font-semibold uppercase tracking-[0.3em] text-faint">Cross-file data flow</div>
        <div className="mt-1 text-base text-muted">Tracing attacker-controlled input to a dangerous sink.</div>
      </div>
      <div className="flex flex-col items-center">
        {nodes.map((n, i) => {
          const Icon = ROLE_ICON[n.role] ?? ArrowRightLeft;
          const color = ROLE_COLOR[n.role] ?? "var(--muted)";
          const isFinding = n.role === "finding";
          const delay = 250 + i * 720;
          return (
            <div key={n.id} className="flex w-full flex-col items-center">
              <div className={isFinding ? "anim-slam" : "anim-pop"}
                style={{ animationDelay: `${delay}ms`, ["--glow" as string]: `${color}66` }}>
                <div className="glow flex w-[340px] items-center gap-3 rounded-xl border px-4 py-2"
                  style={{ borderColor: color, background: `${color}14` }}>
                  <Icon size={17} style={{ color }} />
                  <div className="min-w-0">
                    <div className="text-[9px] font-semibold tracking-widest" style={{ color }}>{(n.role || "").toUpperCase()}</div>
                    <div className={`truncate font-medium ${isFinding ? "text-base" : "text-sm"}`}>{n.label}</div>
                    {n.file && <div className="mono truncate text-[10px] text-muted">{n.file}{n.function ? `::${n.function}` : ""}</div>}
                  </div>
                </div>
              </div>
              {i < nodes.length - 1 && (
                <svg width="24" height="22" className="anim-fadein" style={{ animationDelay: `${delay + 300}ms` }}>
                  <line x1="12" y1="1" x2="12" y2="21" stroke="var(--border-strong)" strokeWidth="2" className="edge-flow" />
                </svg>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function Evidence({ finding }: { finding: Finding }) {
  const [confirmed, setConfirmed] = useState(false);
  useEffect(() => { const t = setTimeout(() => setConfirmed(true), 6500); return () => clearTimeout(t); }, []);
  const sink = finding.evidence?.sink;
  return (
    <div className="grid w-full max-w-5xl gap-6 lg:grid-cols-[1fr_320px]">
      <div className="anim-fadeup">
        <div className="text-sm font-semibold uppercase tracking-[0.3em] text-faint">Why this is a finding</div>
        <h3 className="mt-2 text-2xl font-semibold" style={{ color: "var(--crit)" }}>{finding.vuln_class}</h3>
        <p className="mt-3 max-w-xl text-[15px] leading-relaxed text-fg/90">{finding.description}</p>
        {sink && <div className="mono mt-4 inline-block rounded-md border border-border bg-black/30 px-3 py-1.5 text-xs text-high">sink: {sink.callee} @ line {sink.line}</div>}
      </div>
      <div className="anim-fadein flex flex-col items-center justify-center rounded-xl border border-border bg-panel p-6" style={{ animationDelay: "250ms" }}>
        <div className="text-xs uppercase tracking-widest text-faint">Human review</div>
        {!confirmed ? (
          <button className="ring-pulse mt-4 flex items-center gap-2 rounded-lg px-5 py-2.5 text-sm font-semibold text-white"
            style={{ background: "var(--crit)" }}>
            <Check size={16} /> Confirm Finding
          </button>
        ) : (
          <div className="anim-slam mt-4 flex items-center gap-2 rounded-lg border-2 px-5 py-2.5 text-sm font-bold"
            style={{ borderColor: "var(--crit)", color: "var(--crit)" }}>
            <ShieldCheck size={16} /> CONFIRMED
          </div>
        )}
        <p className="mt-4 text-center text-[11px] leading-relaxed text-faint">Every finding is a <b>candidate</b> until a human confirms it. The model never auto-confirms.</p>
      </div>
    </div>
  );
}

function useCount(target: number, run: boolean, ms = 900) {
  const [v, setV] = useState(0);
  useEffect(() => {
    if (!run) return;
    let raf = 0; const t0 = performance.now();
    const tick = (t: number) => { const p = Math.min(1, (t - t0) / ms); setV(Math.round(target * (1 - Math.pow(1 - p, 3)))); if (p < 1) raf = requestAnimationFrame(tick); };
    raf = requestAnimationFrame(tick); return () => cancelAnimationFrame(raf);
  }, [target, run, ms]);
  return v;
}
function Bench({ benches }: { benches: Benchmark[] }) {
  const top = useMemo(() => benches.slice().sort((a, b) => (b.aggregate!.fixtures) - (a.aggregate!.fixtures)).slice(0, 5), [benches]);
  return (
    <div className="w-full max-w-4xl text-center">
      <div className="anim-fadeup text-sm font-semibold uppercase tracking-[0.3em] text-faint">Measured, honestly</div>
      <p className="anim-fadeup mt-2 text-2xl font-medium" style={{ animationDelay: "120ms" }}>Evaluated on labeled corpora — the false positives are shown too.</p>
      <div className="mt-10 flex items-end justify-center gap-6" style={{ height: 240 }}>
        {top.map((b, i) => <Bar key={b.file} b={b} i={i} />)}
      </div>
      <div className="anim-fadein mt-4 mono text-[11px] text-faint" style={{ animationDelay: "900ms" }}>bars = detection rate · FP = false positives on clean code · model: qwen2.5-coder:7b</div>
    </div>
  );
}
function Bar({ b, i }: { b: Benchmark; i: number }) {
  const det = Math.round((b.aggregate!.detection_rate ?? 0) * 100);
  const h = useCount(det, true, 1000);
  const fp = b.aggregate!.fp_on_clean_fixtures ?? 0;
  const name = b.file.replace(/\.json$/, "").replace(/^\d+-/, "").replace("ollama-", "");
  return (
    <div className="flex flex-col items-center gap-2" style={{ width: 92 }}>
      <div className="text-lg font-semibold">{h}%</div>
      <div className="relative w-14 overflow-hidden rounded-t-md bg-panel" style={{ height: 150 }}>
        <div className="bar-grow absolute bottom-0 w-full rounded-t-md" style={{ height: `${det * 1.5}px`, background: "var(--accent)", animationDelay: `${i * 120}ms` }} />
      </div>
      <div className="mono text-[10px] text-faint" style={{ color: fp ? "var(--high)" : "var(--ok)" }}>FP {fp}</div>
      <div className="mono max-w-[88px] truncate text-[10px] text-muted">{name}</div>
      <div className="mono text-[10px] text-faint">{b.aggregate!.fixtures} fx</div>
    </div>
  );
}

function EndCard() {
  return (
    <div className="text-center">
      <div className="anim-pop mx-auto grid h-14 w-14 place-items-center rounded-xl" style={{ background: "var(--accent-dim)" }}>
        <ShieldCheck size={28} style={{ color: "var(--accent)" }} />
      </div>
      <h1 className="anim-fadeup mt-5 text-4xl font-semibold tracking-tight" style={{ animationDelay: "150ms" }}>Local Security Agent</h1>
      <p className="anim-fadeup mx-auto mt-3 max-w-lg text-muted" style={{ animationDelay: "300ms" }}>
        Local Ollama · deterministic program analysis · LLM reasoning · cross-file taint · measurable evaluation.
      </p>
      <div className="anim-fadeup mt-6 inline-flex items-center gap-2 rounded-lg border border-border bg-panel px-4 py-2 text-sm" style={{ animationDelay: "450ms" }}>
        <GitBranch size={15} /> <span className="mono">github.com/Khatalahmed/security-agent</span>
      </div>
      <div className="anim-fadein mt-6 flex items-center justify-center gap-2 text-xs text-faint" style={{ animationDelay: "700ms" }}>
        <Lock size={12} /> your code never leaves your machine
      </div>
    </div>
  );
}

/* --------------------------------------------------------------- bits ----- */
function Center({ children }: { children: React.ReactNode }) {
  return <div className="flex h-screen w-screen items-center justify-center bg-bg">{children}</div>;
}
function OllamaPill({ o }: { o: OllamaStatus | null }) {
  const on = o?.online;
  const color = on ? "var(--ok)" : "var(--crit)";
  return (
    <div className="flex items-center gap-2 rounded-full border border-border bg-panel px-3 py-1.5 text-xs">
      <span className="relative flex h-2 w-2">
        {on && <span className="absolute inline-flex h-full w-full animate-ping rounded-full opacity-60" style={{ background: color }} />}
        <span className="relative h-2 w-2 rounded-full" style={{ background: color }} />
      </span>
      <Cpu size={12} className="text-muted" />
      <span className="mono">{on ? `${o?.active_model} · local` : "Ollama offline"}</span>
    </div>
  );
}
function Ctl({ children, onClick, primary }: { children: React.ReactNode; onClick: () => void; primary?: boolean }) {
  return (
    <button onClick={onClick}
      className="grid h-9 w-9 place-items-center rounded-full border transition-colors"
      style={primary ? { background: "var(--accent)", borderColor: "var(--accent)", color: "#fff" } : { borderColor: "var(--border)", color: "var(--muted)" }}>
      {children}
    </button>
  );
}
