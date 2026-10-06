"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { AnimatePresence, motion } from "framer-motion";
import {
  Play, Pause, X, ChevronLeft, ChevronRight, RotateCcw, ShieldCheck, Clapperboard, Code2,
} from "lucide-react";
import { api } from "@/lib/api";

type Scene = {
  route: string;
  kind?: "card";
  eyebrow?: string;
  title: string;
  caption?: string;
  dur: number;        // ms
  pan?: boolean;      // slow auto-scroll during the hold
};

function buildScenes(heroId: string | null): Scene[] {
  const hero = heroId ? `/findings/${encodeURIComponent(heroId)}` : "/dataflow";
  return [
    { route: "/", kind: "card", eyebrow: "LOCAL SECURITY AGENT",
      title: "AI-assisted application security — running entirely on your machine.",
      caption: "Local Ollama · deterministic program analysis · LLM reasoning", dur: 4600 },
    { route: "/", title: "The console", caption: "Local Ollama. Deterministic analysis + LLM reasoning. Source never leaves this machine.", dur: 10500, pan: true },
    { route: "/scan/new", title: "Run a scan", caption: "Point it at a repo — the real engine runs locally and streams real pipeline stages.", dur: 8000 },
    { route: "/findings", title: "Findings", caption: "Per-file and cross-file findings across every scan, each with a full review lifecycle.", dur: 10000, pan: true },
    { route: hero, title: "Cross-file taint — the hero", caption: "SOURCE → SINK, reconstructed from real taint evidence. Not a mockup — actual analysis.", dur: 17000, pan: true },
    { route: "/dataflow", title: "Every data-flow", caption: "Every cross-file source → sink chain the AST taint engine discovered.", dur: 10000, pan: true },
    { route: "/benchmarks", title: "Measured, honestly", caption: "Real evaluation results — the imperfect numbers are shown, not hidden.", dur: 12000, pan: true },
    { route: "/reports", title: "Report anywhere", caption: "Export to Markdown · JSON · HTML · SARIF — from the engine’s own reporting layer.", dur: 6500 },
    { route: "/", kind: "card", eyebrow: "LOCAL · OLLAMA · OPEN SOURCE",
      title: "Local AI + program analysis + measurable evaluation.",
      caption: "github.com/Khatalahmed/security-agent", dur: 5200 },
  ];
}

const easeInOut = (t: number) => (t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2);

export function DemoExperience() {
  const router = useRouter();
  const [active, setActive] = useState(false);
  const [idx, setIdx] = useState(0);
  const [paused, setPaused] = useState(false);
  const [progress, setProgress] = useState(0);
  const [scenes, setScenes] = useState<Scene[]>(() => buildScenes(null));

  const startRef = useRef(0);
  const pausedAtRef = useRef(0);
  const rafRef = useRef<number | null>(null);

  // pick a real taint finding as the hero (first cross-file chain)
  useEffect(() => {
    api.findings().then((fs) => {
      const hero = fs.find((f) => f.method === "taint" && Array.isArray(f.evidence?.chain) && f.evidence.chain!.length > 0)
        ?? fs.find((f) => Array.isArray(f.evidence?.chain) && f.evidence.chain!.length > 0);
      setScenes(buildScenes(hero?.id ?? null));
    }).catch(() => {});
  }, []);

  const scene = scenes[idx];

  const goTo = useCallback((i: number) => {
    const clamped = Math.max(0, Math.min(scenes.length - 1, i));
    setIdx(clamped);
    setProgress(0);
    startRef.current = performance.now();
    pausedAtRef.current = 0;
    window.scrollTo({ top: 0, behavior: "instant" as ScrollBehavior });
    router.push(scenes[clamped].route);
  }, [router, scenes]);

  const start = useCallback(() => {
    setActive(true); setPaused(false); setIdx(0); setProgress(0);
    startRef.current = performance.now();
    window.scrollTo({ top: 0 });
    router.push(scenes[0].route);
  }, [router, scenes]);

  const stop = useCallback(() => {
    setActive(false); setPaused(false);
    if (rafRef.current) cancelAnimationFrame(rafRef.current);
  }, []);

  // the timeline loop
  useEffect(() => {
    if (!active || paused) return;
    const loop = () => {
      const s = scenes[idx];
      if (!s) return;
      const elapsed = performance.now() - startRef.current;
      const p = Math.min(1, elapsed / s.dur);
      setProgress(p);
      if (s.pan) {
        const max = Math.max(0, document.body.scrollHeight - window.innerHeight);
        const t = easeInOut(Math.max(0, Math.min(1, (p - 0.12) / 0.78)));
        window.scrollTo(0, max * t * 0.92);
      }
      if (p >= 1) {
        if (idx >= scenes.length - 1) { stop(); return; }
        goTo(idx + 1);
        return;
      }
      rafRef.current = requestAnimationFrame(loop);
    };
    rafRef.current = requestAnimationFrame(loop);
    return () => { if (rafRef.current) cancelAnimationFrame(rafRef.current); };
  }, [active, paused, idx, scenes, goTo, stop]);

  const togglePause = useCallback(() => {
    setPaused((pz) => {
      if (!pz) { pausedAtRef.current = performance.now(); }
      else { startRef.current += performance.now() - pausedAtRef.current; }
      return !pz;
    });
  }, []);

  // keyboard
  useEffect(() => {
    if (!active) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") stop();
      else if (e.key === " ") { e.preventDefault(); togglePause(); }
      else if (e.key === "ArrowRight") goTo(idx + 1);
      else if (e.key === "ArrowLeft") goTo(idx - 1);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [active, idx, goTo, stop, togglePause]);

  // ---- launcher (inactive) ----
  if (!active) {
    return (
      <button onClick={start}
        className="group fixed bottom-5 right-5 z-[60] flex items-center gap-2 rounded-full border px-4 py-2.5 text-sm font-medium shadow-lg transition-colors"
        style={{ background: "var(--accent)", borderColor: "var(--accent)", color: "white" }}>
        <Clapperboard size={16} /> Play Demo
        <span className="mono ml-1 rounded-full bg-black/20 px-1.5 py-0.5 text-[10px]">~80s</span>
      </button>
    );
  }

  const isCard = scene?.kind === "card";

  // ---- active overlay (pointer-events none except controls so the real page shows) ----
  return (
    <div className="pointer-events-none fixed inset-0 z-[70]">
      {/* top progress timeline */}
      <div className="absolute inset-x-0 top-0 flex gap-1 p-2">
        {scenes.map((_, i) => (
          <div key={i} className="h-[3px] flex-1 overflow-hidden rounded-full bg-white/10">
            <div className="h-full rounded-full" style={{
              background: "var(--accent)",
              width: i < idx ? "100%" : i === idx ? `${progress * 100}%` : "0%",
              transition: i === idx ? "none" : "width .2s",
            }} />
          </div>
        ))}
      </div>

      {/* cinematic letterbox */}
      <div className="absolute inset-x-0 top-0 h-10 bg-gradient-to-b from-black/80 to-transparent" />
      <div className="absolute inset-x-0 bottom-0 h-40 bg-gradient-to-t from-black/85 via-black/40 to-transparent" />

      {/* intro / outro full cards */}
      <AnimatePresence>
        {isCard && (
          <motion.div key={idx} initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            transition={{ duration: 0.6 }}
            className="absolute inset-0 grid place-items-center"
            style={{ background: "radial-gradient(1200px 600px at 50% 40%, rgba(15,19,26,.96), rgba(10,12,16,.99))" }}>
            <motion.div initial={{ y: 18, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.15, duration: 0.7 }}
              className="max-w-2xl px-8 text-center">
              <div className="mb-5 inline-flex items-center gap-2.5">
                <div className="grid h-10 w-10 place-items-center rounded-lg" style={{ background: "var(--accent-dim)" }}>
                  <ShieldCheck size={22} style={{ color: "var(--accent)" }} />
                </div>
              </div>
              <div className="mono mb-3 text-xs tracking-[0.25em]" style={{ color: "var(--accent)" }}>{scene.eyebrow}</div>
              <h1 className="text-balance text-3xl font-semibold leading-tight tracking-tight">{scene.title}</h1>
              {scene.caption && (
                <div className="mono mt-4 flex items-center justify-center gap-2 text-sm text-muted">
                  {idx === scenes.length - 1 && <Code2 size={14} />} {scene.caption}
                </div>
              )}
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* caption bar */}
      {!isCard && (
        <AnimatePresence mode="wait">
          <motion.div key={idx} initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} exit={{ opacity: 0 }}
            transition={{ duration: 0.45 }}
            className="absolute inset-x-0 bottom-16 flex justify-center px-6">
            <div className="max-w-3xl text-center">
              <div className="mono mb-1.5 text-[11px] tracking-widest" style={{ color: "var(--accent)" }}>
                {String(idx).padStart(2, "0")} · {scene.title}
              </div>
              <div className="text-balance text-lg font-medium text-white drop-shadow">{scene.caption}</div>
            </div>
          </motion.div>
        </AnimatePresence>
      )}

      {/* controls */}
      <div className="pointer-events-auto absolute bottom-4 left-1/2 flex -translate-x-1/2 items-center gap-1 rounded-full border border-white/10 bg-black/60 px-2 py-1.5 backdrop-blur">
        <Ctrl onClick={() => goTo(idx - 1)} title="Previous"><ChevronLeft size={16} /></Ctrl>
        <Ctrl onClick={togglePause} title="Play/Pause">{paused ? <Play size={16} /> : <Pause size={16} />}</Ctrl>
        <Ctrl onClick={() => goTo(idx + 1)} title="Next"><ChevronRight size={16} /></Ctrl>
        <Ctrl onClick={() => goTo(0)} title="Restart"><RotateCcw size={15} /></Ctrl>
        <div className="mono px-2 text-[11px] text-white/60">{idx + 1}/{scenes.length}</div>
        <Ctrl onClick={stop} title="Exit"><X size={16} /></Ctrl>
      </div>
    </div>
  );
}

function Ctrl({ children, onClick, title }: { children: React.ReactNode; onClick: () => void; title: string }) {
  return (
    <button onClick={onClick} title={title}
      className="grid h-8 w-8 place-items-center rounded-full text-white/80 transition-colors hover:bg-white/10 hover:text-white">
      {children}
    </button>
  );
}
