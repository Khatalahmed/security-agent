"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import { api } from "@/lib/api";
import { MonitorPlay, Play, Pause, SkipForward, SkipBack, X, MousePointer2 } from "lucide-react";

/* A driven product tour: it navigates the REAL pages, moves a synthetic cursor,
   spotlights live elements, and shows captions. Nothing is faked — it operates
   the actual app and highlights real data. */

interface Step {
  route: string;
  sel: string;          // data-tour selector to spotlight on that page
  cap: string;
  ms: number;
  click?: boolean;      // play a click ripple on the target
  pad?: number;
}

function buildSteps(heroId: string | null): Step[] {
  const detail = heroId ? `/findings/${encodeURIComponent(heroId)}` : "/findings";
  return [
    { route: "/", sel: "[data-tour=ollama]", cap: "100% local — inference runs on Ollama, on your machine.", ms: 6500 },
    { route: "/", sel: "[data-tour=pipeline]", cap: "Deterministic program analysis, then the local model reasons over the evidence — with a human gate.", ms: 8000, pad: 10 },
    { route: "/scan/new", sel: "[data-tour=scan-form]", cap: "Point it at any repo or path. The source never leaves this machine.", ms: 8000, pad: 10 },
    { route: "/findings", sel: "[data-tour=filters]", cap: "Every finding across scans — filter by severity, analysis method, and review status.", ms: 7500 },
    { route: "/findings", sel: "[data-tour=finding-row][data-method=taint]", cap: "A cross-file taint finding — opening it…", ms: 5500, click: true },
    { route: detail, sel: "[data-tour=dataflow]", cap: "Cross-file taint: attacker input traced to a dangerous sink, across multiple files.", ms: 10000, pad: 8 },
    { route: detail, sel: "[data-tour=confirm]", cap: "It stays a candidate until a human confirms it. The model never auto-confirms.", ms: 7500 },
    { route: "/benchmarks", sel: "[data-tour=bench]", cap: "Measured on labeled corpora — and the false positives are shown too. Honest evaluation.", ms: 8500, pad: 8 },
  ];
}

interface Rect { top: number; left: number; width: number; height: number; }

function waitFor(sel: string, timeout = 3000): Promise<HTMLElement | null> {
  return new Promise((resolve) => {
    const t0 = performance.now();
    const tick = () => {
      const el = document.querySelector(sel) as HTMLElement | null;
      if (el) return resolve(el);
      if (performance.now() - t0 > timeout) return resolve(null);
      requestAnimationFrame(tick);
    };
    tick();
  });
}

export function GuidedTour() {
  const router = useRouter();
  const pathname = usePathname();
  const [active, setActive] = useState(false);
  const [playing, setPlaying] = useState(false);
  const [i, setI] = useState(0);
  const [heroId, setHeroId] = useState<string | null>(null);
  const [rect, setRect] = useState<Rect | null>(null);
  const [cursor, setCursor] = useState<{ x: number; y: number }>({ x: -100, y: -100 });
  const [clicking, setClicking] = useState(false);
  const [cap, setCap] = useState("");
  const [ended, setEnded] = useState(false);
  const steps = useRef<Step[]>(buildSteps(null));
  const advTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // fetch a hero taint finding id once
  useEffect(() => {
    api.findings().then((fs) => {
      const taint = fs
        .filter((f) => Array.isArray(f.evidence?.chain) && (f.evidence!.chain as string[]).length >= 2)
        .sort((a, b) => (b.evidence!.chain as string[]).length - (a.evidence!.chain as string[]).length);
      const id = (taint[0] ?? fs[0])?.id ?? null;
      setHeroId(id); steps.current = buildSteps(id);
    }).catch(() => {});
  }, []);

  const start = useCallback(() => {
    steps.current = buildSteps(heroId);
    setEnded(false); setActive(true); setPlaying(true); setI(0);
  }, [heroId]);

  // autostart via ?tour=1 (read from the URL without useSearchParams/Suspense)
  useEffect(() => {
    if (heroId && typeof window !== "undefined" && new URLSearchParams(window.location.search).get("tour") === "1") start();
  }, [heroId, start]);

  const place = useCallback(async (step: Step, alive: () => boolean) => {
    setCap(step.cap);                         // caption immediately (current step)
    if (pathname !== step.route) { router.push(step.route); return; } // re-runs after nav
    const el = await waitFor(step.sel);
    if (!alive()) return;
    if (!el) { setRect(null); return; }
    el.scrollIntoView({ behavior: "smooth", block: "center" });
    await new Promise((r) => setTimeout(r, 520));
    if (!alive()) return;
    const pad = step.pad ?? 6;
    const measure = () => {
      const b = el.getBoundingClientRect();
      setRect({ top: b.top - pad, left: b.left - pad, width: b.width + pad * 2, height: b.height + pad * 2 });
      setCursor({ x: b.left + Math.min(b.width / 2, 120), y: b.top + Math.min(b.height / 2, 32) });
    };
    measure();
    setTimeout(() => alive() && measure(), 700);   // re-measure after async content (e.g. the graph) renders
    if (step.click) {
      await new Promise((r) => setTimeout(r, 900));
      if (!alive()) return;
      setClicking(true); setTimeout(() => alive() && setClicking(false), 500);
    }
  }, [pathname, router]);

  // run current step (cancellation-safe; re-runs when pathname settles after nav)
  useEffect(() => {
    if (!active) return;
    const step = steps.current[i];
    if (!step) { setEnded(true); setPlaying(false); return; }
    let cancelled = false;
    place(step, () => !cancelled);
    return () => { cancelled = true; };
  }, [active, i, heroId, place]);

  // auto-advance
  useEffect(() => {
    if (!active || !playing || ended) return;
    const step = steps.current[i];
    if (!step) return;
    advTimer.current = setTimeout(() => {
      if (i >= steps.current.length - 1) { setEnded(true); setPlaying(false); }
      else setI((n) => n + 1);
    }, step.ms);
    return () => { if (advTimer.current) clearTimeout(advTimer.current); };
  }, [active, playing, i, ended]);

  // keyboard
  useEffect(() => {
    if (!active) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") exit();
      else if (e.key === " ") { e.preventDefault(); setPlaying((p) => !p); }
      else if (e.key === "ArrowRight") { setPlaying(false); setI((n) => Math.min(steps.current.length - 1, n + 1)); }
      else if (e.key === "ArrowLeft") { setPlaying(false); setI((n) => Math.max(0, n - 1)); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [active]);

  const exit = () => { setActive(false); setPlaying(false); setI(0); setRect(null); setEnded(false); };

  // launcher (hidden on /demo)
  if (!active) {
    if (pathname.startsWith("/demo")) return null;
    return (
      <button onClick={start}
        className="fixed bottom-5 right-5 z-40 flex items-center gap-2 rounded-full px-4 py-2.5 text-sm font-semibold text-white shadow-lg"
        style={{ background: "var(--accent)" }}>
        <MonitorPlay size={16} /> Guided tour
      </button>
    );
  }

  const capBelow = rect ? rect.top + rect.height + 150 < window.innerHeight : true;

  return (
    <div className="fixed inset-0 z-50" aria-hidden>
      {/* spotlight dim + cutout */}
      {rect ? (
        <div className="pointer-events-none absolute transition-all duration-700"
          style={{
            top: rect.top, left: rect.left, width: rect.width, height: rect.height,
            borderRadius: 12, border: "1.5px solid var(--accent)",
            boxShadow: "0 0 0 9999px rgba(7,9,13,.74), 0 0 34px 2px rgba(59,130,246,.55)",
            transitionTimingFunction: "cubic-bezier(.4,0,.2,1)",
          }} />
      ) : (
        <div className="pointer-events-none absolute inset-0" style={{ background: "rgba(7,9,13,.74)" }} />
      )}

      {/* caption callout */}
      {cap && !ended && (
        <div className="pointer-events-none absolute max-w-md transition-all duration-500"
          style={rect
            ? { left: Math.min(Math.max(12, rect.left), window.innerWidth - 400), top: capBelow ? rect.top + rect.height + 16 : Math.max(12, rect.top - 96) }
            : { left: "50%", top: "42%", transform: "translateX(-50%)" }}>
          <div className="anim-fadeup rounded-xl border border-border bg-panel/95 px-4 py-3 shadow-2xl backdrop-blur">
            <div className="mono mb-1 text-[10px] uppercase tracking-widest text-faint">step {i + 1} / {steps.current.length}</div>
            <div className="text-sm leading-relaxed text-fg">{cap}</div>
          </div>
        </div>
      )}

      {/* synthetic cursor */}
      <div className="pointer-events-none absolute left-0 top-0 transition-transform duration-700"
        style={{ transform: `translate(${cursor.x}px, ${cursor.y}px)`, transitionTimingFunction: "cubic-bezier(.4,0,.2,1)" }}>
        {clicking && <span className="absolute -left-3 -top-3 h-9 w-9 rounded-full" style={{ animation: "ringPulse .5s ease-out", boxShadow: "0 0 0 2px var(--accent)" }} />}
        <MousePointer2 size={22} className="drop-shadow-lg" style={{ color: "#fff", fill: "var(--accent)" }} />
      </div>

      {/* end overlay */}
      {ended && (
        <div className="absolute inset-0 flex flex-col items-center justify-center gap-4 bg-bg/85 backdrop-blur">
          <div className="anim-fadeup text-center">
            <div className="text-[12px] font-semibold uppercase tracking-[0.3em] text-faint">Local Security Agent</div>
            <h2 className="mt-3 text-3xl font-semibold tracking-tight">Local Ollama · program analysis · LLM reasoning</h2>
            <p className="mono mt-3 text-sm text-muted">github.com/Khatalahmed/security-agent</p>
          </div>
          <div className="flex gap-3">
            <button onClick={start} className="rounded-md px-4 py-2 text-sm font-semibold text-white" style={{ background: "var(--accent)" }}>Replay</button>
            <button onClick={exit} className="rounded-md border border-border px-4 py-2 text-sm text-muted">Exit</button>
          </div>
        </div>
      )}

      {/* controls */}
      <div className="absolute bottom-5 left-1/2 z-10 flex -translate-x-1/2 items-center gap-2 rounded-full border border-border bg-panel/95 px-3 py-2 shadow-xl backdrop-blur">
        <Ctl onClick={() => { setPlaying(false); setI((n) => Math.max(0, n - 1)); }}><SkipBack size={15} /></Ctl>
        <Ctl onClick={() => setPlaying((p) => !p)} primary>{playing ? <Pause size={15} /> : <Play size={15} />}</Ctl>
        <Ctl onClick={() => { setPlaying(false); setI((n) => Math.min(steps.current.length - 1, n + 1)); }}><SkipForward size={15} /></Ctl>
        <div className="mx-1 flex items-center gap-1">
          {steps.current.map((_, k) => (
            <span key={k} className="h-1.5 rounded-full transition-all"
              style={{ width: k === i ? 18 : 6, background: k === i ? "var(--accent)" : "var(--border-strong)" }} />
          ))}
        </div>
        <Ctl onClick={exit}><X size={15} /></Ctl>
      </div>
    </div>
  );
}

function Ctl({ children, onClick, primary }: { children: React.ReactNode; onClick: () => void; primary?: boolean }) {
  return (
    <button onClick={onClick} className="grid h-8 w-8 place-items-center rounded-full border transition-colors"
      style={primary ? { background: "var(--accent)", borderColor: "var(--accent)", color: "#fff" } : { borderColor: "var(--border)", color: "var(--muted)" }}>
      {children}
    </button>
  );
}
