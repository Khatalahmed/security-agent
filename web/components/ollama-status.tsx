"use client";
import { useEffect, useState } from "react";
import { Cpu } from "lucide-react";
import { api } from "@/lib/api";
import type { OllamaStatus } from "@/lib/types";

export function OllamaBadge() {
  const [s, setS] = useState<OllamaStatus | null>(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let alive = true;
    const tick = () => api.ollama().then((d) => alive && (setS(d), setLoaded(true)))
      .catch(() => alive && (setS(null), setLoaded(true)));
    tick();
    const t = setInterval(tick, 15000);
    return () => { alive = false; clearInterval(t); };
  }, []);

  const online = s?.online;
  const color = !loaded ? "var(--faint)" : online ? "var(--ok)" : "var(--crit)";
  return (
    <div className="card-2 flex items-center gap-3 px-3 py-1.5" title={s?.endpoint}>
      <span className="relative flex h-2.5 w-2.5">
        {online && <span className="absolute inline-flex h-full w-full animate-ping rounded-full opacity-60" style={{ background: color }} />}
        <span className="relative inline-flex h-2.5 w-2.5 rounded-full" style={{ background: color }} />
      </span>
      <div className="leading-tight">
        <div className="flex items-center gap-1.5 text-xs font-medium">
          <Cpu size={12} className="text-muted" />
          {!loaded ? "Checking Ollama…" : online ? "Ollama Online" : "Ollama Offline"}
        </div>
        <div className="mono text-[10px] text-faint">
          {online ? `${s?.active_model} · local inference` : s === null ? "backend unreachable" : "start `ollama serve`"}
        </div>
      </div>
    </div>
  );
}
