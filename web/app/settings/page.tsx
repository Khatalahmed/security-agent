"use client";
import { api } from "@/lib/api";
import { useAsync } from "@/lib/use-async";
import { Loading, ErrorState, PageTitle } from "@/components/states";
import { Lock, Cpu, Check, X } from "lucide-react";

export default function SettingsPage() {
  const cfg = useAsync(() => api.config(), []);
  const oll = useAsync(() => api.ollama(), []);
  if (cfg.loading || oll.loading) return <Loading />;
  if (cfg.error) return <ErrorState message={cfg.error} />;
  const c = cfg.data!, o = oll.data;

  const Row = ({ k, v }: { k: string; v: React.ReactNode }) => (
    <div className="flex items-center justify-between border-b border-border/60 py-2 text-sm last:border-0">
      <span className="text-muted">{k}</span><span className="mono">{v}</span>
    </div>
  );

  return (
    <div className="max-w-2xl">
      <PageTitle title="Settings" subtitle="Read-only view of the engine’s active configuration. No secrets are exposed." />
      <div className="card p-5">
        <div className="mb-3 flex items-center gap-2 text-sm font-semibold"><Cpu size={15} /> Inference</div>
        <Row k="Provider" v={c.provider} />
        <Row k="Model" v={c.model} />
        <Row k="Endpoint" v={c.base_url} />
        <Row k="Context window" v={c.num_ctx} />
        <Row k="Local-only" v={c.local_only ? <span style={{ color: "var(--ok)" }}><Check size={13} className="inline" /> yes</span> : <span style={{ color: "var(--high)" }}><X size={13} className="inline" /> hosted</span>} />
        <Row k="Enabled skills" v={c.skills_enabled.join(", ")} />
      </div>

      <div className="card mt-4 p-5">
        <div className="mb-3 flex items-center gap-2 text-sm font-semibold"><Lock size={15} /> Ollama</div>
        <Row k="Status" v={o?.online ? <span style={{ color: "var(--ok)" }}>online</span> : <span style={{ color: "var(--crit)" }}>offline</span>} />
        <Row k="Models present" v={o?.models?.join(", ") || "—"} />
        <Row k="Active model present" v={o?.model_present ? "yes" : "no"} />
        {o?.error && <Row k="Error" v={<span style={{ color: "var(--crit)" }}>{o.error}</span>} />}
      </div>

      <p className="mt-4 text-xs text-faint">
        Model/provider are configured in <span className="mono">security-agent/config/config.toml</span>. API keys (for hosted
        providers, if ever enabled in the CLI) come only from environment variables and are never read by this UI.
      </p>
    </div>
  );
}
