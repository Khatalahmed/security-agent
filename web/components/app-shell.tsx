"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard, ScanLine, ListChecks, Share2, FlaskConical,
  FileText, Settings, ShieldCheck, Lock,
} from "lucide-react";
import { OllamaBadge } from "./ollama-status";
import { cls } from "@/lib/ui";

const NAV = [
  { href: "/", label: "Overview", icon: LayoutDashboard },
  { href: "/scan/new", label: "New Scan", icon: ScanLine },
  { href: "/scans", label: "Scans", icon: ListChecks },
  { href: "/findings", label: "Findings", icon: ShieldCheck },
  { href: "/dataflow", label: "Data Flow", icon: Share2 },
  { href: "/benchmarks", label: "Benchmarks", icon: FlaskConical },
  { href: "/reports", label: "Reports", icon: FileText },
  { href: "/settings", label: "Settings", icon: Settings },
];

export function AppShell({ children }: { children: React.ReactNode }) {
  const path = usePathname();
  return (
    <div className="flex min-h-screen">
      <aside className="hidden w-60 shrink-0 flex-col border-r border-border bg-panel md:flex">
        <div className="flex items-center gap-2.5 border-b border-border px-4 py-4">
          <div className="grid h-8 w-8 place-items-center rounded-md" style={{ background: "var(--accent-dim)" }}>
            <ShieldCheck size={18} style={{ color: "var(--accent)" }} />
          </div>
          <div className="leading-tight">
            <div className="text-sm font-semibold tracking-tight">Local Security Agent</div>
            <div className="text-[10px] text-faint">AppSec analysis · running locally</div>
          </div>
        </div>
        <nav className="flex-1 space-y-0.5 p-2">
          {NAV.map(({ href, label, icon: Icon }) => {
            const active = href === "/" ? path === "/" : path.startsWith(href);
            return (
              <Link key={href} href={href}
                className={cls(
                  "flex items-center gap-2.5 rounded-md px-3 py-2 text-sm transition-colors",
                  active ? "bg-panel2 text-fg" : "text-muted hover:bg-panel2 hover:text-fg"
                )}
                style={active ? { boxShadow: "inset 2px 0 0 var(--accent)" } : undefined}>
                <Icon size={16} className={active ? "" : "opacity-70"} />
                {label}
              </Link>
            );
          })}
        </nav>
        <div className="border-t border-border p-3 text-[10px] text-faint">
          <div className="flex items-center gap-1.5"><Lock size={11} /> Source stays on this machine</div>
          <div className="mt-1 mono">local-only · Ollama</div>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-between gap-3 border-b border-border bg-bg/80 px-5 py-3 backdrop-blur">
          <div className="mono text-xs text-faint">
            {path === "/" ? "overview" : path.replace(/^\//, "")}
          </div>
          <OllamaBadge />
        </header>
        <main className="min-w-0 flex-1 p-5 lg:p-6">{children}</main>
      </div>
    </div>
  );
}
