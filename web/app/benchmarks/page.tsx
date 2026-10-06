"use client";
import { api } from "@/lib/api";
import { useAsync } from "@/lib/use-async";
import { Loading, ErrorState, Empty, PageTitle } from "@/components/states";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";

const SEMANTIC = [
  "shlex.quote()", "basename()", "int coercion", "shell=False",
  "parameterized SQL", "exact allowlists", "decode ordering",
  "cross-file taint", "second-order flows",
];

export default function BenchmarksPage() {
  const { data, loading, error } = useAsync(() => api.benchmarks(), []);
  if (loading) return <Loading />;
  if (error) return <ErrorState message={error} />;
  const all = (data ?? []).filter((b) => !b.mock && b.aggregate); // real runs only
  if (all.length === 0) return <Empty title="No committed benchmark results" hint="Run the harness (evaluation/benchmark.py); results are written to evaluation/results/." />;

  const chart = all.slice(0, 8).reverse().map((b) => ({
    name: b.file.replace(/\.json$/, "").replace(/^\d+-/, ""),
    detection: Math.round((b.aggregate!.detection_rate ?? 0) * 100),
    fp: b.aggregate!.fp_on_clean_fixtures ?? 0,
  }));

  return (
    <div>
      <PageTitle title="Benchmarks"
        subtitle="Real evaluation results, read from committed evaluation/results/*.json. Imperfect numbers are shown honestly." />

      <div className="card mb-5 p-4">
        <div className="mb-3 text-sm font-semibold">Detection rate (%) — committed runs</div>
        <div style={{ height: 260 }}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chart} margin={{ left: -18, right: 8, top: 4 }}>
              <XAxis dataKey="name" tick={{ fontSize: 10, fill: "var(--faint)" }} interval={0} angle={-12} textAnchor="end" height={54} />
              <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: "var(--faint)" }} />
              <Tooltip contentStyle={{ background: "var(--panel)", border: "1px solid var(--border)", borderRadius: 8, fontSize: 12 }} />
              <Bar dataKey="detection" radius={[3, 3, 0, 0]}>
                {chart.map((_, i) => <Cell key={i} fill="var(--accent)" />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
        <div className="mono mt-1 text-[11px] text-faint">bars = TP / planted bugs per committed run · false-positives shown in the table</div>
      </div>

      <div data-tour="bench" className="card mb-5 overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-left text-[11px] uppercase tracking-wide text-faint">
              <th className="px-3 py-2.5 font-medium">Run</th>
              <th className="px-3 py-2.5 font-medium">Mode</th>
              <th className="px-3 py-2.5 font-medium">Model</th>
              <th className="px-3 py-2.5 font-medium">Fixtures</th>
              <th className="px-3 py-2.5 font-medium">Detection</th>
              <th className="px-3 py-2.5 font-medium">FP (clean)</th>
              <th className="px-3 py-2.5 font-medium">JSON ok</th>
              <th className="px-3 py-2.5 font-medium">s/file</th>
            </tr>
          </thead>
          <tbody>
            {all.map((b) => {
              const a = b.aggregate!;
              return (
                <tr key={b.file} className="border-b border-border/60 hover:bg-panel2">
                  <td className="mono px-3 py-2 text-xs">{b.file.replace(/\.json$/, "")}</td>
                  <td className="mono px-3 py-2 text-xs text-muted">{b.mode}</td>
                  <td className="mono px-3 py-2 text-xs text-muted">{b.model}</td>
                  <td className="px-3 py-2">{a.fixtures}</td>
                  <td className="px-3 py-2"><b>{Math.round(a.detection_rate * 100)}%</b> <span className="mono text-[11px] text-faint">({a.counts.tp}/{a.counts.expected})</span></td>
                  <td className="px-3 py-2" style={{ color: a.fp_on_clean_fixtures ? "var(--high)" : "var(--ok)" }}>{a.fp_on_clean_fixtures}</td>
                  <td className="px-3 py-2">{Math.round(a.json_valid_rate * 100)}%</td>
                  <td className="mono px-3 py-2 text-xs text-muted">{a.avg_seconds_per_file}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="card p-4">
        <div className="mb-2 text-sm font-semibold">Hard semantic cases in the corpus</div>
        <div className="flex flex-wrap gap-2">
          {SEMANTIC.map((s) => <span key={s} className="mono rounded border border-border px-2 py-1 text-[11px] text-muted">{s}</span>)}
        </div>
        <p className="mt-3 text-xs text-faint">These are the distinctions the safe-twin fixtures probe (e.g. does the model credit shlex.quote / basename / parameterized SQL as safe). Honest evaluation is a feature of this project.</p>
      </div>
    </div>
  );
}
