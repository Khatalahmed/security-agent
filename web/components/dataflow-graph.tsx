"use client";
import { useMemo, useState } from "react";
import {
  ReactFlow, Background, Controls, Handle, Position,
  type Node, type Edge, type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import type { DataFlow, DataFlowNode, DataFlowRole } from "@/lib/types";
import { FileCode2, Radio, ArrowRightLeft, ShieldAlert, Crosshair, Bug } from "lucide-react";

const ROLE: Record<DataFlowRole, { color: string; bg: string; icon: typeof Radio; title: string }> = {
  source:         { color: "var(--accent)", bg: "rgba(59,130,246,.12)", icon: Radio, title: "SOURCE" },
  transformation: { color: "var(--muted)",  bg: "rgba(139,152,169,.10)", icon: ArrowRightLeft, title: "TRANSFORMATION" },
  sanitizer:      { color: "var(--ok)",     bg: "rgba(34,197,94,.12)", icon: ShieldAlert, title: "SANITIZER / GUARD" },
  sink:           { color: "var(--high)",   bg: "rgba(251,146,60,.14)", icon: Crosshair, title: "SINK" },
  finding:        { color: "var(--crit)",   bg: "rgba(244,63,94,.14)", icon: Bug, title: "FINDING" },
};

type FlowNodeData = DataFlowNode & { onPick: (n: DataFlowNode) => void; selected: boolean };

function FlowNode({ data }: NodeProps) {
  const d = data as unknown as FlowNodeData;
  const r = ROLE[d.role] ?? ROLE.transformation;
  const Icon = r.icon;
  return (
    <div onClick={() => d.onPick(d)}
      className="w-[260px] cursor-pointer rounded-lg border px-3 py-2.5 text-left transition-shadow"
      style={{
        background: r.bg, borderColor: `${r.color}${d.selected ? "" : "55"}`,
        boxShadow: d.selected ? `0 0 0 1px ${r.color}, 0 8px 24px -8px ${r.color}66` : "none",
      }}>
      <Handle type="target" position={Position.Top} style={{ background: r.color, border: "none", width: 7, height: 7 }} />
      <div className="flex items-center gap-1.5 text-[10px] font-semibold tracking-widest" style={{ color: r.color }}>
        <Icon size={12} /> {r.title}
      </div>
      <div className="mt-1 truncate text-sm font-medium text-fg">{d.label}</div>
      {d.file && (
        <div className="mono mt-0.5 flex items-center gap-1 truncate text-[11px] text-muted">
          <FileCode2 size={11} /> {d.file}{d.function ? `::${d.function}` : ""}
        </div>
      )}
      <Handle type="source" position={Position.Bottom} style={{ background: r.color, border: "none", width: 7, height: 7 }} />
    </div>
  );
}

const nodeTypes = { flow: FlowNode };

export function DataFlowGraph({ flow }: { flow: DataFlow }) {
  const [picked, setPicked] = useState<DataFlowNode | null>(null);

  const { nodes, edges } = useMemo(() => {
    const ns: Node[] = flow.nodes.map((n, i) => ({
      id: n.id, type: "flow", position: { x: 40, y: i * 130 },
      data: { ...n, selected: picked?.id === n.id, onPick: setPicked },
      draggable: false,
    }));
    const es: Edge[] = flow.edges.map((e, i) => ({
      id: `e${i}`, source: e.from, target: e.to, animated: true,
      style: { stroke: "var(--border-strong)", strokeWidth: 1.5 },
    }));
    return { nodes: ns, edges: es };
  }, [flow, picked]);

  return (
    <div className="grid gap-3 lg:grid-cols-[1fr_300px]">
      <div className="card" style={{ height: 520 }}>
        <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes}
          fitView fitViewOptions={{ padding: 0.2 }} proOptions={{ hideAttribution: true }}
          nodesConnectable={false} nodesDraggable={false} panOnScroll zoomOnScroll={false}>
          <Background color="#1b2430" gap={22} />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>
      <div className="card-2 p-4">
        {picked ? (
          <div>
            <div className="text-[10px] font-semibold tracking-widest" style={{ color: ROLE[picked.role].color }}>
              {ROLE[picked.role].title}
            </div>
            <div className="mt-1 text-sm font-medium">{picked.label}</div>
            {picked.file && <div className="mono mt-2 text-xs text-muted">{picked.file}{picked.function ? `::${picked.function}` : ""}</div>}
            {picked.detail && <p className="mt-3 text-xs leading-relaxed text-muted">{picked.detail}</p>}
          </div>
        ) : (
          <div className="text-xs text-faint">
            <div className="mb-2 font-medium text-muted">Source → Sink chain</div>
            Click any node to inspect its file, function, and role. This graph is
            built from the engine’s stored taint evidence — not fabricated.
            {flow.crosses_files && <div className="mt-3 rounded border border-border px-2 py-1 text-[11px]">spans multiple files</div>}
          </div>
        )}
      </div>
    </div>
  );
}
