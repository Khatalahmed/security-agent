"""Adapter: turn a stored Finding's evidence into a source -> sink graph.

NO security logic here and NOTHING fabricated. We only reshape data the engine
already produced: taint findings carry `evidence.chain` (an ordered list of
"file::function" steps) and `evidence.sink` ({callee,line,class}); per-file
(broad) findings carry `evidence.file`/`raw_item` but no chain. When there is no
chain we say so truthfully rather than inventing a graph.
"""
from __future__ import annotations

from typing import Any

# node roles the UI renders distinctly
SOURCE = "source"
TRANSFORM = "transformation"
SINK = "sink"
FINDING = "finding"


def _node(nid: str, role: str, label: str, **extra: Any) -> dict:
    return {"id": nid, "role": role, "label": label, **extra}


def build_dataflow(finding: dict) -> dict:
    """finding: a Finding row with `evidence` already parsed to a dict.
    Returns {"kind","nodes","edges","available",...}. `available=False` means the
    finding has no cross-file chain (e.g. a per-file broad finding) — the UI shows
    a truthful notice, not a fake diagram."""
    ev = finding.get("evidence") or {}
    chain = ev.get("chain") if isinstance(ev, dict) else None
    sink = ev.get("sink") if isinstance(ev, dict) else None

    if not chain or not isinstance(chain, list):
        return {
            "available": False,
            "reason": "per-file"
            if (isinstance(ev, dict) and ev.get("file"))
            else "no-chain",
            "message": "This finding was produced by per-file analysis, so there "
            "is no cross-file source->sink chain to render. Open the source "
            "to view the flagged line in context.",
            "nodes": [],
            "edges": [],
        }

    nodes: list[dict] = []
    edges: list[dict] = []

    # 1) external-input SOURCE (the chain's first function reads request.*/input())
    first = chain[0]
    src_file, _, src_fn = first.partition("::")
    nodes.append(_node("src", SOURCE, "External input",
                       file=src_file, function=src_fn or None,
                       detail="Attacker-controlled input enters here (request/argv/stdin)."))

    # 2) one TRANSFORMATION node per chain hop (file::function)
    prev = "src"
    for i, step in enumerate(chain):
        f, _, fn = step.partition("::")
        nid = f"hop{i}"
        role = SINK if (i == len(chain) - 1) else TRANSFORM
        label = fn or f
        nodes.append(_node(nid, role, label, file=f, function=fn or None,
                           detail=(f"Sink: {sink.get('callee')} @ line {sink.get('line')}"
                                   if role == SINK and isinstance(sink, dict)
                                   else "Data passes through this function.")))
        edges.append({"from": prev, "to": nid})
        prev = nid

    # 3) terminal FINDING node (the vuln class)
    nodes.append(_node("finding", FINDING, finding.get("vuln_class", "Finding"),
                       severity=finding.get("severity"),
                       detail=finding.get("description", "")))
    edges.append({"from": prev, "to": "finding"})

    return {
        "available": True,
        "crosses_files": bool(ev.get("crosses_files")),
        "sink": sink,
        "nodes": nodes,
        "edges": edges,
    }
