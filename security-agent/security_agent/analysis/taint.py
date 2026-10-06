"""Cross-file taint audit runner.

Builds an AST call graph, finds source->sink chains (possibly across files), and
asks the LLM to judge each chain: can attacker-controlled input reach the sink
without adequate sanitization along the way? The model reasons over a *slice*
(the actual code of every function in the chain), not a single file — this is the
capability per-file analysis cannot provide.

CPU-aware: cross-file chains are analyzed first and the number of model calls is
capped (each chain = one call).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from security_agent.ai.base import AIProvider
from security_agent.analysis.callgraph import assemble_slice, build_graph, find_chains
from security_agent.findings.dedup import canonical_class
from security_agent.findings.models import Finding, State
from security_agent.skillengine.validator import normalize_enums, validate_item


def _parse(raw: str) -> tuple[list[dict], bool]:
    try:
        data = json.loads(raw)
        items = data.get("findings", []) if isinstance(data, dict) else []
        return (items if isinstance(items, list) else []), True
    except Exception:
        return [], False


def run_taint_audit(
    repo: Path, scan_id: str, provider: AIProvider, skill,
    include_globs: list[str], skip_dirs: list[str],
    start_index: int = 1, max_model_calls: int = 10,
    on_progress: Callable[[str], None] = lambda m: None,
) -> tuple[list[Finding], dict]:
    graph = build_graph(repo, include_globs, skip_dirs)
    chains = find_chains(graph)
    # Prioritize cross-file chains (the whole point); cap model calls for CPU.
    chains.sort(key=lambda c: (not c.crosses_files, len(c.funcs)))
    budget = chains[:max_model_calls]
    on_progress(f"{len(graph.all_funcs)} functions, {len(chains)} source->sink chain(s); "
                f"analyzing {len(budget)} (cross-file first)")

    stats = {"functions": len(graph.all_funcs), "chains": len(chains),
             "analyzed": len(budget), "json_ok": 0, "json_bad": 0,
             "schema_invalid": 0, "total_seconds": 0.0, "skill": skill.name,
             "parse_errors": len(graph.errors), "cleared": []}
    findings: list[Finding] = []
    counter = start_index

    for chain in budget:
        sig = " -> ".join(f"{f.file}::{f.name}" for f in chain.funcs)
        on_progress(f"chain [{chain.sink.vuln_class}] {sig}")
        slice_text = assemble_slice(chain)
        try:
            result = provider.generate(skill.system_prompt, slice_text, json=True)
        except Exception as e:      # one failed call must not discard the whole run
            stats["errors"] = stats.get("errors", 0) + 1
            on_progress(f"  ! model call failed: {e}")
            continue
        stats["total_seconds"] += result.seconds
        items, ok = _parse(result.text)
        stats["json_ok" if ok else "json_bad"] += 1
        if not ok:
            continue
        dict_items = [i for i in items if isinstance(i, dict)]
        if not dict_items:
            # The model examined the whole source->sink slice and reported nothing:
            # an explicit "this chain is neutralized" verdict. Record it so the
            # taint-authoritative merge can suppress broad per-file FPs on this flow.
            stats["cleared"].append({
                "class": canonical_class(chain.sink.vuln_class),
                "sink_file": chain.funcs[-1].file,
                "sink_line": chain.sink.lineno,
                "chain_files": sorted({f.file for f in chain.funcs}),
            })
            on_progress("  -> 0 finding(s) [chain judged neutralized]")
            continue
        for item in dict_items:
            item = normalize_enums(item, skill.finding_schema)
            if validate_item(item, skill.finding_schema):
                stats["schema_invalid"] += 1
                continue
            fid = f"F-{scan_id}-{counter:03d}"
            counter += 1
            findings.append(Finding(
                id=fid, scan_id=scan_id, source=f"{skill.name}:{provider.name}",
                target=chain.source_func.file,
                vuln_class=str(item.get("vuln_class", chain.sink.vuln_class)),
                severity=str(item.get("severity", "unknown")),
                confidence=str(item.get("confidence", "")),
                location=f"{chain.funcs[-1].file}:{chain.funcs[-1].name} "
                         f"(sink {chain.sink.callee} @ {chain.sink.lineno})",
                description=str(item.get("why", "")),
                poc=str(item.get("poc_request", "")),
                remediation=str(item.get("remediation", "")),
                state=State.CANDIDATE,
                evidence={
                    "engine": "taint",
                    "chain": [f"{f.file}::{f.name}" for f in chain.funcs],
                    "crosses_files": chain.crosses_files,
                    "sink": {"callee": chain.sink.callee, "line": chain.sink.lineno,
                             "class": chain.sink.vuln_class},
                    "raw_item": item,
                    "model_seconds": round(result.seconds, 1),
                },
            ))
        on_progress(f"  -> {len(dict_items)} finding(s)")

    stats["total_seconds"] = round(stats["total_seconds"], 1)
    return findings, stats
