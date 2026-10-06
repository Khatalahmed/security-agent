"""Lightweight AST call-graph + source/sink analysis (stdlib `ast`).

This is the backbone of cross-file taint reasoning. It does NOT try to be a full
dataflow engine; it builds enough structure to find *candidate* chains from an
external-input SOURCE to a dangerous SINK — possibly spanning functions and
files — and to assemble the relevant code into one slice for the LLM to judge.

Deterministic and model-free, so it is unit-tested directly.
"""
from __future__ import annotations

import ast
import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

# callee (dotted tail or bare name) -> canonical vuln class it represents
SINKS: dict[str, str] = {
    "subprocess.check_output": "command_injection", "subprocess.run": "command_injection",
    "subprocess.call": "command_injection", "subprocess.Popen": "command_injection",
    "os.system": "command_injection", "os.popen": "command_injection",
    "eval": "command_injection", "exec": "command_injection",
    "execute": "sqli", "executemany": "sqli", "executescript": "sqli",
    "render_template_string": "ssti",
    "requests.get": "ssrf", "requests.post": "ssrf", "requests.put": "ssrf",
    "requests.delete": "ssrf", "requests.head": "ssrf", "requests.request": "ssrf",
    "urlopen": "ssrf",
    "open": "path_traversal", "send_file": "path_traversal",
    "pickle.loads": "deserialization", "yaml.load": "deserialization",
    "marshal.loads": "deserialization",
}
# attribute-tail sinks that match on any receiver (obj.execute(...), etc.)
_TAIL_SINKS = {"execute", "executemany", "executescript", "urlopen",
               "render_template_string", "send_file"}
# external-input markers that make a function a taint SOURCE
_SOURCE_NAMES = {"request", "flask_request"}
_SOURCE_CALLS = {"input"}


@dataclass
class SinkHit:
    callee: str
    vuln_class: str
    lineno: int


@dataclass
class FuncInfo:
    name: str
    file: str
    lineno: int
    is_source: bool
    sinks: list[SinkHit] = field(default_factory=list)
    calls: set[str] = field(default_factory=set)       # bare callee names
    source_code: str = ""


@dataclass
class Chain:
    funcs: list[FuncInfo]
    sink: SinkHit

    @property
    def crosses_files(self) -> bool:
        return len({f.file for f in self.funcs}) > 1

    @property
    def source_func(self) -> FuncInfo:
        return self.funcs[0]


@dataclass
class Graph:
    funcs_by_name: dict[str, list[FuncInfo]]
    all_funcs: list[FuncInfo]
    errors: list[tuple[str, str]] = field(default_factory=list)


def _callee_names(call: ast.Call) -> tuple[str, str]:
    """Return (dotted, tail) names for a call's callee, best-effort."""
    f = call.func
    if isinstance(f, ast.Name):
        return f.id, f.id
    if isinstance(f, ast.Attribute):
        tail = f.attr
        parts = [tail]
        cur = f.value
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts)), tail
    return "", ""


def _analyze_function(node: ast.AST, file: str, source: str) -> FuncInfo:
    name = getattr(node, "name", "<lambda>")
    info = FuncInfo(name=name, file=file, lineno=getattr(node, "lineno", 0),
                    is_source=False)
    try:
        info.source_code = ast.get_source_segment(source, node) or ""
    except Exception:
        info.source_code = ""

    for sub in ast.walk(node):
        if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name):
            if sub.value.id in _SOURCE_NAMES:
                info.is_source = True
        if isinstance(sub, ast.Name) and sub.id in _SOURCE_NAMES:
            info.is_source = True
        if isinstance(sub, ast.Call):
            dotted, tail = _callee_names(sub)
            if dotted:
                info.calls.add(dotted.split(".")[0])   # root name for graph edges
                info.calls.add(tail)
            if tail in _SOURCE_CALLS:
                info.is_source = True
            vuln = SINKS.get(dotted) or (SINKS.get(tail) if tail in _TAIL_SINKS else None)
            if vuln:
                info.sinks.append(SinkHit(callee=dotted or tail, vuln_class=vuln,
                                          lineno=getattr(sub, "lineno", info.lineno)))
    return info


def build_graph(repo: Path, include_globs: list[str], skip_dirs: list[str]) -> Graph:
    funcs_by_name: dict[str, list[FuncInfo]] = {}
    all_funcs: list[FuncInfo] = []
    errors: list[tuple[str, str]] = []
    skip = set(skip_dirs)

    for p in sorted(repo.rglob("*")):
        if not p.is_file() or any(part in skip for part in p.relative_to(repo).parts):
            continue
        if not any(fnmatch.fnmatch(p.name, g) for g in include_globs):
            continue
        try:
            src = p.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(src)
        except (SyntaxError, ValueError) as e:
            errors.append((str(p), str(e)))
            continue
        rel = str(p.relative_to(repo))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                info = _analyze_function(node, rel, src)
                all_funcs.append(info)
                funcs_by_name.setdefault(info.name, []).append(info)
    return Graph(funcs_by_name=funcs_by_name, all_funcs=all_funcs, errors=errors)


def find_chains(graph: Graph, max_depth: int = 5, max_chains: int = 25) -> list[Chain]:
    """Chains from a SOURCE function to a function containing a SINK, following
    local call edges (cross-file resolved by function name)."""
    chains: list[Chain] = []

    def dfs(path: list[FuncInfo], visited: set[int]):
        if len(chains) >= max_chains or len(path) > max_depth:
            return
        cur = path[-1]
        for sink in cur.sinks:
            chains.append(Chain(funcs=list(path), sink=sink))
            if len(chains) >= max_chains:
                return
        for callee in cur.calls:
            for target in graph.funcs_by_name.get(callee, []):
                if id(target) in visited:
                    continue
                dfs(path + [target], visited | {id(target)})

    for f in graph.all_funcs:
        if f.is_source:
            dfs([f], {id(f)})
    return chains


def assemble_slice(chain: Chain) -> str:
    """Concatenate the source of every function in the chain, with headers."""
    parts = [f"# Source->sink chain for {chain.sink.vuln_class} "
             f"(sink: {chain.sink.callee} @ line {chain.sink.lineno})", ""]
    for i, f in enumerate(chain.funcs):
        role = "SOURCE (external input)" if i == 0 else "callee"
        if f.sinks:
            role += " [contains SINK]"
        parts.append(f"# --- {f.file} :: {f.name}  [{role}] ---")
        parts.append(f.source_code or "# (source unavailable)")
        parts.append("")
    return "\n".join(parts)
