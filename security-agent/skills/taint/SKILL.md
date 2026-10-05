---
name: taint
version: 0.1.0
category: source-analysis
supports: [source_audit]
engine: taint
risk_level: safe
---

# Taint — Cross-File Data-Flow

The one thing per-file analysis cannot do: follow user input **across functions
and files** to a dangerous sink and judge the whole chain. Uses an AST call graph
(`analysis/callgraph.py`) to find source→sink chains, then has the LLM reason over
a slice containing every function in the chain.

## How it differs from `source_audit`

`source_audit` sees one file at a time, so a handler in `app.py` that passes
input to a sink in `db.py` is invisible to it. This skill assembles both into one
slice and asks: does tainted data reach the sink unsanitized along the path?

## Method

1. **Build the call graph** (stdlib `ast`): functions, calls, SOURCES (read
   `request.*`, `input()`), SINKS (`subprocess`, `execute`, `render_template_string`,
   `requests.get`, `open`, `pickle.loads`, …).
2. **Find chains** SOURCE → … → function-with-SINK, following call edges across
   files. Cross-file chains are prioritized; model-call count is capped (CPU).
3. **Judge the slice** — the LLM decides if the flow is exploitable or neutralized
   somewhere along the way.

## Limitations (honest)

Call resolution is by function name (best-effort, no type/import resolution);
dynamic dispatch and callbacks are missed. It finds *candidate* chains and lets
the model + human adjudicate. Python only. All findings `CANDIDATE`.

## Run it

`python -m security_agent audit --repo <path> --skills taint`
