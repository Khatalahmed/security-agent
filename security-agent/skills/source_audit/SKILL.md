---
name: source_audit
version: 0.1.0
category: source-analysis
supports: [source_audit]
risk_level: safe
---

# Source Audit

Per-file static security audit of source code, performed by a local LLM with
JSON-enforced output. This is the Phase 0-proven integration (3/3 detection,
0 false positives on the evaluation fixtures) — not vulnhuntr's broken local
path.

## When to use

Mode B — auditing a repository or local source tree you hold. The planner
selects this skill for files in a supported language (see `manifest.toml`
`applies_when`).

## Method

1. Discover in-scope source files (respect `include_globs` / `skip_dirs`, and the
   `max_file_kb` ceiling so a file fits the model's `num_ctx`).
2. For each file, send one well-formed, JSON-enforced prompt (the `system_prompt`
   in `manifest.toml`) containing the file path and its full text.
3. Parse the returned `findings[]`. Each object is validated against
   `schemas/finding.json`; malformed items are counted and skipped, never crash.
4. Emit each valid finding as a **CANDIDATE**. Nothing is confirmed without human
   review (the lifecycle gate in `findings/models.py`).

## Known limitations (honest)

- **Per-file only.** Catches same-file / same-function sink bugs well; does not
  yet do cross-function or cross-file taint / data-flow tracing. That is a later
  phase (chunk + evidence-graph, or a vulnhuntr adapter on a stronger backend).
- CPU latency is real — budget tens of seconds to minutes per file locally.

## Outputs

Finding objects matching `schemas/finding.json`, persisted via the findings
store, surfaced in the Markdown report, all at state `CANDIDATE`.
