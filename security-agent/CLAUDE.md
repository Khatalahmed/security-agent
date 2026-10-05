# CLAUDE.md — security-agent

Local, skill-driven AI security assessment platform. **Authorized testing only.**
This file orients a contributor (human or agent); the full design/history is in
[`../DESIGN.md`](../DESIGN.md).

## What it is

A local orchestrator that drives a local LLM (Ollama) + a skill library + real
tools to produce a reviewable **finding → validation → report** package, in two
modes that share one pipeline:

- **Mode B — source audit** (`audit --repo`): skill engine over a repo; per-file
  skills + a cross-file **taint** engine (AST call-graph, source→sink chains).
- **Mode A — target recon** (`scan --target`): scope-gated attack-surface
  profiling + passive enumeration. **Recon only — no active exploitation.**

Shared: cross-skill dedup → automated validation → human gate → reports.

## Safety model (non-negotiable)

- **Refuse-by-default scope guard** (`security_agent/safety.py`): no live target is
  touched unless it's in `config/scope.txt`. Mode A is recon-only.
- **Human gate** (`findings/models.py`): the lifecycle is
  `CANDIDATE → VALIDATION_PENDING → VALIDATED → HUMAN_CONFIRMED`. Automated steps
  (skills, validator) can only advance to `VALIDATED`; `HUMAN_CONFIRMED` and
  `FALSE_POSITIVE` are **human-only**. Nothing is auto-confirmed or auto-rejected.
- **Privacy:** local Ollama keeps data on-machine. Hosted backends send analyzed
  code/evidence to an API — the CLI warns; keys come only from env vars.

## Layout

```
security_agent/            the package (zero runtime deps — stdlib only)
  cli.py                   entry point; subcommands: audit scan validate findings
                           confirm reject report knowledge
  config.py  safety.py  audit_log.py
  ai/                      provider abstraction: ollama (local) + openai/openrouter/anthropic
  findings/                Finding model + lifecycle, SQLite store, dedup + canonical_class
  skillengine/             registry · loader · planner · validator · base (Skill/Context)
  skills/ (code)           source_audit runner (per-file + knowledge injection)
  analysis/                AST call-graph + cross-file taint runner
  recon/                   profiler · analyze (LLM) · parse (robots/sitemap) · enumerate
  validation/              skeptical second-opinion runner
  rag/                     BM25 retriever · ingest · local-embedding semantic KB
  tools/                   http_probe · dns_lookup (recon I/O)
  reporting/               markdown · json · html · sarif
skills/<name>/             SKILL DATA: manifest.toml + SKILL.md + schemas/finding.json
knowledge/patterns.jsonl   RAG corpus (distilled, grows via `knowledge ingest`)
config/                    config.toml + scope.txt (the authorization allowlist)
evaluation/                fixtures + metrics + benchmark harness
tests/test_spine.py        the test suite (custom runner; exit 1 on failure)
```

## Run

```bash
pip install -e .                                   # editable; run from the project root
ollama pull qwen2.5-coder:7b                        # or set a hosted provider in config

security-agent audit --repo ../some-repo            # source audit (default skills)
security-agent audit --repo ../some-repo --skills taint   # cross-file taint
security-agent scan  --target example.com           # recon (host must be in scope.txt)
security-agent validate --scan <ID>                 # automated second opinion
security-agent confirm F-<ID>-001                   # human gate
security-agent report --scan <ID> --format all      # md/json/html/sarif
security-agent knowledge search "ssrf metadata" --class ssrf
```

## Develop & test

```bash
python tests/test_spine.py            # 155 tests, deterministic, no model needed
python -m evaluation.benchmark --mock # harness self-test (also --per-skill, --rag)
```

- **Add a skill:** create `skills/<name>/manifest.toml` (+ `SKILL.md`, `schemas/`).
  `supports`, `detects`, optional `engine = "taint"`. Add it to `[skills].enabled`
  or run with `--skills <name>`. No code change needed for a per-file skill.
- **Grow knowledge:** `security-agent knowledge add|ingest`; `knowledge embed` for
  semantic mode.

## Gotchas (learned the hard way — see DESIGN.md)

- **Stdlib only.** No third-party runtime deps. Manifests are TOML (not YAML) for
  this reason; providers/embeddings are hand-rolled over `urllib`.
- **Windows console is cp1252** — don't print non-ASCII (e.g. `→`); use ASCII.
- **In `manifest.toml`, `system_prompt` must sit above any `[table]` header** or
  TOML scopes it into that table.
- **vulnhuntr's local Ollama path is broken** (120s timeout, prompt truncation);
  the platform ships its own correct Ollama client — don't route through vulnhuntr.
- **Validation/RAG verdicts on local 7B are advisory** — benchmarks show focused
  skills, RAG, and the validator add little on easy fixtures; the human gate is
  what makes auto-steps safe. Measure before assuming value (`evaluation/`).
```
