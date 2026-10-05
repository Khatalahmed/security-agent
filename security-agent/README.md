# security-agent

A **local, skill-driven AI security assessment platform**. Ollama is the local
reasoning backend; this project is the agent/skill runtime. See
[`../DESIGN.md`](../DESIGN.md) for the full architecture.

> **Authorized use only.** Live-target scanning is refuse-by-default: a target
> must be listed in `config/scope.txt` (hosts you own or are explicitly
> authorized to test). All findings are **candidate** until *you* confirm them.

## Status — Phase 1 (spine + working local source-audit)

| Layer | State |
|-------|-------|
| CLI (`audit`, `scan`, `findings`, `confirm`, `reject`, `report`) | ✅ |
| Safety: refuse-by-default scope guard + audit log | ✅ |
| AI layer: provider abstraction + correct Ollama client | ✅ |
| Findings: SQLite store + enforced lifecycle + human gate | ✅ |
| Skill library: `source_audit`, `secrets`, `ssrf`, `sqli`, `idor`, `ssti` (Phase 3) | ✅ |
| Skill engine: registry · loader · planner · validator · enabled-filter | ✅ |
| Cross-skill finding de-duplication (evidence-graph seed) | ✅ |
| Evaluation harness + benchmark (Phase 1.5) | ✅ |
| Reporting: Markdown | ✅ |
| Mode A target scanning: recon profiler + `recon` skill (scope-gated, recon-only) | ✅ |
| Active vuln testing of live targets (payloads/exploitation) | ⛔ out of scope by design |
| Cross-file taint: AST call-graph + source→sink chain reasoning (`--skills taint`) | ✅ |
| Backends: Ollama (local) + OpenAI / OpenRouter / Anthropic (hosted, env-var keys) | ✅ |
| Report exports: Markdown · JSON · HTML · SARIF 2.1.0 (`report --format all`) | ✅ |
| Automated validation: skeptical second opinion → VALIDATED (`validate`) | ✅ |
| Knowledge RAG: BM25 over distilled patterns, grounds prompts (`audit --rag`, `knowledge`) | ✅ |
| Mode A enumeration: robots/sitemap parsing + passive subdomain DNS (`scan --subdomains`) | ✅ |
| Semantic RAG: local Ollama embeddings + cosine, BM25 fallback (`knowledge embed`) | ✅ |
| RAG effectiveness A/B benchmark (`benchmark --rag`) — null on current fixtures | ✅ |
| vulnhuntr adapter · richer knowledge corpus | ⏳ later |
| Active vuln testing of live targets | ⛔ out of scope by design |

## Requirements
- Python 3.11+ (uses stdlib only — `tomllib`, `sqlite3`, `urllib`; hosted backends too)
- For local runs: [Ollama](https://ollama.com) running with a code model pulled:
  ```bash
  ollama pull qwen2.5-coder:7b
  ```
- For a stronger (hosted) model, set `provider` in `config/config.toml` and export the key:
  ```bash
  # anthropic | openai | openrouter — key read from the env var, never stored
  export ANTHROPIC_API_KEY=...
  ```
  **Privacy:** a hosted backend sends the analyzed code/evidence to that API. Keep
  `provider = "ollama"` to stay fully offline. The CLI warns on every hosted run.

## Usage

Run from this directory (`security-agent/`):

```bash
# Source-code audit of a local repo (runs the default skills: source_audit + secrets)
python -m security_agent audit --repo ../proof-modeB/vuln_app

# Run specific focused skills instead (opt-in; each is a separate LLM pass per file)
python -m security_agent audit --repo ../proof-modeB/vuln_app --skills ssrf,sqli,ssti

# Cross-file taint: follow user input across functions/files to a sink (Python)
python -m security_agent audit --repo ../some-python-repo --skills taint

# RAG: ground skill prompts with retrieved disclosed-vulnerability patterns
python -m security_agent audit --repo ../proof-modeB/vuln_app --rag
python -m security_agent knowledge search "ssrf cloud metadata" --class ssrf
python -m security_agent knowledge ingest --dir ../hackerone-reports   # grow the corpus
# Semantic retrieval (local embeddings): pull an embed model, build the cache, enable it
#   ollama pull nomic-embed-text
python -m security_agent knowledge embed      # then set [rag].mode = "semantic" in config

# ...or a public GitHub repo (shallow-cloned into .work/)
python -m security_agent audit --repo https://github.com/user/project

# Automated second opinion: promotes credible findings CANDIDATE -> VALIDATED
# (never auto-rejects/auto-confirms; skips deterministic recon facts)
python -m security_agent validate --scan <SCAN_ID>

# Review what it found (candidate/validated until you confirm)
python -m security_agent findings --scan <SCAN_ID>

# Human gate
python -m security_agent confirm F-<SCAN_ID>-001   # -> HUMAN_CONFIRMED
python -m security_agent reject  F-<SCAN_ID>-002    # -> FALSE_POSITIVE

# (Re)generate the report — Markdown by default, or any/all formats
python -m security_agent report --scan <SCAN_ID>
python -m security_agent report --scan <SCAN_ID> --format all      # md + json + html + sarif
python -m security_agent report --scan <SCAN_ID> --format sarif --out findings.sarif  # for CI

# Live target recon (scope-guarded: host MUST be in config/scope.txt, else refused)
python -m security_agent scan --target example.com            # recon profile + LLM analysis
python -m security_agent scan --target example.com --no-llm   # deterministic recon only
python -m security_agent scan --targets targets.txt           # multiple targets
python -m security_agent scan --target example.com --subdomains  # + passive DNS subdomain enum
# Recon only — no active exploitation is performed against targets.
```

Configuration lives in `config/config.toml`; the authorization allowlist in
`config/scope.txt`.

## What's deliberately honest here
- The source-audit skill does **per-file** analysis (good for same-file sink
  bugs). Cross-function / cross-file taint tracing (vulnhuntr's strength) is a
  later phase.
- The model only ever produces **candidate** findings. The
  `VALIDATED → HUMAN_CONFIRMED` transition is reserved for your explicit action.
- Files larger than `audit.max_file_kb` are skipped (they'd exceed the model's
  context window) and listed in the run stats.
