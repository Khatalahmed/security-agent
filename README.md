# security-agent

[![ci](https://github.com/Khatalahmed/security-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/Khatalahmed/security-agent/actions/workflows/ci.yml)

A **local, skill-driven AI security assessment platform** for **authorized testing only**.
It drives a local LLM (Ollama) or a hosted model + a skill library + real tools to
produce a reviewable **finding → validation → report** package, across two modes that
share one pipeline:

- **Source audit** (`audit --repo`) — a skill engine over a repo: per-vuln-class
  skills plus a cross-file **taint** engine (AST call-graph, source→sink chains).
- **Target recon** (`scan --target`) — scope-gated attack-surface profiling and
  passive enumeration. **Recon only — no active exploitation.**

Shared pipeline: cross-skill dedup → automated validation → **human gate** → reports
(Markdown / JSON / HTML / SARIF). Zero runtime dependencies (Python stdlib only).

> ⚠️ **Authorized use only.** Live-target scanning is refuse-by-default: a host must
> be listed in `security-agent/config/scope.txt` (assets you own or are explicitly
> authorized to test). All findings are *candidate* until a human confirms them.

## Repository layout

| Path | What |
|------|------|
| [`security-agent/`](security-agent/) | the platform — package, skills, tests, CI, and its own [README](security-agent/README.md) + [CLAUDE.md](security-agent/CLAUDE.md) |
| [`DESIGN.md`](DESIGN.md) | full design spec and honest per-phase build log / measurements |
| [`proof-modeB/`](proof-modeB/) | the Phase-0 feasibility proof (vulnerable fixture + direct-Ollama probe) |

## Quick start

```bash
cd security-agent
pip install -e .                     # editable install; zero runtime deps
ollama pull qwen2.5-coder:7b         # or set a hosted provider in config/config.toml

security-agent audit --repo ../proof-modeB/vuln_app     # source audit
security-agent validate --scan <ID>                     # automated second opinion
security-agent report --scan <ID> --format all          # md / json / html / sarif
```

Full usage, architecture, and the safety model are in
[`security-agent/README.md`](security-agent/README.md) and
[`security-agent/CLAUDE.md`](security-agent/CLAUDE.md).

## Tests

```bash
cd security-agent && python tests/test_spine.py     # deterministic, no model needed
```
