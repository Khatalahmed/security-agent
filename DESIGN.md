# Local LLM Security Research Assistant — Design Spec

> **Working name:** `reconbrain` (rename freely)
> **Primary use:** Authorized penetration testing & bug-bounty research
> **Brain:** Ollama (local model) — no data leaves the machine
> **Human-in-the-loop:** every finding is *candidate* until **you** confirm it

---

## 0. Guiding principle: authorization is a feature, not a footnote

This tool only ever runs against:
- assets **you own**, or
- targets inside the **explicit written scope** of an engagement / bug-bounty program you are enrolled in.

The design enforces this in code: **nothing runs against a target that is not in the scope allowlist.** This is the first module built and the hardest to bypass. A tool that can't prove it stayed in scope is not a *standard* pentest tool — it's a liability.

---

## 1. What the system is

A **local orchestrator** that takes one of two inputs and drives a local LLM + a library of skills + real tools to produce a reviewable **finding → PoC → report** package.

```
                    ┌──────────────────────────────┐
                    │        Orchestrator / CLI     │
                    │   (mode routing, job queue)   │
                    └───────────────┬──────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        │                           │                            │
   Scope Guard               Ollama Engine                 Skill Registry
 (allowlist, refuse-    (prompt build, JSON out,      (loads SKILL.md modules,
  by-default)            retries, ctx mgmt)            matches to task)
        │                           │                            │
        └───────────────────────────┼───────────────────────────┘
                                    │
            ┌───────────────────────┴────────────────────────┐
            │                                                  │
   MODE A: Target scan                               MODE B: Source audit
   recon → enum → per-vuln skills                    vulnhuntr + source-audit skill
            │                                                  │
            └───────────────────────┬────────────────────────┘
                                    │
                    ┌───────────────┴──────────────┐
                    │     Findings Store (states)   │
                    │  candidate→validated→confirmed│
                    └───────────────┬──────────────┘
                                    │
                          Report Generator (MD/HTML/PDF)
```

---

## 2. The three reference repos — exact role of each

| Repo | What it is | Role here | Executable? |
|------|-----------|-----------|:-----------:|
| [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) | Archive of *disclosed* HackerOne reports grouped by bug type | **Knowledge base.** You mine it to (a) author per-vuln-class skills, (b) build report templates that match real disclosure style. | No |
| [protectai/vulnhuntr](https://github.com/protectai/vulnhuntr) | LLM-assisted static analyzer that traces vulnerable data flows in source code | **Mode B engine.** Invoked directly on a repo; its output feeds the source-audit skill. | **Yes** |
| [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter) | A set of Claude *skills* for bug hunting | **Skill-format reference.** Adopt its `SKILL.md` convention wholesale so skills are portable and self-describing. | No (instructions) |

**Takeaway:** only *vulnhuntr* is a tool you run. The other two are inputs to your *skill-authoring* and *reporting* process. Don't try to "run" them — you distill them.

---

## 3. The two operating modes

### Mode A — Target scan (live, authorized hosts/apps)
```
scope-checked targets → recon skill → enumeration skill
   → per-vuln-class skills (IDOR, SSRF, XSS, SQLi, auth, logic, ...)
   → candidate findings → PoC drafts → report
```

### Mode B — Source audit (a repo / open-source project)
```
repo URL or path → vulnhuntr (LLM-assisted)
   → candidate vulns → source-audit skill interprets & ranks
   → PoC + exploit-path writeup → report
```

Both converge on the **same Findings Store and Report Generator** — that shared pipeline is what makes it feel like one standard tool instead of two scripts.

---

## 4. Full component list (the "list all of them")

### Core
1. **Orchestrator / CLI** — single entry point, subcommands, job queue, mode routing.
2. **Ollama engine layer** — model selection, prompt construction, **forced JSON output**, retries, context-window budgeting, streaming.
3. **Scope & authorization guard** — required allowlist; refuses any out-of-scope target; logs every scope decision.
4. **Skill registry / loader** — discovers `SKILL.md` modules, parses manifests, matches skills to the current task.
20. **Backend abstraction** — one interface, swappable providers (Ollama *or* a hosted model). Develop/validate skills against a strong model, then switch to Ollama for fully-local runs. Without this you can't tell whether a bad result is your *skill* or the *local model*. (Numbered 20 because it was added after the first draft; belongs in Core.)

### Skills layer
5. **Recon / asset-discovery skill**
6. **Enumeration skill** (services, endpoints, tech fingerprinting)
7. **Per-vuln-class skills** — one per HackerOne category: IDOR / broken access control, SSRF, XSS, SQLi, auth/session, business logic, info disclosure, file upload, SSTI, etc.
8. **Source-audit skill** — wraps and interprets vulnhuntr output.
9. **PoC-drafting skill** — turns a candidate into a minimal, reproducible proof.
10. **Report-writing skill** — HackerOne-style structure (title, CVSS, repro steps, impact, remediation).

### Tooling layer (real executables the skills call)
11. **Recon/enum tool wrappers** — subdomain, port, HTTP probing; wrap existing OSS, don't reinvent.
12. **vulnhuntr** — installed, invoked for Mode B.
13. **HTTP request tooling** — crafting/sending validation requests for PoCs.

### Data & output layer
14. **Findings store** — structured records (SQLite or JSON), with lifecycle state.
15. **Report generator** — Markdown → HTML/PDF per target.
16. **Evidence/artifact store** — logs, request/response captures, raw tool output, linked to each finding.

### Control / quality layer
17. **Human-in-the-loop gate** — nothing becomes `confirmed` without your review.
18. **Audit log** — every target, action, and decision, timestamped.
19. **Config** — `config.yaml` (model, concurrency, scope path, enabled skills, rate limits).

---

## 5. Repository layout

```
reconbrain/
├── cli/                  # entry point + subcommands (scan, audit, report, skills)
├── engine/
│   ├── ollama_client.py  # model calls, JSON-schema enforcement, retries
│   ├── schema.py         # Finding / Report pydantic models
│   └── store.py          # findings + evidence persistence (SQLite)
├── guard/
│   └── scope.py          # allowlist parsing + enforcement (refuse-by-default)
├── skills/
│   ├── recon/SKILL.md
│   ├── enumerate/SKILL.md
│   ├── idor/SKILL.md
│   ├── ssrf/SKILL.md
│   ├── xss/SKILL.md
│   ├── source_audit/SKILL.md
│   ├── poc/SKILL.md
│   └── report/SKILL.md
├── tools/                # thin wrappers around vulnhuntr + recon/enum OSS tools
├── reports/
│   ├── templates/        # HackerOne-style MD templates
│   └── out/              # generated reports (gitignored)
├── config/
│   ├── config.yaml
│   └── scope.txt         # the authorization allowlist
├── docs/
│   └── methodology.md    # distilled from hackerone-reports
└── tests/
```

---

## 6. The standard schemas (this is what makes LLM output reliable)

Force the model to emit **structured JSON** validated against these. Free-text output is the #1 cause of flaky local-LLM pipelines.

### SKILL.md manifest (front-matter + body — the Claude-BugHunter convention)
```markdown
---
name: ssrf-hunter
description: Identify and validate server-side request forgery on in-scope web targets.
when_to_use: An endpoint accepts a URL, hostname, or fetches a remote resource.
requires_tools: [http_client]
severity_hint: high
---

## Steps
1. Enumerate parameters that take URLs / hostnames / file paths.
2. For each, reason about whether the server fetches it server-side.
3. Propose a *validation* request (non-destructive) that proves the behavior.
4. Emit a Finding JSON object (schema below). Do NOT mark confirmed.
```

### Finding record
```json
{
  "id": "F-0001",
  "target": "app.example.com",
  "vuln_class": "ssrf",
  "title": "SSRF via image-proxy url parameter",
  "severity": "high",
  "cvss": "7.5",
  "state": "candidate",
  "evidence_refs": ["req-0001", "resp-0001"],
  "repro_steps": ["..."],
  "impact": "...",
  "remediation": "...",
  "confidence": 0.6,
  "needs_human_review": true
}
```

### State machine
```
candidate ──(automated validation passes)──> validated ──(YOU confirm)──> confirmed
    │                                              │
    └──────────────(either step fails)────────────┴──> false_positive
```
The `validated → confirmed` edge is **manual only**. That's your review gate.

---

## 7. How to make it *standard* (checklist)

1. **One entry point, consistent subcommands.** `reconbrain scan --scope config/scope.txt --targets t.txt`, `reconbrain audit --repo ./x`, `reconbrain report F-0001`.
2. **Config-driven, nothing hardcoded** — model, concurrency, scope path, enabled skills in `config.yaml`.
3. **One fixed skill schema** (`SKILL.md`), so skills are portable, self-describing, and discoverable.
4. **Structured JSON I/O** validated with pydantic — reject & retry on malformed model output.
5. **Refuse-by-default scope guard** — explicit allowlist, logged decisions, no exceptions.
6. **Finding lifecycle states** with a mandatory human gate before `confirmed`.
7. **Reproducibility** — every finding stores exact inputs/commands so a PoC re-runs.
8. **Idempotent, resumable, checkpointed jobs.**
9. **Rate limiting + politeness** per target (standard pentest etiquette, avoids self-DoS).
10. **Dry-run mode** so you develop skills without touching real targets.
11. **Audit log** of everything, exportable with the report.
12. **Tests** for the guard, schema validation, and store — the parts that must never silently fail.

---

## 8. Build order (recommended)

| Phase | Deliverable |
|------|-------------|
| 1 | Scope guard + config + CLI skeleton + findings store (the safety spine) |
| 2 | Ollama engine with enforced-JSON output + one trivial skill, end-to-end dry-run |
| 3 | **Mode B first** — wire vulnhuntr, source-audit skill, PoC + report on a sample repo (fully local, lowest risk) |
| 4 | Report generator + templates distilled from hackerone-reports |
| 5 | Mode A — recon/enum wrappers + 2–3 per-vuln-class skills against a lab target |
| 6 | Expand the skill library, add the human-review TUI, harden |

Starting with Mode B is deliberate: it runs entirely on source code you hold, needs no live targets, and exercises the whole finding→PoC→report pipeline safely.

---

## 9. Model & hardware requirements (reality check)

### This machine (measured 2026-10-05)
- **RAM:** 16 GB · **CPU:** Intel i5-1135G7 (4-core, ultrabook) · **GPU:** Intel Iris Xe integrated (no dedicated GPU, ~2 GB shared VRAM)
- **Consequence:** Ollama runs **on CPU only**. Realistic ceiling is a **7–8B model, 4-bit quantized** (~4–5 GB). Expect **a few tokens/sec** and long waits on big files. 14B is possible but painfully slow; 70B is out of reach.

### What this means for the objective
- vulnhuntr's maintainers explicitly warn open-source models "structure their output incorrectly." A **7–8B CPU model is the weakest end of that spectrum** — so Mode B on this laptop with a local model will likely produce **unreliable findings / broken JSON**. It will *run*; quality is the gamble.
- **This is why component #20 (backend abstraction) exists.** On this hardware, the practical pattern is:
  - **Develop & validate skills** against a strong hosted model (Claude/GPT) so you know the skill is correct.
  - **Run fully-local** on Ollama when privacy/offline matters, accepting lower quality — or upgrade to a machine with a dedicated GPU (≥12–16 GB VRAM) for a usable local 14–34B model.

### Rules that are non-optional on weak local models
- Pick a **code-capable** model with the largest context you can afford (long files/diffs matter for Mode B). Candidates to test: `qwen2.5-coder:7b`, `llama3.1:8b`, `deepseek-coder-v2:16b` (if RAM allows).
- Always **request JSON → validate → retry with a repair prompt** on failure. Local models drift from schemas far more than hosted ones — the validator (§6) is what keeps the pipeline alive.
- vulnhuntr points at Ollama via `OLLAMA_BASE_URL=http://localhost:11434/api/generate` + `OLLAMA_MODEL=...`. If local output is unusable, fall back to running vulnhuntr with a hosted key and have your Ollama-backed source-audit skill triage its output.

---

## 9b. Phase 3 proof results (measured 2026-10-05)

Hard facts established by actually installing and running vulnhuntr on this machine:

| Check | Result |
|---|---|
| Python 3.13 + venv | ✅ works |
| `pip install vulnhuntr` (PyPI) | ✅ installs **1.2.2** cleanly on 3.13 (no dep friction) |
| vulnhuntr CLI runs | ✅ `-l` supports claude, gpt, ollama, openrouter, claude-code, gemini-cli, codex, qwen-code; has `--dry-run`, `--budget`, `--markdown/--json/--sarif/--html` |
| `--dry-run` on sample app | ✅ parses target, estimates tokens/cost (1 file ≈ 107K tok ≈ $0.72 on sonnet API) |
| `claude-code` backend (no API key) | ❌ **broken in PyPI 1.2.2** — wheel ships without the `vulnhuntr.cli_providers` module (`ModuleNotFoundError`). Affects all 4 CLI backends. |
| `git+https://github.com/protectai/vulnhuntr` | ⚠️ installs **0.1.0** (older original; only claude/gpt/ollama, no CLI backends) — GitHub main is *behind* PyPI |
| vulnhuntr `-l ollama` on fixture | ❌ **fails** — hard-coded 120s read timeout; ~8 tok/s CPU model can't finish vulnhuntr's giant (~74K-tok) single prompt in time |
| Local model via **correct** Ollama call | ✅ **3/3 vulns found, 0 FP, 100% valid JSON** (see benchmark) |

**Gotchas to remember:**
- Pin `vulnhuntr==1.2.2` (richer reports/backends). Do **not** `pip install` from GitHub main — it's the old 0.1.0.
- The advertised **key-free `claude-code` backend does not work** in the current release (missing `cli_providers` module).
- **vulnhuntr's built-in Ollama client is broken** (`llms.py` `Ollama.send_message`): hard-codes `timeout=120`; omits `num_ctx` (→ Ollama truncates the prompt to ~4096 tokens); puts `system` *inside* `options` (Ollama ignores it); sends no `format`/schema. This trio — not model weakness — is almost certainly why the maintainers warn "OSS models don't structure output correctly." **Do not use vulnhuntr's local path; it needs patching or replacing.**
- A deliberately-vulnerable Flask fixture lives at `proof-modeB/vuln_app/app.py` (LFI + command-injection + SSRF) for scanner validation.

### Benchmark — local 7B, CORRECT integration (the decisive test)
Bypassing vulnhuntr and calling Ollama properly (`proof-modeB/audit_local.py`: top-level `system`, `format: json`, `num_ctx: 8192`, `temperature: 0.1`) on the fixture:

| Metric | Result |
|---|---|
| Detection | **3/3** (LFI, Command Injection, SSRF) — correct function + line + PoC each |
| False positives | **0** |
| JSON valid | **100%** (clean parse) |
| Latency | 165 s for a 40-line file · ~3 tok/s gen · 439 in / 332 out tokens |

**Verdict:** fully-local Mode B **is viable on this hardware for small/targeted files** — *if you write a correct Ollama client yourself*. The model reasons fine; vulnhuntr's integration was the blocker.

**Caveats that shape the platform design:**
- Test file was tiny (439 input tokens). Real repos exceed a small local context, so the platform's **source-audit skill must chunk** code (per-function / per-file) to fit `num_ctx`, instead of vulnhuntr's one-giant-prompt approach. ← validates §9c.
- This single-prompt pass caught same-function sink bugs; **cross-function taint/data-flow** (vulnhuntr's real strength) needs the chunk-plus-evidence-graph approach, not one prompt.
- CPU latency is real: budget minutes per chunk. Fine for targeted audits; slow for whole large repos. Move reasoning to a stronger/faster backend (openrouter free / hosted) when scale or depth is needed — architecture unchanged (§9c principle #2).

### Phase 1 end-to-end verification (measured 2026-10-05)
The built platform (`security-agent/`, not the throwaway script) was run on the same fixture via its own `audit` command:
- **3/3** correct classes (LFI, command injection, SSRF) — correct function + line hint each; all persisted as `CANDIDATE` (human gate held).
- **321 s** for the one file vs the minimal script's 165 s — ~2× slower because the platform's richer `SYSTEM_PROMPT` (9 vuln classes + `confidence`/`remediation` fields) produces more output tokens. Trade-off: fuller findings for more generation time. Worth revisiting prompt size if latency bites.
- JSON valid 1/1. Confirms the platform's own `ai/ollama.py` replicates the correct integration (it does **not** depend on vulnhuntr).

### Phase 1.5 evaluation harness (built 2026-10-05)
`security-agent/evaluation/` drives the real platform over labeled fixtures and scores detection + **false-positive rate on clean code** (the number the single all-vulnerable fixture could not produce):
- `fixtures/{vulnerable,safe,mixed}/` — incl. genuinely-safe code (basename+allowlist, parameterized SQL) that must yield **0** findings.
- `expected/expected.json` ground truth · `metrics.py` (vuln-class canonicalization + TP/FP/FN) · `benchmark.py` (`--mock` self-test passes 3/3, 0 FP; real run writes `results/<ts>.{json,md}`).

**First real benchmark (qwen2.5-coder:7b, 5 fixtures, 2026-10-05):**

| Metric | Result |
|---|---|
| Detection | **100%** (3/3 planted bugs: path-traversal, SQLi, command-injection) |
| **False positives on clean code** | **0** (both `safe/` fixtures → `[]`) |
| Mixed fixture | flagged only the real `command_injection`; left the safe parameterized `get_profile` alone |
| False negatives | 0% |
| JSON valid | 100% (5/5) |
| Latency | 26.1 s/file avg · 130.3 s total (small fixtures; faster than the 40-line all-bug file because fewer findings → fewer output tokens) |

**This is the number the single all-vulnerable fixture could not give:** on genuinely-safe code (basename+allowlist, parameterized SQL) the 7B local model raised **zero** false positives, and on mixed code it discriminated the vulnerable function from the safe one. Caveat: still small single-file fixtures and same-function sinks — this validates precision on easy cases, not cross-function taint or large-repo scale.

**Bug surfaced & fixed by this harness:** the first run crashed in `source_audit.py` because qwen returned a `findings` array containing a bare string (valid JSON, wrong item shape). Fixed to skip+count non-dict items (`malformed_items`); regression test added (`tests/test_spine.py` → 18/18).

### Phase 2 — skill engine (built 2026-10-05)
The single `source_audit.py` is now driven by a model-independent skill engine (DESIGN §9c principles #2–3). Two trees, cleanly split:
- **Skill data** — project-root `skills/<name>/`: `manifest.toml` (machine contract incl. the `system_prompt`), `SKILL.md` (human methodology), `schemas/finding.json` (output schema). First skill: `skills/source_audit/`.
- **Engine code** — `security_agent/skillengine/`: `loader` (parse a skill dir), `registry` (discover all, collect per-skill load errors without aborting), `planner` (select by mode + detected languages — DESIGN §9c #3), `validator` (stdlib JSON-schema subset: required/type/enum), `base` (`Skill`, `Context`).

**Decisions made:**
- **TOML, not YAML, for manifests** — keeps the platform pure-stdlib (`tomllib`); PyYAML would be the first runtime dependency. `SKILL.md` keeps a YAML front-matter header for human/portability reasons but the engine reads `manifest.toml`.
- `run_source_audit(..., skill=…)` now takes the prompt + schema from the selected skill and validates each finding against it (`schema_invalid` counter); `skill=None` preserves the legacy prompt for tests/benchmark.
- CLI `audit` path: discover → `detect_languages(repo)` → `plan()` → run each selected skill, IDs kept unique across skills in one scan. Findings now carry `source="<skill>:<provider>"` + `evidence.skill`.

**Verified:** full suite **36/36** (added loader/registry/planner/validator/language-detection tests); real end-to-end CLI audit on the path-traversal fixture selected `source_audit` via the planner and produced the correct `LFI/path traversal` CANDIDATE attributed to `source_audit:ollama`. `--mock` benchmark still 3/3, 0 FP (no regression).

**Gotcha logged:** in `manifest.toml` the `system_prompt` key must sit **above** any `[table]` header, or TOML scopes it into that table (`missing required key` at load). Caught by the registry test.

### Phase 2b — second skill + multi-skill validation (2026-10-05)
Added a second skill, `skills/secrets/` (hardcoded-credential detection), chosen because it is **language-agnostic** (`applies_when.languages = []`) — so it exercises the planner's "applies to any language" branch in a real run, and proves the engine runs *multiple* skills over one repo. Tests now **42/42** (registry sees ≥2 skills; planner selects `secrets` for both python and go repos, and neither skill for `target_scan`).

**Multi-skill end-to-end** on a file with both a hardcoded key and a command injection: both skills ran, findings correctly attributed (`secrets:ollama` vs `source_audit:ollama`). **Engine: works.**

**Honest precision finding (model, not engine):** the `secrets` skill — despite a prompt scoped to "literal secrets only" — also reported the command injection and missed the second key. The 7B local model does not reliably honor skill-scope boundaries, producing a cross-skill **duplicate**. Implications to address before scaling to many skills:
- **Per-skill output scoping** — e.g. an optional `allowed_classes` on a skill that the validator enforces (drop findings whose class is out-of-scope), and/or a stronger backend for scope-sensitive skills (§9c #2 — architecture unchanged).
- **Cross-skill dedup** — when two skills flag the same location+class, merge into one finding with multiple `source`s (feeds the evidence graph, §9c layer 7).
- This is exactly why skills run as **CANDIDATE**-only with a human gate: the review step already catches this today; the above just reduces reviewer noise.

### Phase 2c — cross-skill de-duplication (built 2026-10-05)
Implemented mitigation #2 above. `security_agent/findings/dedup.py`:
- **`canonical_class()`** — one vuln-class vocabulary for the whole platform (adds `hardcoded_secret`); `evaluation/metrics.py` now imports it instead of keeping its own copy (single source of truth).
- **`dedup_findings()`** — merges findings sharing `target` + canonical class + a **compatible code-line signature** (one `line_hint` a substring of the other, or one side has none). Conservative by design: distinct lines never merge, so two different same-class bugs in one file stay separate. The merged finding records every skill as `source="a+b"` and keeps `evidence.merged_from` / `all_sources` / `merged_raw_items` — the first real edge of the evidence graph (§9c layer 7). Max severity wins; a function-qualified location is preferred as primary.
- Wired into CLI `audit` after all skills run, before persistence; prints and logs each merge.

**Verified live:** the leaky.py multi-skill run that previously produced a duplicate now reports **3 raw → 2 findings** — the command injection seen by both `secrets` and `source_audit` collapses to one finding sourced `secrets:ollama+source_audit:ollama`, while the hardcoded key stands alone. Tests **55/55** (added canonical-class + 8 dedup cases: merge, different-class/-target/-line non-merges, source/severity/primary/evidence checks). Mock benchmark still 3/3, 0 FP after the metrics consolidation.

## 9e. Phase 3 — skill library (ported methodology, 2026-10-05)
Grew the library from 2 to **6 skills** by porting per-vuln-class methodology into the platform's shape. Per the §9d directive, these are **distilled, not copied** from the Claude-BugHunter style + disclosed-report patterns — each is original methodology text the platform owns, tested against its own fixtures.

**New focused skills** (`skills/{ssrf,sqli,idor,ssti}/`): each = `manifest.toml` (class-specific `system_prompt` with real methodology — sinks, validation checks, known bypasses — plus `applies_when`), `SKILL.md` (human methodology), `schemas/finding.json` (shared envelope). All `supports = ["source_audit"]`, `languages = []` (concept-general), `risk_level = safe`.

**Design problem this phase forced — and solved:** a growing library can't run every skill on every file (each skill is a separate LLM pass; 6 skills × ~45 s/file on CPU is unworkable). Added an **enabled filter**:
- `skillengine.filter_enabled(skills, names)` — applied after the planner; `[]` = all applicable.
- config `[skills].enabled` (ships as `["source_audit", "secrets"]` so **default audits stay fast and proven**); focused skills are opt-in.
- CLI `--skills ssti,ssrf` overrides per run.
- Flow is now: `discover → plan (mode+language) → filter_enabled (user intent) → run → dedup`.

**Relationship to `source_audit`:** the broad skill stays the default triage; focused skills are deeper, single-class alternatives you opt into (and cross-skill dedup merges any overlap). This matches §9c #3 (planner + per-class skills) without 6×-ing every default audit.

**Verified live (each focused skill, via `--skills`):**
- `ssti` on its fixture → `SSTI` at `render_template_string`, attributed `ssti:ollama`.
- `idor` on its fixture → `IDOR` at the invoice handler, attributed `idor:ollama`.
- `--skills` correctly ran only the requested skill out of 6 applicable.

Tests **65/65** (registry discovers ≥6 skills; planner selects focused skills for a python repo; `filter_enabled` default/override/unknown cases). Example fixtures live in each skill's `examples/` (kept out of `evaluation/fixtures/` so the benchmark corpus and its 100%/0-FP result stay untouched).

## 9f. Per-skill benchmark — focused vs broad (measured 2026-10-05)
Extended the harness with a `--per-skill` mode: each skill runs over the corpus and is scored only on the class it `detects` (manifest field); broad `source_audit` on all. Added 3 fixtures (ssrf/ssti/idor) and a focused-vs-broad comparison.

**Real result (qwen2.5-coder:7b), `sqli` & `ssti` vs broad, over their target + both safe fixtures:**

| Skill | Class | Focused detected | Broad detected | Focused FP elsewhere |
|---|---|--:|--:|--:|
| sqli | sqli | 1/1 | 1/1 | 0 |
| ssti | ssti | 1/1 | 1/1 | 0 |

- Broad `source_audit`: 100% (2/2) on target classes, **0 FP** on the two safe fixtures.
- Focused skills: 100% on their class, **0 FP** on non-target fixtures (no scope-drift on these cases — unlike the earlier secrets-vs-source_audit overlap), and **cheap when their class is absent** (~9–11 s to return `[]` vs ~40–58 s for a real analysis).

**Verdict (honest, and decision-relevant):** on **blatant single-bug fixtures the broad skill equals the focused skills** on both detection and FP — so focused skills do **not** yet justify their cost (one extra LLM pass each). Their hypothesized advantage — class-specific methodology (bypasses, second-order, validation nuance) catching **subtle** cases the generic "find any vuln" prompt misses — is **untested**, because the corpus only has obvious bugs. 

**Consequence for the plan:** do **not** mass-port the remaining ~18 classes on faith. First build a **hard/subtle fixture corpus** (near-misses, partial mitigations, second-order, cross-call) and re-run `--per-skill`. Port focused skills only for classes where the data shows them beating broad. Until then, the broad skill + `secrets` remain the sensible default (which is exactly what `config [skills].enabled` ships).

### Hard-fixture corpus result — the decisive test (measured 2026-10-05)
Built `evaluation/fixtures_hard/`: 8 subtle fixtures, a vulnerable + a near-identical safe one per class (ssrf/sqli/idor/ssti). Vulnerable = a real bug behind a bypassable-looking guard or one call away (blocklist-bypass SSRF, helper-concat SQLi, authN-not-authZ IDOR, %-format SSTI helper). Safe = looks dangerous but is correctly defended (allowlist+no-redirect SSRF, allowlisted `ORDER BY` SQLi, ownership-checked IDOR, bound-data SSTI). Ran broad `source_audit` + the 4 focused skills over all 8 (`--per-skill`, qwen2.5-coder:7b).

| Axis | Broad `source_audit` | Focused skills |
|---|---|---|
| Recall (subtle-vulnerable, 4) | **4/4** | each **1/1** on its class |
| Precision (subtle-safe, 4) | **0 false positives** | 0 FP on safe fixtures… |
| Cross-class false positives | **0** | `sqli` skill **hallucinated SQLi** on the SSTI %-format fixture (1 FP) |
| Cost per class covered | one pass covers all | one LLM pass **per skill** |

**Verdict — opposite of the hypothesis, and decisive:** on this hard corpus the broad skill **matched focused on recall, matched on precision, and beat it on cross-class FP** — the `sqli` specialist, primed to hunt `%`/string-formatting, misfired SQLi on a template file where broad correctly saw SSTI. Focused per-class skills therefore add cost (N passes) and a **new failure mode (class-primed false positives)** with **no measured benefit**. Notably, broad even nailed the designed traps: it did **not** flag the allowlisted-`ORDER BY` SQL or the bound-data `render_template_string`.

**Decision (locked): do NOT mass-port per-class skills.** Ship broad `source_audit` + `secrets` as the default (already the case). Keep the 4 focused skills as opt-in library examples, not the roadmap. The real improvement levers lie elsewhere:
1. **Cross-function / cross-file taint** — the one thing per-file broad analysis genuinely can't do (the helper-concat case worked only because it was same-file).
2. **A stronger/faster backend** for depth and scale (§9c #2, architecture unchanged).
3. **Mode A (target scanning)** — the entire unbuilt half of the objective.

**Caveats (honest):** small sample (8 fixtures, 1 model); all single-file; focused prompts could be tuned. But the signal is clear enough to not spend 18 more skills' worth of effort chasing it. *This is exactly what building the benchmark first bought: a data-backed "no" that saved the port.*

**Still open:** cross-file taint; hosted backends; HTML/PDF/SARIF export; automated validation step. *(Mode A — see §10b.)*

## 10b. Phase 4 — Mode A target scanning (recon, built 2026-10-05)
Built the recon/attack-surface half of the objective. **Scope is deliberately limited to reconnaissance + profiling — no active exploitation / payload injection against live hosts.** That riskier capability is intentionally not built.

**Safety model (unchanged spine, now exercised):** every target passes the refuse-by-default `ScopeGuard` before any packet; all requests are read-only GETs, rate-limited (`[safety].max_rps`), with an identifying User-Agent; findings are `CANDIDATE` only. The `recon` skill is `requires_authorization: true`, `risk_level: low`.

**Components**
- `tools/http_probe.py` — stdlib HTTP probe; pure `analyze_headers()` (missing security headers, version disclosure) + `fingerprint()`; capped read, timeout, no exploitation.
- `tools/dns_lookup.py` — stdlib DNS resolve.
- `recon/profiler.py` — orchestrates DNS + scheme probing (honors explicit scheme/port) + well-known/sensitive paths (`/robots.txt`, `/.well-known/security.txt`, `/.git/config`, `/.env`) → `AttackSurface` + deterministic findings. A 200 on `.git/config`/`.env` is a **high** exposed-file finding.
- `recon/analyze.py` + `skills/recon/` — target_scan skill: the LLM reasons over the *profile* (evidence), never the network (best-effort; a model failure never sinks the scan).
- `cli.py cmd_scan` — scope → profile (deterministic) → recon skill (LLM, `--no-llm` to skip) → dedup → store → report. `--targets` multi-target, `--scan-id`, `--out`.

**Verified live (local test server, 127.0.0.1, in a scratch scope — real `scope.txt`/DB untouched):**
- In-scope scan → 6 deterministic findings (4 distinct missing headers, version disclosure, **exposed `.env` = high**) + 3 LLM recon findings; report generated.
- Out-of-scope target (`example.com`) → **REFUSED** by the scope guard before any probe.
- `--no-llm` deterministic path works with no model.

**Bug found & fixed by this test:** cross-skill dedup over-merged the 4 distinct missing-header findings (same target+class+location, empty line-sig → all collapsed to 1). Fixed by giving each deterministic finding a distinct `vuln_class` (specific header) and a `line_hint` signature. Now 6 stay separate. Tests **77/77** (added recon header-analysis, recon→findings, target_scan planner).

**Still open in Mode A:** port/subdomain enumeration, authenticated crawling, richer fingerprinting; and — deliberately deferred — any active vulnerability testing of live targets (needs a much stronger safety boundary, e.g. PoC-in-sandbox per §9c #5).

## 10c. Phase 5 — cross-file taint (Mode B depth, built 2026-10-05)
The capability per-file analysis structurally cannot provide (and the one the benchmark pointed at): follow user input **across functions and files** to a dangerous sink and judge the whole chain.

**How it works**
- `analysis/callgraph.py` (stdlib `ast`): extracts functions, call edges, **SOURCES** (`request.*`, `input()`) and **SINKS** (`subprocess`, `.execute`, `render_template_string`, `requests.*`, `open`, `pickle.loads`, …) mapped to canonical classes; `find_chains()` walks source→sink paths across files (name-resolved); `assemble_slice()` stitches every function in a chain into one slice.
- `analysis/taint.py` `run_taint_audit`: builds the graph, **prioritizes cross-file chains**, caps model calls (CPU), and the LLM judges each slice for exploitability.
- New `engine = "taint"` manifest field; `skills/taint/` uses it; `cmd_audit` dispatches `engine == "taint"` to the chain runner. Run with `audit --skills taint`.

**Verified live (cross-file fixtures: SOURCE in `app.py`, SINK in `util.py`):**
- Vulnerable (`shell=True`, no validation) → graph finds `ping -> run_ping`, LLM judges **exploitable** → 1 Command Injection (high) with the **chain path as evidence**.
- Safe (upstream allowlist + list-args, no shell) → **same chain detected**, LLM judges **neutralized** → **0 findings** (7 s). This is the key result: the graph proposes the candidate; the model adjudicates vulnerable-vs-safe with full cross-file context, and gets both right.

**Honest scope/limits:** call resolution is by function name (no import/type resolution) — dynamic dispatch, methods and callbacks are missed; Python only; chains capped per run for CPU. On this small fixture per-file `source_audit` *also* flagged the bug (the sink function looks suspicious in isolation), so the clean win shown here is **precision on the safe cross-file case** and **evidence quality** (the explicit path); the recall advantage will show on flows where the sink function is benign in isolation. Deterministic graph tested at **87/87** (source/sink classification, cross-file chain, slice assembly). Bug fixed during bring-up: a `->` arrow emitted as `→` crashed on the cp1252 Windows console (now ASCII).

## 10d. Phase 6 — hosted backends (built 2026-10-05)
Realizes the §20 backend abstraction: run skills on a stronger model than local 7B. The per-skill benchmark caveat ("single weak model") is now addressable by config alone — **no skill, runner, or engine code changed.**

**Providers (all pure stdlib `urllib`, no vendor SDKs — the zero-dependency promise holds):**
- `ai/openai_compat.py` — OpenAI **and** OpenRouter (`/chat/completions`, `response_format=json_object`).
- `ai/anthropic.py` — Claude Messages API (`system` + `messages`, JSON nudged in the system text).
- `make_provider` routes `ollama | openai | openrouter | anthropic`; model/provider chosen in `[model]` config.

**Keys & privacy (deliberate):**
- API keys come **only from environment variables** (`api_key_env`, defaulting per provider) — never stored in config or passed on the CLI. Missing key → clean error (exit 2), not a traceback; in `scan` the LLM step self-disables and deterministic recon still runs.
- `provider_is_local()` + a CLI **PRIVACY notice**: any hosted provider sends the analyzed code/evidence off-machine — the opposite of Ollama's local guarantee. The notice fires on every hosted `audit`/`scan`. Local Ollama remains the default.

**Pattern enabled (§9c #2 / §20):** develop & validate skills on a strong hosted model, then switch `provider` back to `ollama` for fully-local runs — architecture unchanged. Tests **100/100** (payload build + response parse for both APIs, routing, locality, missing-key and unknown-provider errors). Live API calls are not exercised in-repo (needs the user's key + sends data off-machine).

## 10e. Phase 7 — report exports (built 2026-10-05)
Findings are now exportable beyond Markdown, making them shareable and CI-ingestible. All renderers are pure, stdlib-only, model-free functions over stored rows.
- `reporting/json_report.py` — stable JSON: scan metadata + severity/state summary + full findings (evidence parsed back from its stored string). `build_report()` is the shared base.
- `reporting/sarif.py` — **SARIF 2.1.0** for CI / code-scanning (e.g. GitHub): a rule per vuln class, level mapping (critical/high→error, medium→warning, low/info→note), `security-severity`, best-effort file+line, `candidate: true` on every result.
- `reporting/html.py` — self-contained styled HTML (inline CSS, light/dark, severity badges, summary table + finding cards); **HTML-escapes all finding content** (XSS-safe reports).
- `RENDERERS` registry; CLI `report --scan ID --format md|json|html|sarif|all` (single format honors `--out`; `all` writes `reports/<id>.{md,json,html,sarif}`).

**Verified:** `report --format all` on a real scan produced valid JSON (6 findings, correct severity counts), valid SARIF 2.1.0 (6 results/6 rules, line numbers parsed), and a valid HTML document; markup injected into a finding is escaped. Tests **114/114** (added JSON/SARIF/HTML structure + escaping checks).

## 10f. Phase 8 — automated validation (built 2026-10-05)
Closes the lifecycle (§6 / §9c #4): an automated skeptical second-opinion step between detection and the human gate. `validation/validator.py` + `skills/validation/` + `store.annotate()` + CLI `validate --scan ID`.

**Human gate preserved by construction.** The `validator` actor may only advance `CANDIDATE → VALIDATION_PENDING → VALIDATED`; `FALSE_POSITIVE` and `HUMAN_CONFIRMED` stay human-only (enforced in `store.transition`). So automated validation **only advances confidence** — `true_positive` → `VALIDATED`; `false_positive`/`uncertain` stay `CANDIDATE` with the verdict recorded. Nothing is ever auto-rejected or auto-confirmed.

**Three bugs found & fixed by running it on a weak local model (honest):**
1. **Don't LLM-validate deterministic findings.** The first run rejected all 6 recon findings — including a real exposed `.env` — because recon `:probe` facts carry no code/response evidence, so the ungrounded skeptic defaults to reject. Fix: `validate` skips deterministic (`source` ending `:probe`) findings; they're facts, not guesses.
2. **Incomplete grounding.** Taint validation only read the sink file, so the skeptic couldn't see the input was user-controlled and rejected a real bug. Fix: `_validation_context` now reads **every file in the chain** (source→sink).
3. **Ambiguous verdict labels.** The 7B model correctly *described* a command injection in its reasoning but output `reject` — it read "reject" as "reject the code," the opposite of intended. Fix: unambiguous `true_positive | false_positive | uncertain` labels (with alias tolerance), and a prompt that separates "is the code bad" from "is the finding correct."

**End-to-end verified** after the fixes: the cross-file command injection ran the full designed lifecycle with actor attribution —
`CANDIDATE (skill) → VALIDATION_PENDING (validator) → VALIDATED (validator) → HUMAN_CONFIRMED (human)`.
Tests **127/127** (verdict parse + alias tolerance, prompt/grounding, stub run, and the lifecycle rule that the validator cannot reach `FALSE_POSITIVE`).

**Honest limit:** even with clear labels + grounding, a local 7B skeptic is imperfect — treat its verdicts as advisory (it's why nothing is auto-rejected and the human gate is mandatory). For high-stakes validation, run `validate` with a hosted backend (Phase 6) — a stronger skeptic, architecture unchanged.

## 10g. Phase 9 — HackerOne RAG (built 2026-10-05)
The last of the three reference repos, wired in as **retrieval**, not prompt-stuffing (DESIGN §2/§9d). Per the same "distill, don't copy" rule — and to avoid fabricating real reports/handles — this ships the RAG *infrastructure* + a seed of **generic distilled per-class patterns**, with an ingest path for the real hackerone-reports dataset.

**Components (pure stdlib — no embeddings/vector DB):**
- `knowledge/patterns.jsonl` — seed corpus (12 distilled records across ssrf/sqli/idor/ssti/command_injection/path_traversal/xss/hardcoded_secret/deserialization); plain JSONL so it stays diffable and grows by append.
- `rag/retriever.py` — **BM25 Okapi** in pure Python: tokenize + stopwords, df/idf, length-normalized scoring; `KnowledgeBase.retrieve(query, k, vuln_class)` with class filter + corpus fallback.
- `rag/ingest.py` — `add_record`, `ingest_files` (bulk-import a dir of .md/.txt, inferring class from the path — matches the hackerone-reports "by bug type" layout), `format_hits_for_prompt`.
- Integration: `run_source_audit(..., knowledge=[...])` prepends retrieved patterns as reference context; `audit --rag` (or `[rag].enabled`) retrieves per-skill by the skill's `detects` class. Off by default (extra tokens; opt-in).
- CLI `knowledge search|add|ingest`.

**Verified:** retriever ranks the right class record for a query, honors the class filter, falls back on an unknown class, and is safe on an empty corpus; `knowledge search` returns a scored hit; a real `audit --rag --skills sqli` grounded with 12 records and still detected the SQLi. Tests **136/136**.

**Honest scope:** BM25 keyword retrieval (not semantic embeddings) — good, transparent, dependency-free, but literal; the seed corpus is small and generic (distilled, not real reports). The value grows by ingesting the actual hackerone-reports dataset: `knowledge ingest --dir <repo>`. Whether grounding measurably improves detection/precision on the weak local model is **unmeasured** — a natural next benchmark (the harness + `--rag` make it a one-flag A/B).

## 10h. Phase 10 — Mode A enumeration depth (built 2026-10-05)
Deepened recon with **passive** techniques only (parse what the server advertises + DNS resolution) — deliberately no active content-discovery/dirbusting.
- `recon/parse.py` — `parse_robots` (Disallow/Allow/Sitemap, strips comments) and `parse_sitemap` (`<loc>` via regex, no XML parser → no XXE surface). Pure/testable.
- `recon/enumerate.py` — `enumerate_subdomains(base, wordlist, resolver)`: DNS-only sweep over a short conservative wordlist (no flooding, no zone transfer); resolver is injectable for tests.
- Profiler now parses robots.txt + sitemap.xml it fetches into `AttackSurface.discovered_endpoints` (fed to the recon LLM skill + report; probe body cap raised to 8 KB). `scan --subdomains` enumerates subdomains, **scope-checks each**, logs them, and records in-scope resolved ones as `info` `Discovered Subdomain` findings (out-of-scope ones are reported but never probed).
- **Verified:** parsers + enum (with a fake resolver) unit-tested; a real `scan` parsed the server's robots.txt and surfaced the `/admin` endpoint. Tests **143/143**.

**Still passive by design:** no undisclosed-path probing, no auth attacks, no active exploitation — same boundary as §10b. Subdomain enum is DNS lookups; discovered hosts are only *probed* if the user scans them (and scope allows).

## 10i. Phase 11 — semantic RAG with local embeddings (built 2026-10-05)
Upgrades retrieval from keyword (BM25) to **meaning-based**, while staying fully local and dependency-free.
- `rag/embeddings.py` — `OllamaEmbedder` (POST `/api/embeddings`), pure `cosine`, `SemanticKnowledgeBase` (same `retrieve(query, k, vuln_class)` shape as BM25, ranked by cosine over cached vectors), an on-disk embedding cache (`build_cache`/`load_cache`), and `load_semantic_kb`.
- `load_knowledge(corpus, mode, cache, embedder)` factory: returns the semantic KB when `mode="semantic"` and a usable cache exists, **else transparently falls back to BM25** — semantic is an upgrade, never a hard requirement.
- Config `[rag] mode = bm25|semantic`, `embed_model` (default `nomic-embed-text`), `embed_base_url`, `cache`. CLI `knowledge embed` builds the cache; `knowledge search` and `audit --rag` are semantic-aware with graceful fallback and a clear message.

**Verified:** cosine + payload/parse + a `SemanticKnowledgeBase` with a deterministic fake embedder (ranks the right class top), cache round-trip, and the factory's semantic/bm25 selection — Tests **155/155**. The factory correctly fell back to BM25 in this environment (no cache), and `knowledge embed` gave a clean error (exit 2) because this Ollama was started without `--embeddings`.

**Honest limit / how to turn it on:** a live semantic run needs `ollama serve` with an embedding model pulled (`ollama pull nomic-embed-text`) and the server embeddings-capable, then `security-agent knowledge embed` to build the cache and `[rag].mode = "semantic"`. The mechanism is built and unit-tested; the live embedding path is environment-gated (not exercised here). Whether semantic beats BM25 for grounding on this corpus is, like RAG itself, best settled with the benchmark once embeddings are available.

## 10j. Phase 12 — RAG effectiveness benchmark (measured 2026-10-05)
`benchmark.py --rag`: runs each focused skill over each fixture **twice — with vs without** retrieved knowledge — and reports the detection/FP delta attributable to grounding (same harness, `--mock` validated, tests **155/155**).

**Real result (sqli skill, hard SQLi pair, qwen2.5-coder:7b, 2 retrieved patterns):**

| Skill | Detect (base → RAG) | FP (base → RAG) |
|---|---|---|
| sqli | 100% → **100%** | 0 → **0** |

**Verdict — null effect here, and that's a real finding.** Grounding changed nothing: the baseline already detected the subtle helper-concat SQLi and correctly ignored the allowlist-safe near-miss, so there was **no headroom**. This mirrors §9f (focused didn't beat broad on easy cases): on small, already-solved fixtures, extra machinery adds cost, not signal.

**What this does and doesn't say:** it does *not* show RAG is useless — it shows RAG's value is **unproven on this setup** (ceiling baseline, 12 generic distilled records, BM25). A fair test needs (a) harder/realistic fixtures where the ungrounded model actually fails, and (b) a richer corpus — ingest the real hackerone-reports dataset (`knowledge ingest`) and, for semantic, `knowledge embed`. The benchmark is the instrument to settle it; today it returns a principled "no measurable effect yet," which is the honest state. RAG stays **off by default** accordingly.

## 10k. Phase 13 — professionalization (built 2026-10-05)
Packaging + onboarding + CI, without adding runtime dependencies.
- `pyproject.toml` — installable (`pip install -e .`), zero runtime deps, `security-agent` console script (`security_agent.cli:main`). Skill/knowledge data stay project-root dirs resolved relative to the root, so editable install works from anywhere.
- `.github/workflows/ci.yml` — tests on Python 3.11/3.12/3.13 (`pip install -e .` → `python tests/test_spine.py`) plus the mock benchmark self-tests (no model needed in CI).
- `CLAUDE.md` — contributor orientation: what it is, the safety model, the layout, run/test commands, how to add a skill, and the hard-won gotchas (stdlib-only, cp1252 console, TOML `system_prompt` placement, vulnhuntr's dead local path, advisory local-7B verdicts).
- `.gitignore` extended for generated artifacts (results, logs, embedding cache, build dirs); stale package docstring refreshed.
- **Verified:** `pip install -e .` succeeds, the `security-agent` console script runs (`--help`, and a real `knowledge search`), tests **155/155**.

Not done (deliberately, would add scope/deps): Docker image, web UI, observability stack — out of scope for a zero-dependency local tool.

## 10l. Phase 14 — incremental (diff) audit (built 2026-10-06)
Audit only what changed, so the tool is practical as a PR/CI gate (fast, cheap on CPU, pairs with SARIF export). Stdlib git via subprocess; no new deps.
- `security_agent/vcs.py` — `changed_files(repo, ref)`: files changed vs `<ref>` (or uncommitted vs HEAD when no ref), **including untracked** non-ignored files; `--relative` so paths match the repo root; clean error when `--repo` is not a git work tree.
- `discover_files(..., restrict=set)` + `run_source_audit(..., restrict_files=…)` limit analysis to those repo-relative paths.
- CLI `audit --diff [REF]` (`--diff` alone = uncommitted changes; `--diff main` = vs a ref). Early-exits "nothing to do" with no model call when the changed set is empty; applies to the per-file/skill runners (the whole-repo taint engine is unaffected by design).
- **Verified:** unit tests for `restrict` + `changed_files` (modified/untracked/clean/non-git); CLI smoke test on a temp git repo — clean tree → 0 changed (no model call), untracked file → detected. Tests **178/178** (includes improvements landed in parallel: case-insensitive enum normalization, hosted base_url hardening, SARIF rule-level security-severity, planner skip-dir fix).

## 10m. Phase 15 — harder evaluation corpus (built 2026-10-06)
Directly answers the §9f/§10c open question: the earlier benchmarks showed broad == focused *only on easy, single-file, blatant bugs*, so the value of focused skills / taint / RAG was **unmeasured on hard cases**. This builds the instrument to settle it — a corpus specifically engineered to defeat a naive per-file reader.

`evaluation/fixtures_hard2/` — **10 fixtures, 5 vulnerable + 5 look-alike safe twins**, over command_injection / sqli / ssrf / path_traversal / deserialization. Three hardness classes, all absent from the earlier corpora:
- **Cross-file benign-looking sink** (cmdi/ssrf/deser): the sink lives in a helper that reads as harmless plumbing in isolation, so per-file analysis *should* miss it and the AST taint engine *should* catch it — the one gap per-file analysis structurally cannot close.
- **Second-order** (sqli): input stored via a safe parameterized write, then read back and concatenated into SQL in a **different** handler (source and sink far apart).
- **Check-before-decode ordering bug** (path traversal): a real `..` guard that runs on the still-encoded value, bypassed by `%2e%2e%2f` after `unquote()`.

Each vulnerable fixture has a **structurally identical safe twin** (same shape, correctly defended: `shell=False` argv, bound param, host allowlist + no redirects, decode-then-basename-then-anchor, `json.loads`) so **false positives are measurable, not hypothetical**. Ground truth in `evaluation/expected/expected_hard2.json`; run via the harness's `--fixtures-dir`/`--expected` flags (no harness code changed) and the taint engine via `audit --skills taint` per fixture.

**Design choice — no baked-in `--mock` number.** The harness `MockProvider` is keyed to the original `fixtures/` substrings, so it is not a meaningful oracle here (it under-detects and misfires on the safe twins); real numbers are model/host-dependent and belong to a live run, per "measure, don't assume." The **model-free guarantee** that the taint graph proposes exactly the right cross-file chain for each cross-file fixture (and that the safe twin proposes the *same* chain, so only the model's judgment separates them) is locked in `tests/test_spine.py::test_hard2_corpus`.

**Verified:** all 16 fixture files parse; ground truth is 1:1 with the fixture dirs; the deterministic call-graph finds correct cross-file chains for all three cross-file vulnerable fixtures and still raises the chain on the safe SSRF twin. Tests **185/185** (178 + 7). The live detection/precision A/B against a backend is the next measurement this corpus exists to enable.

## 10n. Phase 16 — hard3 corpus proves taint earns its cost (measured 2026-10-06)
hard2 (§Phase 15) couldn't separate broad per-file from taint: broad scored 100%/0-FP because the dangerous op stayed locally visible in some file. `evaluation/fixtures_hard3/` removes that crutch — each case is split across **three files** (SOURCE in `app.py`, string/URL/SQL assembly in a builder, the SINK in an executor/fetcher/dao that looks dangerous but takes an opaque arg), and for the **safe twins the mitigation lives UPSTREAM in `app.py`** (regex allowlist, resource allowlist + fixed host, `isalnum()`), while the builder/sink files are byte-for-byte as scary as the vulnerable twin's. 3 vulnerable + 3 safe twins (cmdi/ssrf/sqli).

**Head-to-head (qwen2.5-coder:7b, local) — the decisive result:**

| | Broad `source_audit` | Taint engine |
|---|---|---|
| Detection (3 vulnerable) | **3/3** | **3/3** (with cross-file chain path as evidence) |
| FP on the 3 safe twins | **3/3 — precision collapses** | **1/3** (cleared cmdi + ssrf; FP only on sqli) |

Broad false-positived on **every** safe twin: reading `executor.py`/`fetcher.py`/`query_builder.py` in isolation it sees an unguarded sink and fires, blind to the upstream guard. Taint read the full `app.py -> builder -> sink` slice (guard included) and correctly cleared the cmdi and ssrf twins. **This is the first data-backed evidence that the taint engine earns its extra cost** — precision broad structurally cannot reach on cross-file guards.

**Two honest caveats this run exposed (both real):**
1. **Taint still FP'd on the sqli safe twin.** The guard `username.isalnum()` genuinely neutralizes SQLi (no quotes possible), but the 7B model didn't credit it — the local model's judgment remains the weak link (advisory verdicts, human gate; §10f).
2. **Callgraph bug found by the corpus — and fixed.** The cmdi fixtures produced a spurious `sqli` because a local helper named `execute(...)` collided with the SQL cursor `.execute` sink (`execute`/`executemany`/`executescript` are bare keys in `SINKS` *and* in `_TAIL_SINKS`). Fix: these cursor-method sinks now require an attribute receiver (`obj.execute`), so a bare `execute(...)` local call is no longer misread as SQL — `urlopen`/`render_template_string`/`send_file` (legitimately called bare) are unaffected, and real `conn.execute(sql)` / `sqlite3.connect(...).execute(sql)` still classify. Regression test `tests/test_spine.py::test_sink_name_collision`.

**Verified:** full suite **196/196** (added hard3 integrity + 3-file-chain tests and the sink-collision regression); live head-to-head above; post-fix the cmdi chain set is `{command_injection}` only. Results logged (not committed) in `evaluation/hard3_h2h.log`; eval scans persisted under `hard3-taint-*` in the local (untracked) findings DB.

## 9c. Target architecture v2 (layered) — adopt *after* the Phase 3 experiment

The v1 "~20 components" list is correct but flat. For a *standard* platform, organize it as **8 layers**. This is the version to build toward once the feasibility experiment passes.

```
1. USER INTERFACE      CLI / (later) Web UI / API
2. ORCHESTRATION       Job manager · planner · scheduler · state machine
3. SAFETY              Scope · authorization · rate limits · kill switch
4. SKILL ENGINE        Registry · loader · planner · (recon/vuln-class/report skills)
5. TOOL LAYER          HTTP · DNS · recon · static analysis · vulnhuntr
6. AI LAYER            Ollama / hosted · structured output · RAG
7. FINDINGS+EVIDENCE   Findings · requests · responses · logs · artifacts (evidence graph)
8. REPORTING           Finding → validation → report → export
```

### Five principles that make it "standard"
1. **The LLM reasons over evidence; it is not the security engine.** Flow is `tool output → evidence normalization → LLM analysis → candidate finding → validation → evidence → human confirmation`. Never `LLM → "I found SQLi"`.
2. **Model-independent skill registry.** *Correction to the original objective:* don't think "Ollama uses Claude's skills." Think: the platform owns a model-independent skill registry; Claude-BugHunter + HackerOne are **reference material** to author those skills; the orchestrator injects the applicable skill + evidence into whatever backend is selected (Ollama or hosted). **Ollama is the model runtime; the platform is the agent/skill runtime.**
3. **Skill planner, not a bag of scanners.** `target → scope check → asset discovery → tech fingerprint → attack-surface map → planner selects applicable skills`. A React/Node API gets auth/IDOR/SSRF/XSS/logic; a Python repo gets vulnhuntr + data-flow/dependency checks.
4. **Stronger finding lifecycle:** `DISCOVERED → CANDIDATE → TRIAGED → VALIDATION_PENDING → VALIDATED → HUMAN_CONFIRMED` (and `CANDIDATE → FALSE_POSITIVE`). LLM proposes *potential*; only you confirm.
5. **PoC has its own safety boundary.** Repo findings reproduce in a **local Docker sandbox / test fixture**, never arbitrary auto-exploitation. Live targets stay under explicit scope + controlled, minimally-invasive validation.

### Richer skill shape (supersedes the flat SKILL.md idea)
```
skills/ssrf/
├── SKILL.md            manifest.yaml (name, version, category, requires, inputs,
├── prompts/            outputs, risk_level, requires_authorization, supports:[target_scan,source_audit])
│   ├── analysis.md
│   └── validation.md
├── checks/  examples/  tests/
└── schemas/finding.json
```
→ versioned, testable, portable skills instead of loose prompt files.

### Reproducibility objects to add
- **Target profile** (`type`, `authorization.scope_file`, `assets`, `restrictions: {max_rps, destructive_tests, authenticated_testing}`) — the basis of the safety system.
- **Scan manifest** (`scan_id`, target, model `{provider, model}`, skills[], tools[], config) — so months later you can answer *exactly how this finding was produced*.

### Evidence graph (layer 7)
Store relationships, not just a finding string: `Finding → {Skill, Endpoint, Parameter, Evidence, Tool Run, Validation, Report}`. Gives full traceability.

### Refined build order
`Phase 0` feasibility proof (**current — vulnhuntr→Ollama→fixture**) → `1` safety spine → `2` skill engine → `3` source audit → `4` target scanning → `5` validation lifecycle → `6` reporting → `7` knowledge/RAG from HackerOne → `8` professionalization (Docker, CI, tests, benchmark, observability, web UI).

### Phase 0 must end with a benchmark, not a vibe
Score the local model against the fixture: detection rate, false-positive rate, **JSON-valid %**, evidence completeness, PoC reproducibility, avg inference time, tokens/scan. That table decides whether 7B-local is viable or whether reasoning/validation moves to a stronger backend (architecture unchanged — just the AI-layer provider).

## 9d. Committed architecture & repo roles (locked 2026-10-05)

This is the architecture to build toward. Vulnhuntr is **one engine inside** the platform, not the platform.

### Repo roles (final)
| Reference | Role in platform | Key facts (verified) |
|---|---|---|
| **reddelexc/hackerone-reports** | **Knowledge base / RAG** — patterns, impact, validation, report style | Disclosed reports in `data.csv`, organized by vuln class (XSS, IDOR, RCE, SQLi, SSRF, OAuth, GraphQL, business logic, auth bypass, MFA, …) |
| **elementalsouls/Claude-BugHunter** | **Skill methodology source — port, don't copy** | 83 skills · 15 commands · 24 vuln classes · SKILL.md Agent-Skills format · multi-harness (Claude Code/OpenCode/Codex/Hermes/AntiGravity). Categories: Web App 58, Enterprise 10, Reporting/Validation 6, Recon/Intel 5, Methodology 4 |
| **protectai/vulnhuntr** | **Source-analysis engine (one of several)** | Python-only; detects LFI, AFO, RCE, XSS, SQLi, SSRF, IDOR; does cross-function taint from remote input → sink |
| **Ollama + qwen2.5-coder** | **Local reasoning backend** | Proven 3/3 on fixture via correct integration (§9b) |
| **Your orchestrator** | **The actual platform** | Loads skills, plans, runs tools, collects evidence, drives the model, validates, reports |

### HackerOne becomes RAG, not prompts
`data.csv → ingest → chunk → metadata (vuln class) → embeddings → vector DB`. At analysis time: a candidate IDOR retrieves relevant IDOR methodology + disclosed examples + impact + validation + report structure, and those go into the model prompt alongside the skill and tool evidence. Turns `"find vulns"` into `evidence + skill + relevant HackerOne patterns + validation rules → analyze`.

### Claude-BugHunter: port, don't copy
Its skills assume a Claude Code harness. For each: `understand methodology → extract detection logic → extract evidence requirements → extract validation criteria → extract report format → adapt to our SKILL schema → test against fixtures → register`. Result: a **model-independent** skill library.

### Skill planner (target mode is not "run everything")
`target → scope check → DNS/subdomains → HTTP discovery → tech fingerprint → endpoints/API/auth surface → attack-surface graph → planner selects applicable skills`. e.g. detecting Next.js + REST + OAuth + JWT + GraphQL → enables auth, authz, IDOR, JWT, OAuth, GraphQL, API, XSS, SSRF skills.

### Multi-target
`scan --targets targets.txt` → one `SCAN-id` fanning out to `target-001…N`, each with its own evidence + findings.

### Final CLI surface
```
security-agent scan  --target  example.com
security-agent scan  --targets targets.txt
security-agent audit --repo    ./my-project
security-agent audit --repo    https://github.com/example/project
security-agent report <FINDING-ID>
```

## 10. Open items to decide during build

- Which recon/enum OSS tools to wrap (depends on your target types: web apps vs. network).
- vulnhuntr's exact LLM backend compatibility with Ollama (verify in Phase 3).
- Report export target (Markdown is the baseline; HTML/PDF optional).
- Whether findings live in SQLite (recommended) or flat JSON.
```
