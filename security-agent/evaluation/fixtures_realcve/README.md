# fixtures_realcve — real CVE before/after-fix corpus (Option A)

A tiny, hand-verified corpus of **real** Python vulnerabilities, each a
before/after pair: the **vulnerable commit** (positive) and the **security-fix
commit** (safe twin). Built to test detection on real code, not synthetic
fixtures. **No accuracy is claimed** — this is qualitative "what is / isn't
supported" reporting on N=4.

## No vendoring — reproducible fetch
Third-party code is **never** committed here. [`manifest.json`](manifest.json)
records, per case: repo, exact vulnerable + fix SHAs, file path, changed-line
range, CWE/class, license, memorization risk, and size. [`fetch.py`](fetch.py)
blobless-clones each repo and extracts the one changed file at both SHAs into
`_fetched/` (gitignored). Every pair was verified by fetching and reading the
fix diff.

```bash
python evaluation/fixtures_realcve/fetch.py          # populate _fetched/
python evaluation/fixtures_realcve/fetch.py --list   # list cases (no network)
```

## Cases

| id | class | in-vocab sink? | fits ctx? | license | memo-risk |
|---|---|:--:|:--:|---|---|
| aiohttp_CVE-2024-23334_pathtrav | path_traversal | no (`normpath`/`resolve`) | no (42 KB) | Apache-2.0 | high |
| flask-reuploaded_pathtrav_d64c6b2 | path_traversal | no (`os.path.join`) | yes | MIT | low-med |
| banks_SSTI_dbf7cef | ssti | no (`jinja2.Environment`) | yes | MIT | low |
| frictionless_CVE-2026-93349_cmdi | command_injection | **yes (`os.system`)** | yes | MIT | low-med |

`frictionless` is the deliberate **in-vocabulary control** — a sink the platform
models, in a file that fits context — to separate "detection ability" from
"vocabulary coverage."

## Measured result (qwen2.5-coder:7b, `source_audit + taint + --taint-all-chains`)

| Case | vuln detected | fixed FP |
|---|:--:|:--:|
| aiohttp | no | none |
| flask-reuploaded | no | none |
| banks | no | none |
| frictionless (control) | **yes** | **yes (FP on the argv fix)** |

- **Vulnerable detection: 1/4**; **fixed-version FPs: 1/4**; **clean vuln/fix discrimination: 0/4**.
- **taint: 0 source->sink chains in all 8 file-versions (0 taint model calls)** — real entry points (CLI args, aiohttp/werkzeug request objects) and sinks (`os.path.join`, `jinja2.Environment`) are outside its vocabulary. The **authority merge never triggered**.
- **Runtime:** ~23 min; **8 broad model calls, 0 taint calls**.

## What this says (and doesn't)
**Supported, confirmed on real code:** broad per-file detection fires for a
blatant in-vocabulary sink (`os.system` f-string) even in a real package.

**NOT supported / gaps surfaced:**
1. **Vocabulary coverage** — framework path-traversal (`os.path.normpath`/`resolve`,
   `os.path.join`+`secure_filename`) and `jinja2.Environment`/`Template` SSTI are
   not modeled, so no signal on 3/4 real cases.
2. **Context size** — the 42 KB aiohttp file exceeds `num_ctx=8192` and truncates.
3. **Precision / vuln-vs-fix discrimination** — broad flagged the argv
   `subprocess.run(...)` fix as command injection (FP); it does not credit
   shell=False/argv over `os.system`. 0/4 cases discriminated cleanly.
4. **Taint on real entry points** — CLI/web-framework sources aren't recognized,
   so taint (and therefore the authority merge) never engaged on real code.

**Not an accuracy claim** (N=4). **Memorization** is moot — nothing was detected
on the 3 famous cases regardless; the one detection (frictionless) is a recent,
niche package (lower memorization risk).

## Gaps / next
- **SSRF** not sourced to a verifiable small merged-fix pair this pass.
- A fair, larger corpus needs a **curated dataset (e.g. CVEfixes)** or
  user-provided CVE+SHAs.
- The clearest actionable improvement this surfaced — **broadening taint's
  SINKS/SOURCES to real framework idioms** and teaching broad argv-vs-shell — is
  a **production-architecture change, intentionally NOT made here.**
