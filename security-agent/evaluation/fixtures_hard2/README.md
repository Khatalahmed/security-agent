# fixtures_hard2 — the harder evaluation corpus

Built to test the levers [`DESIGN.md`](../../../DESIGN.md) flags as **unmeasured** after
the Phase 9f/10c results (where the broad skill matched focused skills on easy,
single-file bugs). Each case is designed so a naive per-file reader is misled:

- **Cross-file, benign-looking sink** — the dangerous sink lives in a helper that
  reads like harmless plumbing in isolation. Per-file analysis should *miss* these;
  the AST taint engine (`audit --skills taint`) should *catch* them. This is the
  gap per-file analysis structurally cannot close.
- **Second-order** — input is stored via a safe, parameterized write, then read
  back and misused in a *different* handler. The source and sink are far apart.
- **Check-before-decode ordering bug** — a real `..` guard that runs on the
  still-encoded value, so `%2e%2e%2f` bypasses it after `unquote()`.

Every vulnerable fixture has a **structurally look-alike safe twin** (same shape,
correctly defended) so false positives are measurable, not hypothetical.

| Fixture (vulnerable / safe twin) | Class | What makes it hard |
|---|---|---|
| `cmdi_benign_helper_crossfile` / `cmdi_listargs_crossfile_safe` | command_injection | sink `_run` looks generic; safe twin uses `subprocess.run(argv, shell=False)` |
| `sqli_second_order` / `sqli_second_order_param_safe` | sqli | stored-then-reused; safe twin binds the read-back value |
| `ssrf_fetch_helper_crossfile` / `ssrf_allowlist_crossfile_safe` | ssrf | generic `get_json` helper; safe twin = https + host allowlist, no redirects |
| `path_traversal_decode_after_check` / `path_traversal_decode_then_check_safe` | path_traversal | guard runs before `unquote`; safe twin decodes first + basename + anchor check |
| `deser_pickle_crossfile` / `deser_json_crossfile_safe` | deserialization | cross-file `load_state` → `pickle.loads`; safe twin uses `json.loads` |

Ground truth: [`../expected/expected_hard2.json`](../expected/expected_hard2.json)
(`[]` = any finding is a false positive).

## Run it

```bash
# Broad per-file skill over the corpus (real model; CPU = minutes/file):
python -m evaluation.benchmark \
    --fixtures-dir evaluation/fixtures_hard2 \
    --expected    evaluation/expected/expected_hard2.json

# Focused-vs-broad, scored per target class:
python -m evaluation.benchmark --per-skill \
    --fixtures-dir evaluation/fixtures_hard2 \
    --expected    evaluation/expected/expected_hard2.json

# The discriminating test — cross-file TAINT engine (per fixture, via the CLI):
security-agent audit --repo evaluation/fixtures_hard2/vulnerable/cmdi_benign_helper_crossfile --skills taint
security-agent audit --repo evaluation/fixtures_hard2/safe/cmdi_listargs_crossfile_safe       --skills taint
```

**Note on `--mock`:** the harness's `MockProvider` is keyed to the *original*
`fixtures/` substrings, so its numbers on this corpus are not meaningful (it
under-detects and misfires on the safe twins). Use a real backend (local Ollama
or a hosted provider) for measurement. The model-free guarantee that the taint
graph proposes the right cross-file chains lives in `tests/test_spine.py`
(`test_hard2_corpus`).

## Why no `--mock` number is committed here

Per the project's "measure, don't assume" rule, the real detection/precision
numbers come from running the above against a chosen backend on the user's
machine; they are environment- and model-dependent and so are not baked in.
