# fixtures_hard3 — the decisive per-file-vs-taint corpus

hard2 showed broad per-file analysis still scored 100%/0-FP, because in every
"cross-file" fixture the dangerous operation stayed **locally visible** (the
concat sat next to the sink). hard3 removes that crutch. Each case is split
across **three files** so no single file is decisive:

```
app.py       SOURCE (request.args) + the call chain; for SAFE twins, the guard
builder.py   assembles the command / URL / SQL string  (looks like plain formatting)
sink.py      executor / fetcher / dao - runs it        (looks dangerous, arg is opaque)
```

The point is the **safe twins**: their mitigation lives **upstream in `app.py`**
(a regex allowlist, a resource allowlist + fixed host, an `isalnum()` check),
while the builder/sink files are byte-for-byte as scary as the vulnerable twin's.
A per-file reader of `query_builder.py` / `executor.py` / `fetcher.py` sees an
unguarded sink and *should* false-positive; a chain-aware (taint) analysis sees
the whole `app.py → builder → sink` slice, including the upstream guard, and
*should* stay correct. That gap is the measurement hard2 could not produce.

| Pair (vuln / safe twin) | Class | Upstream guard in the safe twin |
|---|---|---|
| `cmdi_split_trusted_sink` / `cmdi_split_upstream_guard_safe` | command_injection | `opts` matched `[a-z0-9_-]+` before use |
| `ssrf_split_trusted_sink` / `ssrf_split_upstream_guard_safe` | ssrf | `resource` in a fixed allowlist + pinned host |
| `sqli_split_trusted_sink` / `sqli_split_upstream_guard_safe` | sqli | `username.isalnum()` enforced |

Ground truth: [`../expected/expected_hard3.json`](../expected/expected_hard3.json).

## Run the head-to-head

```bash
# Broad per-file skill over the corpus:
python -m evaluation.benchmark \
    --fixtures-dir evaluation/fixtures_hard3 \
    --expected    evaluation/expected/expected_hard3.json

# Cross-file taint engine, per fixture:
security-agent audit --repo evaluation/fixtures_hard3/vulnerable/cmdi_split_trusted_sink      --skills taint
security-agent audit --repo evaluation/fixtures_hard3/safe/cmdi_split_upstream_guard_safe     --skills taint
```

Hypothesis: broad detects the vulnerable fixtures (the builder's visible concat
is enough) **but false-positives on one or more safe twins**; taint detects the
vulnerable ones with a chain path **and stays quiet on the safe twins**. The
real local-model numbers are recorded from a live run, not baked in (see the
project's "measure, don't assume" rule). The model-free guarantee that every
chain is proposed with `app.py` in the slice lives in
`tests/test_spine.py::test_hard3_corpus`.
