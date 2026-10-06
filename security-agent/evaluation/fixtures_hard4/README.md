# fixtures_hard4 — diverse cross-file corpus (10 pairs / 20 fixtures)

hard3 proved taint out-precisions per-file analysis on upstream-guard cases, but
it only covered 3 shapes. hard4 broadens coverage to **new axes** so the
broad-vs-taint comparison has real variety, not 20 clones. Every fixture is
cross-file; each vulnerable fixture has a structurally identical **safe twin**
whose guard lives somewhere on the chain. `[]` = any finding is a false positive.

| Pair (vuln / safe) | Class | New axis exercised |
|---|---|---|
| `cmdi_mid_concat` / `cmdi_mid_shlex` | command_injection | **sanitizer in the middle file** (`shlex.quote`) |
| `pathtrav_mid_raw` / `pathtrav_mid_basename` | path_traversal | sanitizer in the middle (`basename`) |
| `ssti_fstring_xfile` / `ssti_context_xfile` | ssti | template source vs **bound context var** |
| `deser_4file_pickle` / `deser_4file_json` | deserialization | **4-file chain depth** |
| `sqli_concat_id` / `sqli_int_coerce` | sqli | **type-coercion guard** (`int()`) |
| `ssrf_branch_gap` / `ssrf_branch_all` | ssrf | **conditional/branch guard gap** |
| `cmdi_loop_shell` / `cmdi_loop_validated` | command_injection | **taint through a loop** |
| `sqli_second_order_xfile` / `sqli_second_order_param` | sqli | **cross-file second-order** (taint blind spot) |
| `ssrf_allowlist_substring` / `ssrf_allowlist_exact` | ssrf | **bypassable substring allowlist** |
| `pathtrav_decode_xfile` / `pathtrav_decode_xfile_safe` | path_traversal | cross-file **decode-after-check** ordering |

Ground truth: [`../expected/expected_hard4.json`](../expected/expected_hard4.json).

**Known-interesting case:** `sqli_second_order_xfile` — the only source->sink
chain the graph can build runs through the *safe* bound INSERT in `/set`; the
real vulnerable concat in `/show -> lookup` is not reachable from a source, so
the taint engine is expected to **miss** it while the broad per-file reader
catches the visible concat. A deliberate illustration of taint's second-order
limitation (DESIGN §10c).

## Run (local Ollama)

```bash
python -m evaluation.benchmark \
    --fixtures-dir evaluation/fixtures_hard4 \
    --expected    evaluation/expected/expected_hard4.json          # broad
security-agent audit --repo evaluation/fixtures_hard4/<cat>/<name> --skills taint  # taint, per fixture
```

Deterministic integrity + chain-proposal guarantees live in
`tests/test_spine.py::test_hard4_corpus`. Real detection/precision numbers come
from a live run (model/host-dependent), not baked in.
