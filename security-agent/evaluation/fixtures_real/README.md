# fixtures_real — real-world vulnerability corpus (pilot)

Minimal, **verbatim**, **MIT-licensed** modules vendored from deliberately-vulnerable
training apps, to test detection on *real framework code* rather than synthetic
fixtures. Every fixture carries a `PROVENANCE.md` (source repo, commit SHA,
original path, license) and the upstream license is kept in `LICENSES/`.

| Fixture | Class | Source (MIT) | Why |
|---|---|---|---|
| `vulnerable/sqli_vulpy_libuser` | sqli | Vulpy `bad/libuser.py` | `.format`/`%` creds into SQL |
| `vulnerable/cmdi_pygoat_eval` | command_injection | PyGoat `introduction/mitre.py` | `eval(request.POST[...])` |
| `vulnerable/deser_pygoat_pickle` | deserialization | PyGoat `insec_des_lab/main.py` | `pickle.loads(b64(request.form))` |
| `safe/sqli_vulpy_libposts_parameterized` | [] (clean) | Vulpy `bad/libposts.py` | parameterized `?` queries |

## This is a RECALL corpus, not a precision corpus
Training apps are all-vulnerable by design — no fixed "safe twin" per bug — so it
measures **detection on real code**. False-positive measurement stays with
`fixtures_hard3/4` (synthetic safe twins) plus the one real clean negative here.
**Scoring rule:** on a real noisy file, findings *outside* the labeled class are
**unlabeled**, not auto-FP; FP is counted only on `safe/`.

## Honest scope / caveats
- **Classes limited to what these apps cleanly expose** as genuine, user-driven,
  small self-contained modules: sqli, command_injection (`eval`), deserialization.
  SSRF/SSTI/path-traversal here have fixed (non-user) sinks or live in 1000-line
  files — deferred to a future CVE before/after-fix phase (Option A).
- **Memorization:** PyGoat is well-known OWASP training code; the 7B model may
  have seen it (`memorized_risk` flagged per fixture). Treat PyGoat detection as
  an upper bound.
- **Noise is the point:** `mitre.py` is a full ~25-handler Django views module;
  the bug is one function among many — a realistic signal-in-noise test.

## Run (local Ollama)
```bash
python -m evaluation.benchmark \
    --fixtures-dir evaluation/fixtures_real \
    --expected    evaluation/expected/expected_real.json
```
Integrity (parse, provenance, license-on-file, expected<->dirs) is guarded by
`tests/test_spine.py::test_real_corpus`. Detection numbers come from a live run
(recorded in DESIGN), not baked in.
