# Provenance

- **Source:** PyGoat (OWASP) — https://github.com/adeyosemanputra/pygoat
- **Commit:** 19d17cc8874861142b330636d068bbde54e86b85
- **Original path:** `introduction/mitre.py`
- **License:** MIT (see `../../LICENSES/pygoat-LICENSE`)
- **Vendored:** verbatim, unmodified (full module — a realistic noisy Django views
  file with ~25 handlers; the vulnerability is one function among many).

## Ground truth
- **Class:** command_injection (code injection via `eval`; CWE-94/95)
- **Why vulnerable:** `mitre_lab_25_api()` does
  `expression = request.POST.get('expression'); result = eval(expression)` —
  attacker-controlled input passed straight to `eval`, i.e. arbitrary code
  execution. Canonicalizes to `command_injection` in this platform's vocabulary.
