---
name: secrets
version: 0.1.0
category: secrets
supports: [source_audit]
risk_level: safe
---

# Secrets Detection

Flags credentials hardcoded directly in source: API keys, access tokens,
passwords, private keys, and connection strings with embedded credentials. A
complement to `source_audit` — that skill hunts exploitable code paths; this one
hunts committed secrets, a different class the general audit prompt does not
focus on.

## When to use

Mode B, any language (`applies_when.languages = []`). The planner selects it for
every source repo regardless of language, so it runs alongside language-specific
skills.

## Method

1. For each in-scope file, send the file text with the secrets `system_prompt`.
2. The model reports only **literal** secret values present in the code —
   explicitly not environment-variable reads, config lookups, secret-manager
   calls, or placeholders. That narrowness is the whole point: it keeps the
   false-positive rate down.
3. Each finding is validated against `schemas/finding.json` and emitted as a
   **CANDIDATE** for human review.

## Known limitations (honest)

- LLM-based, not entropy/regex based — good at *contextual* secrets (a key
  assigned to a named variable, a password in a connection string) but not a
  replacement for a dedicated high-recall scanner on huge repos.
- Shares the per-file limitation of the engine's runner.

## Outputs

Finding objects (shared envelope; `vuln_class` names the secret type) matching
`schemas/finding.json`, all at state `CANDIDATE`.
