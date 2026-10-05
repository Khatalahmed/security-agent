---
name: validation
version: 0.1.0
category: validation
supports: [validation]
risk_level: safe
---

# Validation — Automated Second Opinion

A skeptical reviewer that re-judges each `CANDIDATE` finding before it reaches a
human. Its purpose is to **catch false positives** and raise confidence on real
ones, cutting reviewer load.

## Lifecycle (the human gate is preserved)

The `validator` actor may only advance a finding `CANDIDATE → VALIDATION_PENDING
→ VALIDATED`. It **cannot** mark `FALSE_POSITIVE` or `HUMAN_CONFIRMED` — those
stay human-only (`findings/models.py`). So:

- **confirm** → finding promoted to `VALIDATED` (ready for human `confirm`)
- **reject** / **uncertain** → finding stays `CANDIDATE`; the verdict + reasoning
  are recorded in evidence for the human (never auto-rejected)

## Method

For each candidate the `validate` command sends the finding (class, location,
why, PoC, evidence, call chain) plus — when resolvable — the **relevant source
code**, and asks: true positive or likely false positive? The model weighs
sanitization, reachability, authorization, and whether the evidence supports the
claim.

## Run it

`python -m security_agent validate --scan <SCAN_ID>`
