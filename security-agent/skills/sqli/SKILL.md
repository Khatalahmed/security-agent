---
name: sqli
version: 0.1.0
category: web
supports: [source_audit]
risk_level: safe
---

# SQLi — SQL Injection

Focused skill: finds SQL statements where user input is interpolated instead of
bound. Distilled methodology; complements `source_audit`.

## When to use

Any file that builds or executes SQL (raw driver calls, ORM raw/extra queries,
query builders with string fragments).

## Method

1. **Find the sink** — `execute/executemany/cursor.execute`, ORM `raw`/`extra`/
   `literal`/`text()`, query-builder string fragments.
2. **Inspect construction** — is a user value concatenated, f-stringed, `%`- or
   `.format()`-ed into the SQL text? That is the vulnerability.
3. **Confirm it's not parameterized** — bound placeholders (`?`, `%s` + params
   tuple, named binds) are safe; dynamic identifiers must come from a fixed
   allowlist, never from input.
4. **Consider second-order** — input stored now, concatenated into SQL later.

## Known patterns to weigh

`ORDER BY`/`LIMIT`/column names from input · `IN (...)` lists built by join ·
LIKE wildcards · stacked queries · ORM escape hatches.

## Limitations

Per-file reasoning; cross-module query assembly needs the taint phase.

## Outputs

`vuln_class: "SQL Injection"` findings (shared envelope) at `CANDIDATE`.
