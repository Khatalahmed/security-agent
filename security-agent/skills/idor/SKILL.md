---
name: idor
version: 0.1.0
category: access-control
supports: [source_audit]
risk_level: safe
---

# IDOR — Broken Object-Level Authorization

Focused skill: finds resource accesses keyed by a user-supplied id with no
ownership/authorization check. Distilled methodology; complements `source_audit`.

## When to use

Any request handler that fetches/updates/deletes a resource by an id, uuid,
filename, account number, or slug taken from the request.

## Method

1. **Find the reference** — an object id/key read from path, query, body, or header.
2. **Find the access** — a DB lookup or mutation using that reference.
3. **Check the guard** — is the access scoped to the authenticated principal
   (`filter(owner=current_user, …)`) or preceded by an explicit permission check?
   If the only key is the user-supplied id, it's IDOR.
4. **Weigh exposure** — sequential/guessable ids → higher severity; UUIDs reduce
   but don't remove the issue.

## Related patterns

Mass assignment (user sets `owner_id`) · missing function-level authz · indirect
references leaked in prior responses.

## Limitations

Authorization is often enforced in middleware/decorators elsewhere; per-file
reasoning can over-report. Findings are CANDIDATE — the human gate confirms
whether an out-of-file guard exists.

## Outputs

`vuln_class: "IDOR"` findings (shared envelope) at `CANDIDATE`.
