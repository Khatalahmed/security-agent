---
name: ssrf
version: 0.1.0
category: web
supports: [source_audit]
risk_level: safe
---

# SSRF — Server-Side Request Forgery

Focused skill: finds server-side fetches whose destination is influenced by user
input and insufficiently validated. Distilled from established SSRF methodology
and disclosed-report patterns; complements the broad `source_audit` skill with
deeper, class-specific reasoning.

## When to use

Any file where the server fetches a remote resource (HTTP clients, URL previews,
webhooks, image/PDF/document fetchers, SVG/XML parsers, OAuth/OIDC discovery).

## Method

1. **Find the sink** — `requests/httpx/urllib/aiohttp.get/post`, `curl`, headless
   browsers, XML/SVG external-entity loaders, library fetchers.
2. **Trace the destination** back to user input (param, JSON body, header,
   stored value, filename).
3. **Check validation before the fetch** — is there an *allowlist* of hosts/schemes?
   A blocklist, a regex, or a one-time host check that a redirect can bypass does
   not count.
4. **Assess reach** — cloud metadata (`169.254.169.254`), loopback/internal
   ranges, alternate schemes (`file://`, `gopher://`, `dict://`).

## Known bypasses to weigh

Open redirects chained into the fetch · DNS rebinding · decimal/octal/IPv6 IP
encodings · `@`-userinfo tricks · metadata via alternate hostnames.

## Limitations

Per-file LLM reasoning: strong on direct sinks, weaker on fetches assembled
across modules (that needs the evidence-graph / taint phase).

## Outputs

`vuln_class: "SSRF"` findings (shared envelope) at state `CANDIDATE`.
