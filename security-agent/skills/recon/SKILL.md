---
name: recon
version: 0.1.0
category: reconnaissance
supports: [target_scan]
risk_level: low
requires_authorization: true
---

# Recon — Attack-Surface Analysis (Mode A)

Reasons over an authorized target's attack-surface **profile** (built by the
probe tools) and prioritizes observations. The skill never touches the network
itself — it analyzes evidence.

## Authorization

Mode A only runs against hosts in `config/scope.txt` (refuse-by-default). This
skill is `requires_authorization: true`; the scope guard gates every target
before any probe or analysis happens.

## Inputs (the profile)

DNS/IPs · live schemes (http/https, status, title) · server + technology
fingerprint · response headers · discovered well-known/sensitive paths ·
deterministic observations (missing headers, version disclosure, exposed files).

## Method

1. The probe tools (`http_probe`, `dns_lookup`) build the profile — light-touch,
   rate-limited, read-only GETs. No exploitation.
2. Deterministic checks already emit findings (missing security headers, version
   disclosure, exposed `.git/config` / `.env`).
3. This skill adds LLM synthesis: prioritize, spot combinations, and flag areas
   worth manual testing — strictly from the evidence.

## Boundaries (important)

No payloads, no fuzzing, no auth attacks — this module is reconnaissance only.
Active vulnerability testing against live targets is intentionally out of scope.
All findings are `CANDIDATE` pending human review.

## Outputs

Recon observation findings (shared envelope; severity may be `info`) at
`CANDIDATE`.
