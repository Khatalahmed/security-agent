---
name: ssti
version: 0.1.0
category: web
supports: [source_audit]
risk_level: safe
---

# SSTI — Server-Side Template Injection

Focused skill: finds user input that becomes template *source* (not template
data). Distilled methodology; complements `source_audit`. SSTI frequently
escalates to RCE.

## When to use

Any file that renders templates where part of the template string could derive
from user input.

## Method

1. **Find the render sink** — `render_template_string`, `Template(...).render()`,
   Mako/Jinja/Twig/Freemarker/ERB/Handlebars/Velocity equivalents.
2. **Check what is the template** — if the *template text* is built from user
   input (f-string, concat, direct pass), it's SSTI. If input is only a context
   variable for a fixed template file, it's safe.
3. **Assess impact** — most engines allow object traversal to RCE; confirmed SSTI
   is high/critical.

## Known patterns

`{{7*7}}`-style probes · sandbox escapes (`__class__`/`__mro__` in Jinja) ·
format-string template building · email/notification templates fed user content.

## Limitations

Per-file reasoning; template text assembled across modules needs the taint phase.

## Outputs

`vuln_class: "SSTI"` findings (shared envelope) at `CANDIDATE`.
