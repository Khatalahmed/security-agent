# Provenance

- **Source:** Vulpy — https://github.com/fportantier/vulpy
- **Commit:** 5249cc8b05a1c37f6b2f757b1cf16a509c327122
- **Original path:** `bad/libuser.py`
- **License:** MIT (see `../../LICENSES/vulpy-LICENSE`)
- **Vendored:** verbatim, unmodified.

## Ground truth
- **Class:** sqli
- **Why vulnerable:** `login()` and `password_change()` build SQL with
  `"... '{}' ...".format(username, password)` and `create()` with `% (username, password, ...)`
  — attacker-controlled credentials concatenated directly into the query.
- A deliberately-vulnerable training app; this file is the intended lesson, not a
  latent bug.
