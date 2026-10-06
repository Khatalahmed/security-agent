# Provenance

- **Source:** Vulpy — https://github.com/fportantier/vulpy
- **Commit:** 5249cc8b05a1c37f6b2f757b1cf16a509c327122
- **Original path:** `bad/libposts.py`
- **License:** MIT (see `../../LICENSES/vulpy-LICENSE`)
- **Vendored:** verbatim, unmodified.

## Ground truth
- **Class:** [] (clean negative — any finding here is a false positive)
- **Why safe:** both queries are **parameterized** —
  `c.execute("SELECT * FROM posts WHERE username = ? ...", (username,))` and
  `c.execute("INSERT INTO posts (username, text, date) VALUES (?, ?, ...)", (username, text))`.
  User values are bound parameters, never SQL text. Notably this sits in Vulpy's
  `bad/` directory yet is correctly written — a real-world clean negative for
  measuring false positives on code that *looks* like it could be SQLi.
