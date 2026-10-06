# Provenance

- **Source:** PyGoat (OWASP) — https://github.com/adeyosemanputra/pygoat
- **Commit:** 19d17cc8874861142b330636d068bbde54e86b85
- **Original path:** `dockerized_labs/insec_des_lab/main.py`
- **License:** MIT (see `../../LICENSES/pygoat-LICENSE`)
- **Vendored:** verbatim, unmodified (self-contained Flask app).

## Ground truth
- **Class:** deserialization (CWE-502)
- **Why vulnerable:** `deserialize_data()` does
  `decoded = base64.b64decode(request.form.get('serialized_data')); pickle.loads(decoded)`
  — `pickle.loads` on attacker-controlled bytes is arbitrary code execution.
