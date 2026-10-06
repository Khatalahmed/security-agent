"""Generic HTTP helper. Benign-looking; unsafe only with a tainted endpoint."""
import requests


def get_json(endpoint):
    # No scheme/host restriction: a user-controlled endpoint lets a caller reach
    # internal services (169.254.169.254, localhost, file-like schemes) = SSRF.
    resp = requests.get(endpoint, timeout=5)    # SINK
    return {"status": resp.status_code, "body": resp.text[:200]}
