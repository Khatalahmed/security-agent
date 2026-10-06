"""Generic fetch helper; docstring claims the URL is already vetted."""
import requests


def fetch(url):
    # Fetch a prepared URL. `url` is assumed to be a vetted internal endpoint.
    return requests.get(url, timeout=5).text[:200]  # SINK (opaque arg in isolation)
