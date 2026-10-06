"""Harmless-looking URL string composer; no network call in this file."""


def build_url(resource):
    # Compose an upstream URL from a resource identifier/path.
    return "http://" + resource
