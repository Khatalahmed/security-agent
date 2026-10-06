"""Pins a fixed, trusted host; only the path segment comes from the caller."""


def build_url(resource):
    return "https://api.internal.example.com/" + resource
