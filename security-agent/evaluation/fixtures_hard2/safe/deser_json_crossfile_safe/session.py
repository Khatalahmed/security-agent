"""Session helper that deserializes untrusted bytes the safe way."""
import json


def load_state(raw):
    # json.loads cannot construct arbitrary Python objects - only plain data -
    # so untrusted input here is not code execution.
    return json.loads(raw.decode("utf-8"))
