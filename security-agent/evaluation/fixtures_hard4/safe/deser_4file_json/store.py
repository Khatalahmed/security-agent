import json


def load(raw):
    return json.loads(raw.decode("utf-8"))      # inert data only - safe
