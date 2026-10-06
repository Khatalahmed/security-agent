"""Identical in spirit to the vuln twin's builder - string assembly only."""


def build_convert_cmd(opts):
    return "imgconvert --preset " + opts
