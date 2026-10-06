"""Unchanged from the vuln twin: in isolation this looks like command injection.
It is safe ONLY because of the upstream validation in app.py (not visible here)."""
import os


def execute(command_line):
    return os.popen(command_line).read()          # looks dangerous in isolation
