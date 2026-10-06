"""Looks like a generic command runner; the docstring even claims the input is
trusted. In isolation nothing says the argument is attacker-controlled."""
import os


def execute(command_line):
    # Run a prepared command line. `command_line` is expected to be an internal,
    # already-validated string assembled elsewhere.
    return os.popen(command_line).read()          # SINK (opaque arg in isolation)
