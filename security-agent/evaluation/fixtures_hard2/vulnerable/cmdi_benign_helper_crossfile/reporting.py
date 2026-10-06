"""Helper module. In isolation this reads like harmless plumbing - which is the
point: the danger is only visible with the caller's tainted input."""
import os


def _run(cmd):
    # Generic-looking command runner. Benign on its own; lethal when `cmd`
    # carries unsanitized external input.
    return os.popen(cmd).read()               # SINK: shell command execution


def exec_report(fmt):
    # Builds a shell command line from the caller-supplied format, then runs it.
    # `fmt` is attacker-controlled (e.g. "pdf; rm -rf /").
    return _run("generate-report --format " + fmt)
