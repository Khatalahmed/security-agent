"""Helper module - runs an external program the SAFE way (no shell)."""
import subprocess


def _run(args):
    # argv list + shell=False: the OS executes `args[0]` with the rest as literal
    # arguments. No shell parsing, so user data cannot become a second command.
    return subprocess.run(args, shell=False, capture_output=True, text=True).stdout


def exec_report(fmt):
    # Fixed argv; `fmt` is one discrete argument, never concatenated into a line.
    return _run(["generate-report", "--format", fmt])
