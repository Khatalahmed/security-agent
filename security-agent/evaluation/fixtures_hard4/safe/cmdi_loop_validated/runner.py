import re
import subprocess

_OK = re.compile(r"\A[A-Za-z0-9_.-]+\Z")


def run_all(files):
    argv = ["convert"]
    for f in files:
        if not _OK.match(f):                    # reject anything but safe filenames
            raise ValueError("bad filename")
        argv.append(f)
    # argv form + shell=False: user values are literal args, never a shell line.
    return subprocess.run(argv, shell=False, capture_output=True).stdout
