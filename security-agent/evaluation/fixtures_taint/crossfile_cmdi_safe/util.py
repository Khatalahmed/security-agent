import subprocess


def run_ping(host):
    # Safe: list args (no shell), and host is allowlisted upstream.
    return subprocess.check_output(["ping", "-c", "1", host])
