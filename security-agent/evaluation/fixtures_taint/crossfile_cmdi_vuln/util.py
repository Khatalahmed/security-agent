import subprocess


def run_ping(host):
    # SINK: user host concatenated into a shell command (command injection).
    return subprocess.check_output("ping -c 1 " + host, shell=True)
