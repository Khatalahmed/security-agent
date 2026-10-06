import subprocess


def run_all(files):
    cmd = "convert"
    for f in files:                             # taint through a loop
        cmd += " " + f
    return subprocess.check_output(cmd, shell=True)   # SINK (shell=True)
