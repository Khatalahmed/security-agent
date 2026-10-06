import os


def run(cmd):
    return os.popen(cmd).read()                 # SINK
