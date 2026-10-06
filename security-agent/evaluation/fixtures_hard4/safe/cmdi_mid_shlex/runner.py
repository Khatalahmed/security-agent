import os


def run(cmd):
    return os.popen(cmd).read()                 # looks dangerous in isolation
