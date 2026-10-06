import shlex


def ping_cmd(host):
    # shlex.quote neutralizes shell metacharacters in the user value.
    return "ping -c1 " + shlex.quote(host)
