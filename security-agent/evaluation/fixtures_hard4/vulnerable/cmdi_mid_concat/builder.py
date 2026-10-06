def ping_cmd(host):
    # Raw concatenation, no escaping (contrast: safe twin uses shlex.quote here).
    return "ping -c1 " + host
