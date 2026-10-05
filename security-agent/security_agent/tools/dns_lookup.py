"""DNS resolution for Mode A recon — stdlib socket.getaddrinfo.

Passive: a name lookup, no zone transfer / brute force. Returns resolved IPs or
an error string (never raises).
"""
from __future__ import annotations

import socket


def resolve(host: str) -> tuple[list[str], str]:
    """Return (sorted unique IPs, error). On failure IPs is [] and error is set."""
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError) as e:
        return [], str(e)
    ips = sorted({info[4][0] for info in infos})
    return ips, ""
