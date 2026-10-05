"""security-agent: a local, skill-driven AI security assessment platform.

Authorized testing only. Two modes (source audit / target recon) over one
pipeline: detect -> dedup -> automated validation -> human gate -> report, on a
local (Ollama) or hosted backend. Zero runtime dependencies (stdlib only).
See CLAUDE.md for orientation and DESIGN.md for the full design.
"""

__version__ = "0.1.0"
