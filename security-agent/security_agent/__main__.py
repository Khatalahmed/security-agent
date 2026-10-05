"""Entry point so `python -m security_agent ...` works."""
from security_agent.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
