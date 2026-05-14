#!/usr/bin/env python3

"""Compatibility entrypoint for the DECEIVE SSH honeypot.

The implementation now lives in the shared protocol registry runtime. This file
is intentionally small so existing commands such as
`uv run python SSH/ssh_server.py` keep working.
"""

from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from deceive.server import main  # noqa: E402


if __name__ == "__main__":
    sys.exit(main())
