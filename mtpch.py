#!/usr/bin/env python3
"""Single-file launcher for MTPCH.

Run ``python3 mtpch.py --help`` for a full option list, or just
``python3 mtpch.py`` to open the interactive menu.
"""

from mtpch.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
