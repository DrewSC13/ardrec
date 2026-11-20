#!/usr/bin/env python3
"""R115-F7 executable entrypoint. Imports the audited R115-F7 module unchanged."""
from __future__ import annotations
from pathlib import Path
import sys

REPO = Path('/home/cicada/Development/GitHub/ardrec')
sys.path[:0] = [str(REPO/'src'),str(REPO/'scripts')]
from ardrec.coordination.r115_f7_controlled_boot import main

if __name__ == '__main__':
    raise SystemExit(main())
