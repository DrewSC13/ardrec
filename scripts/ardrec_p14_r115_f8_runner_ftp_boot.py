#!/usr/bin/env python3
"""R115-F8 operator CLI (never auto-runs physical actions)."""
from ardrec.coordination.r115_f8_runner_ftp_boot import main

if __name__ == '__main__':
    raise SystemExit(main())
