#!/usr/bin/env python3
"""ARDREC R168-F2: CLI versionada para Runner bajo DENY; no emite permisos."""
from ardrec.coordination.r168_f2_runner_ftp_boot import main
if __name__ == '__main__':
    raise SystemExit(main())
